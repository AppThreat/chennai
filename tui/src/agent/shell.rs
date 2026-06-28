//! Shell tool implementations: ripgrep, read_file, git operations.
//!
//! Every tool is **read-only** and **cwd-confined** to the project source root. Paths are
//! canonicalised and verified to not escape via `..` or symlinks. Arguments are passed as argv
//! vectors — never as a shell string — so no shell injection is possible.

use serde_json::Value;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const MAX_OUTPUT_BYTES: usize = 32 * 1024; // 32 KiB per tool call
const TOOL_TIMEOUT: Duration = Duration::from_secs(30);

/// Canonicalise `path` relative to `root` and verify it stays within `root`.
fn confine_path(root: &Path, path_str: &str) -> Result<PathBuf, String> {
    let root_canon = root.canonicalize().map_err(|e| format!("cannot resolve root: {e}"))?;
    let joined = root_canon.join(path_str);
    let canon = joined.canonicalize().map_err(|e| format!("path does not exist or is inaccessible: {e}"))?;
    if canon.starts_with(&root_canon) {
        Ok(canon)
    } else {
        Err(format!("path '{path_str}' escapes the source root"))
    }
}

/// Read output from a child process, truncated to [`MAX_OUTPUT_BYTES`].
fn read_output(child: &mut std::process::Child) -> Result<String, String> {
    let mut stdout = child.stdout.take().ok_or("no stdout")?;
    let mut buf = Vec::new();
    stdout.read_to_end(&mut buf).map_err(|e| format!("read error: {e}"))?;
    let _ = child.wait();
    if buf.len() > MAX_OUTPUT_BYTES {
        buf.truncate(MAX_OUTPUT_BYTES);
        let text = String::from_utf8_lossy(&buf).to_string();
        Ok(format!("{text}\n--- OUTPUT TRUNCATED at {} KiB ---", MAX_OUTPUT_BYTES / 1024))
    } else {
        Ok(String::from_utf8_lossy(&buf).to_string())
    }
}

// ---------------------------------------------------------------------------
// ripgrep
// ---------------------------------------------------------------------------

pub fn ripgrep(source_root: &Path, args: &serde_json::Value) -> Result<String, String> {
    let pattern = args.get("pattern").and_then(Value::as_str).ok_or("ripgrep requires 'pattern'")?;
    let max_count = args.get("max_count").and_then(Value::as_u64).unwrap_or(50).min(500) as usize;

    let mut cmd = Command::new("rg");
    cmd.arg("--json")
        .arg("--max-count").arg(max_count.to_string())
        .arg("--context").arg("2")
        .arg("--no-heading")
        .current_dir(source_root);

    cmd.arg(pattern);

    if let Some(glob) = args.get("glob").and_then(Value::as_str).filter(|g| !g.is_empty()) {
        cmd.arg("--glob").arg(glob);
    }
    if let Some(subpath) = args.get("path").and_then(Value::as_str).filter(|p| !p.is_empty()) {
        let confined = confine_path(source_root, subpath)?;
        cmd.arg(confined);
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| format!("failed to spawn rg: {e}"))?;

    // Timeout via a simple polling loop.
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > TOOL_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err("ripgrep timed out after 30s".into());
        }
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    read_output(&mut child)
}

// ---------------------------------------------------------------------------
// read_file
// ---------------------------------------------------------------------------

/// Largest valid UTF-8 char boundary at or below `max`, so byte-slicing `s[..n]`
/// never panics by splitting a multi-byte character. (Equivalent to the unstable
/// `str::floor_char_boundary`.)
fn floor_char_boundary(s: &str, max: usize) -> usize {
    if max >= s.len() {
        return s.len();
    }
    let mut i = max;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

pub fn read_file(source_root: &Path, args: &serde_json::Value) -> Result<String, String> {
    let path_str = args.get("path").and_then(Value::as_str).ok_or("read_file requires 'path'")?;
    let confined = confine_path(source_root, path_str)?;

    let content = std::fs::read_to_string(&confined)
        .map_err(|e| format!("cannot read file: {e}"))?;

    let start = args.get("start").and_then(Value::as_u64).unwrap_or(1) as usize;
    let end = args.get("end").and_then(Value::as_u64).map(|v| v as usize);

    if start == 1 && end.is_none() {
        // Return whole file, respecting the output cap.
        if content.len() > MAX_OUTPUT_BYTES {
            let truncated = &content[..floor_char_boundary(&content, MAX_OUTPUT_BYTES)];
            Ok(format!("{truncated}\n--- FILE TRUNCATED at {} KiB ---", MAX_OUTPUT_BYTES / 1024))
        } else {
            Ok(content)
        }
    } else {
        let lines: Vec<&str> = content.lines().collect();
        let end = end.unwrap_or(lines.len()).min(lines.len());
        // Clamp start so it never exceeds end (e.g. start past EOF, or start > end),
        // which would otherwise panic with an inverted slice range.
        let begin = start.saturating_sub(1).min(end);
        let selected: Vec<&str> = lines[begin..end].to_vec();
        let result = selected.join("\n");
        if result.len() > MAX_OUTPUT_BYTES {
            let truncated = &result[..floor_char_boundary(&result, MAX_OUTPUT_BYTES)];
            Ok(format!("{truncated}\n--- OUTPUT TRUNCATED at {} KiB ---", MAX_OUTPUT_BYTES / 1024))
        } else {
            Ok(result)
        }
    }
}

// ---------------------------------------------------------------------------
// Git tools
// ---------------------------------------------------------------------------

/// Execute a git subcommand with argv arguments (no shell string). Only read-only subcommands
/// are permitted.
fn run_git(source_root: &Path, args: &[&str]) -> Result<String, String> {
    let allowlist = ["diff", "log", "show", "status", "branch", "rev-parse", "rev-list", "ls-files"];
    if let Some(cmd) = args.first()
        && !allowlist.contains(cmd) {
            return Err(format!("git subcommand '{cmd}' is not in the read-only allowlist"));
        }

    let mut cmd = Command::new("git");
    cmd.current_dir(source_root)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("failed to spawn git: {e}"))?;

    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > TOOL_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err("git command timed out after 30s".into());
        }
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    read_output(&mut child)
}

pub fn git_diff(source_root: &Path, args: &serde_json::Value) -> Result<String, String> {
    let mut git_args = vec!["diff"];
    if let Some(range) = args.get("rev_range").and_then(Value::as_str).filter(|r| !r.is_empty()) {
        git_args.push(range);
    }
    if let Some(path) = args.get("path").and_then(Value::as_str).filter(|p| !p.is_empty()) {
        git_args.push("--");
        git_args.push(path);
    }
    run_git(source_root, &git_args)
}

pub fn git_log(source_root: &Path, args: &serde_json::Value) -> Result<String, String> {
    let max_count_str = args.get("max_count").and_then(Value::as_u64).unwrap_or(20).min(200).to_string();
    let rev = args.get("rev").and_then(Value::as_str).filter(|r| !r.is_empty()).unwrap_or("HEAD");
    let mut git_args = vec!["log", "--oneline", "-n", &max_count_str, rev];
    if let Some(path) = args.get("path").and_then(Value::as_str).filter(|p| !p.is_empty()) {
        git_args.push("--");
        git_args.push(path);
    }
    run_git(source_root, &git_args)
}

pub fn git_show(source_root: &Path, args: &serde_json::Value) -> Result<String, String> {
    let rev = args.get("rev").and_then(Value::as_str).ok_or("git_show requires 'rev'")?;
    run_git(source_root, &["show", rev])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn test_root() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let mut f = std::fs::File::create(root.join("test.txt")).unwrap();
        writeln!(f, "line1\nline2\nline3\nline4\nline5").unwrap();
        (dir, root)
    }

    #[test]
    fn confine_path_stays_within_root() {
        let (_dir, root) = test_root();
        let result = confine_path(&root, "test.txt");
        assert!(result.is_ok());
        let bad = confine_path(&root, "../etc/passwd");
        assert!(bad.is_err());
    }

    #[test]
    fn read_file_whole() {
        let (_dir, root) = test_root();
        let args = serde_json::json!({ "path": "test.txt" });
        let result = read_file(&root, &args).unwrap();
        assert!(result.starts_with("line1"));
        assert!(result.contains("line5"));
    }

    #[test]
    fn read_file_range() {
        let (_dir, root) = test_root();
        let args = serde_json::json!({ "path": "test.txt", "start": 2, "end": 3 });
        let result = read_file(&root, &args).unwrap();
        assert_eq!(result, "line2\nline3");
    }

    #[test]
    fn floor_char_boundary_avoids_splitting_multibyte_chars() {
        // "é" is 2 bytes; a cap landing mid-character must step back to a boundary.
        let s = "aé";
        assert_eq!(floor_char_boundary(s, 2), 1); // between 'a' and 'é'
        assert_eq!(floor_char_boundary(s, 1), 1);
        assert_eq!(floor_char_boundary(s, 100), s.len());
        // Slicing at the returned index never panics.
        let _ = &s[..floor_char_boundary(s, 2)];
    }

    #[test]
    fn read_file_truncates_multibyte_content_without_panic() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        // Fill well past MAX_OUTPUT_BYTES with a 3-byte char so the cap lands mid-character.
        let big = "あ".repeat(MAX_OUTPUT_BYTES);
        std::fs::write(root.join("big.txt"), &big).unwrap();
        let args = serde_json::json!({ "path": "big.txt" });
        let result = read_file(&root, &args).unwrap();
        assert!(result.contains("FILE TRUNCATED"));
    }

    #[test]
    fn read_file_start_past_end_does_not_panic() {
        let (_dir, root) = test_root();
        // start beyond EOF (and well past end) must not panic on an inverted slice range.
        let args = serde_json::json!({ "path": "test.txt", "start": 395, "end": 200 });
        let result = read_file(&root, &args).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn read_file_outside_root_rejected() {
        let (_dir, root) = test_root();
        let args = serde_json::json!({ "path": "../etc/passwd" });
        let result = read_file(&root, &args);
        assert!(result.is_err());
        let err = result.unwrap_err();
        // On macOS /tmp is a symlink to /private/tmp, so the path may resolve differently.
        assert!(err.contains("escapes") || err.contains("does not exist") || err.contains("inaccessible"));
    }

    #[test]
    fn ripgrep_missing_pattern() {
        let (_dir, root) = test_root();
        let result = ripgrep(&root, &serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn git_allowlist_rejects_unknown() {
        let (_dir, root) = test_root();
        let result = run_git(&root, &["push", "origin", "main"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("allowlist"));
    }

    #[test]
    fn run_git_allows_read_only_commands() {
        let (_dir, root) = test_root();
        // This may fail if git is not available or not a git repo, but the command itself should be allowed.
        let result = run_git(&root, &["status"]);
        // May error because not a git repo, but should not be an "allowlist" error.
        assert!(!result.as_ref().is_err_and(|e| e.contains("allowlist")));
    }
}
