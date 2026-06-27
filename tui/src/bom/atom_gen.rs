//! Atom CLI discovery and generation — the counterpart to [`super::generator`] for the `atom` tool.
//!
//! The `atom` CLI (from [`@appthreat/atom`](https://github.com/AppThreat/atom)) creates `.atom`
//! files with dependency tracking and data-flow information.  When no `.atom` file exists for a
//! project, chennai can offer to generate one on the fly: first producing a CycloneDX SBOM (via
//! cdxgen) and then passing it through the atom CLI with `--with-data-deps`.
//!
//! # Lookup order for the atom binary
//!
//! 1. `ATOM_CMD` environment variable
//! 2. `atom` on `PATH`
//!
//! # Auto-install
//!
//! When the tools are missing but `npm` is available, chennai can install all three packages
//! globally with a single `npm install -g --ignore-scripts` invocation.

use std::path::{Path, PathBuf};

/// Filename used for the generated atom file.
pub const ATOM_FILENAME: &str = "app.atom";

/// Detect a source language from well-known marker files in `source_dir`, using a
/// priority-ordered waterfall (first match wins), modelled after cdxgen's `createXBom`.
///
/// Only languages with a dedicated atom CLI frontend are returned:
///
/// | Marker file(s)                              | Language tag |
/// |---------------------------------------------|--------------|
/// | `tsconfig.json` / `tslint.json`             | `ts`         |
/// | `package.json` / `yarn.lock` / `rush.json`  | `js`         |
/// | `Pipfile` / `poetry.lock` / `setup.py` / `pyproject.toml` / `*requirements*.txt` | `py` |
/// | `pom.xml` / `build.gradle` / `build.gradle.kts` / `gradle.lockfile` | `java` |
/// | `build.sbt` / `build.sc`                    | `scala`      |
/// | `composer.json` / `composer.lock`           | `php`        |
/// | `Gemfile` / `Gemfile.lock`                  | `rb`         |
/// | `CMakeLists.txt` / `CMakeCache.txt` / `configure` / `meson.build` | `cpp` |
///
/// Returns `None` when no marker is found — callers may fall back to `"all"`.
pub fn detect_language(source_dir: &Path) -> Option<&'static str> {
    // TypeScript markers (checked before plain JS because tsconfig.json
    // co-exists with package.json in TypeScript projects).
    if has_any(source_dir, &["tsconfig.json", "tslint.json"]) {
        return Some("ts");
    }
    // JavaScript / Node.js
    if has_any(source_dir, &["package.json", "yarn.lock", "rush.json", "pnpm-lock.yaml"]) {
        return Some("js");
    }
    // Python (pipenv / poetry / pyproject / setup.py / requirements.txt)
    if has_any(source_dir, &["Pipfile", "poetry.lock", "setup.py", "pyproject.toml"]) {
        return Some("py");
    }
    if has_glob(source_dir, "*requirements*.txt") {
        return Some("py");
    }
    // Java (Maven / Gradle)
    if has_any(source_dir, &["pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile", "settings.gradle"]) {
        return Some("java");
    }
    // Scala (SBT / Mill)
    if has_any(source_dir, &["build.sbt", "build.sc"]) {
        return Some("scala");
    }
    // PHP
    if has_any(source_dir, &["composer.json", "composer.lock"]) {
        return Some("php");
    }
    // Ruby
    if has_any(source_dir, &["Gemfile", "Gemfile.lock"]) {
        return Some("rb");
    }
    // C / C++
    if has_any(source_dir, &["CMakeLists.txt", "CMakeCache.txt", "configure", "meson.build", "conanfile.txt"]) {
        return Some("cpp");
    }

    None
}

/// Return `true` when at least one of the `names` exists as a file in `dir`.
fn has_any(dir: &Path, names: &[&str]) -> bool {
    names.iter().any(|n| dir.join(n).exists())
}

/// Return `true` when a file matching the simple glob `pattern` exists in `dir`.
///
/// The pattern may contain `*` as a wildcard that matches any sequence of characters
/// (e.g. `*requirements*.txt` matches `requirements.txt` and `dev-requirements.txt`).
fn has_glob(dir: &Path, pattern: &str) -> bool {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return false,
    };
    // Split on `*` to isolate the literal parts.  Empty strings appear when the
    // pattern starts or ends with `*`, or when there are consecutive `*`s.
    let parts: Vec<&str> = pattern.split('*').collect();
    let prefixes_first = !pattern.starts_with('*');
    let suffixes_last = !pattern.ends_with('*');

    'next_entry: for entry in entries.flatten() {
        let fname = entry.file_name();
        let Some(name) = fname.to_str() else {
            continue;
        };
        // When the pattern does NOT start with `*`, the first literal must be a prefix.
        if prefixes_first && !name.starts_with(parts[0]) {
            continue;
        }
        // When the pattern does NOT end with `*`, the last literal must be a suffix.
        if suffixes_last && !name.ends_with(parts[parts.len() - 1]) {
            continue;
        }
        // Every non-empty literal part must appear in order inside the name.
        let non_empty: Vec<&str> = parts.iter().filter(|s| !s.is_empty()).copied().collect();
        let mut pos = 0usize;
        for literal in &non_empty {
            let Some(found) = name[pos..].find(literal) else {
                continue 'next_entry;
            };
            pos += found + literal.len();
        }
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Locate the `atom` CLI binary.
///
/// Checks, in order:
/// 1. `ATOM_CMD` environment variable
/// 2. `atom` on `PATH`
pub fn find_atom() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("ATOM_CMD") {
        let pb = PathBuf::from(&path);
        if pb.is_file() {
            return Ok(pb);
        }
    }

    if let Some(path) = which("atom") {
        return Ok(path);
    }

    Err(
        "atom CLI not found. Install it with: npm install -g @appthreat/atom @appthreat/atom-parsetools"
            .to_string(),
    )
}

/// Check whether `npm` is available on PATH.
pub fn find_npm() -> Option<PathBuf> {
    which("npm").or_else(|| which("npm.cmd"))
}

// ---------------------------------------------------------------------------
// Auto-install
// ---------------------------------------------------------------------------

/// Automatically install the required npm packages globally.
///
/// Runs `npm install -g --ignore-scripts @cyclonedx/cdxgen @appthreat/atom @appthreat/atom-parsetools`.
pub fn auto_install_npm() -> Result<(), String> {
    let npm = find_npm().ok_or_else(|| "npm not found on PATH".to_string())?;
    let status = std::process::Command::new(&npm)
        .args([
            "install",
            "-g",
            "--ignore-scripts",
            "@cyclonedx/cdxgen",
            "@appthreat/atom",
            "@appthreat/atom-parsetools",
        ])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| format!("failed to run npm: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("npm install exited with {status}"))
    }
}

// ---------------------------------------------------------------------------
// Atom generation
// ---------------------------------------------------------------------------

/// Generate an atom file for the given source directory using the atom CLI.
///
/// The atom is generated with `--with-data-deps` to include data-flow information.
/// You **must** supply a `language` tag (e.g. `"js"`, `"py"`, `"java"`) — without it
/// the atom CLI refuses to run.  Use [`super::detect_language`] to auto-detect, or
/// pass `"all"` to let the atom CLI probe the source tree.
///
/// Returns the path to the generated `.atom` file.
///
/// # Arguments
/// * `source_dir` — The project source directory to analyse
/// * `output_path` — The desired path for the output `.atom` file
/// * `language` — Source language identifier (e.g. `"js"`, `"py"`, `"all"`)
pub fn generate_atom(source_dir: &Path, output_path: &Path, language: &str) -> Result<PathBuf, String> {
    let atom_bin = find_atom()?;

    // Ensure the parent directory exists.
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create output dir {}: {e}", parent.display()))?;
    }

    let status = std::process::Command::new(&atom_bin)
        .arg("--with-data-deps")
        .arg("--language")
        .arg(language)
        .arg("--output")
        .arg(output_path.to_str().unwrap_or("app.atom"))
        .arg(source_dir.to_str().unwrap_or("."))
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| format!("failed to execute atom CLI: {e}"))?;

    if !status.success() {
        return Err(format!(
            "atom CLI exited with {status}. Ensure the tool is properly installed with: \
             npm install -g @appthreat/atom @appthreat/atom-parsetools"
        ));
    }

    // Give the JVM a moment to flush the atom file to disk.
    std::thread::sleep(std::time::Duration::from_millis(500));

    if output_path.is_file() {
        Ok(output_path.to_path_buf())
    } else {
        Err(format!(
            "atom CLI completed but output file {} was not created",
            output_path.display()
        ))
    }
}

/// Compute the default atom output path inside a source directory.
///
/// Uses [`ATOM_FILENAME`] as the file name (e.g. `app.atom`).
pub fn atom_output_path(source_dir: &Path) -> PathBuf {
    source_dir.join(ATOM_FILENAME)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Simple `<stdin.h>` / `which` replacement.
fn which(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var("PATH").ok()?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Prompt the user on stderr for a yes/no answer and return the boolean.
///
/// The prompt is printed on stderr, then a single line is read from stdin.
/// An empty response, `y`, `Y`, `yes`, or `Yes` are all treated as affirmative;
/// everything else is `false`.
pub fn prompt_yes_no(prompt: &str) -> bool {
    eprint!("{} [Y/n] ", prompt);
    // Flush stderr so the prompt appears before we block on stdin.
    use std::io::Write;
    let _ = std::io::stderr().flush();
    let mut input = String::new();
    match std::io::stdin().read_line(&mut input) {
        Ok(_) => {
            let trimmed = input.trim().to_lowercase();
            trimmed.is_empty() || trimmed == "y" || trimmed == "yes"
        }
        Err(_) => false,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atom_output_path_default() {
        let dir = Path::new("/tmp/test-project");
        assert_eq!(atom_output_path(dir), dir.join("app.atom"));
    }

    #[test]
    fn test_atom_output_path_absolute() {
        let dir = Path::new("/home/user/projects/my-app");
        assert_eq!(atom_output_path(dir), dir.join("app.atom"));
    }

    #[test]
    fn test_which_returns_none_for_nonexistent() {
        assert!(
            which("this-command-definitely-does-not-exist-12345xyz").is_none()
        );
    }

    #[test]
    fn test_find_npm_returns_something_when_available() {
        if let Some(npm) = find_npm() {
            assert!(npm.is_file(), "npm path must be an actual file");
        }
        // If npm is not on PATH the test simply passes — the function
        // gracefully returns None.
    }

    #[test]
    fn test_find_atom_via_env_var() {
        let original = std::env::var("ATOM_CMD").ok();
        if let Some(node) = which("node") {
            // SAFETY: test-only environment mutation with restore.
            unsafe { std::env::set_var("ATOM_CMD", &node); }
            let result = find_atom();
            assert!(
                result.is_ok(),
                "find_atom should find the binary pointed to by ATOM_CMD"
            );
            if let Ok(path) = result {
                assert_eq!(path, node);
            }
            match original {
                Some(v) => unsafe { std::env::set_var("ATOM_CMD", v); },
                None => unsafe { std::env::remove_var("ATOM_CMD"); },
            }
        }
    }

    #[test]
    fn test_find_atom_env_var_nonexistent_file() {
        let original = std::env::var("ATOM_CMD").ok();
        // SAFETY: test-only environment mutation with restore.
        unsafe { std::env::set_var("ATOM_CMD", "/nonexistent/path/to/atom"); }
        let _result = find_atom();
        match original {
            Some(v) => unsafe { std::env::set_var("ATOM_CMD", v); },
            None => unsafe { std::env::remove_var("ATOM_CMD"); },
        }
    }

    #[test]
    fn test_auto_install_npm_fails_without_npm() {
        let original_path = std::env::var("PATH").ok();
        // SAFETY: test-only environment mutation with restore.
        unsafe { std::env::set_var("PATH", "/tmp"); }
        let result = auto_install_npm();
        assert!(result.is_err(), "auto_install should fail without npm");
        assert!(
            result.unwrap_err().contains("npm not found"),
            "error message should mention npm not found"
        );
        if let Some(p) = original_path {
            unsafe { std::env::set_var("PATH", p); }
        } else {
            unsafe { std::env::remove_var("PATH"); }
        }
    }

    #[test]
    fn test_detect_language_js() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        assert_eq!(detect_language(dir.path()), Some("js"));
    }

    #[test]
    fn test_detect_language_ts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("tsconfig.json"), "{}").unwrap();
        // TypeScript takes priority over JavaScript.
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        assert_eq!(detect_language(dir.path()), Some("ts"));
    }

    #[test]
    fn test_detect_language_py() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "").unwrap();
        assert_eq!(detect_language(dir.path()), Some("py"));
    }

    #[test]
    fn test_detect_language_py_pyproject() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pyproject.toml"), "").unwrap();
        assert_eq!(detect_language(dir.path()), Some("py"));
    }

    #[test]
    fn test_detect_language_java() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pom.xml"), "<project/>").unwrap();
        assert_eq!(detect_language(dir.path()), Some("java"));
    }

    #[test]
    fn test_detect_language_java_gradle() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("build.gradle"), "").unwrap();
        assert_eq!(detect_language(dir.path()), Some("java"));
    }

    #[test]
    fn test_detect_language_scala() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("build.sbt"), "").unwrap();
        assert_eq!(detect_language(dir.path()), Some("scala"));
    }

    #[test]
    fn test_detect_language_php() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("composer.json"), "{}").unwrap();
        assert_eq!(detect_language(dir.path()), Some("php"));
    }

    #[test]
    fn test_detect_language_ruby() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Gemfile"), "").unwrap();
        assert_eq!(detect_language(dir.path()), Some("rb"));
    }

    #[test]
    fn test_detect_language_cpp() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("CMakeLists.txt"), "").unwrap();
        assert_eq!(detect_language(dir.path()), Some("cpp"));
    }

    #[test]
    fn test_detect_language_unknown() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(detect_language(dir.path()), None);
    }

    #[test]
    fn test_has_any_true() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foo.txt"), "").unwrap();
        assert!(has_any(dir.path(), &["foo.txt", "bar.txt"]));
    }

    #[test]
    fn test_has_any_false() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!has_any(dir.path(), &["nonexistent.a", "nonexistent.b"]));
    }

    #[test]
    fn test_has_glob_requirements() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "").unwrap();
        assert!(has_glob(dir.path(), "*requirements*.txt"));
    }

    #[test]
    fn test_has_glob_dev_requirements() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("dev-requirements.txt"), "").unwrap();
        assert!(has_glob(dir.path(), "*requirements*.txt"));
    }

    #[test]
    fn test_has_glob_no_match() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!has_glob(dir.path(), "*requirements*.txt"));
    }

    #[test]
    fn test_generate_atom_fails_without_atom_binary() {
        let original_path = std::env::var("PATH").ok();
        // SAFETY: test-only environment mutation with restore.
        unsafe { std::env::set_var("PATH", "/tmp"); }
        let original_env = std::env::var("ATOM_CMD").ok();
        unsafe { std::env::remove_var("ATOM_CMD"); }

        let tmp = tempfile::tempdir().unwrap();
        let result = generate_atom(tmp.path(), &tmp.path().join("test.atom"), "js");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("atom CLI not found"),
            "error must mention missing atom CLI"
        );

        if let Some(p) = original_path {
            unsafe { std::env::set_var("PATH", p); }
        } else {
            unsafe { std::env::remove_var("PATH"); }
        }
        match original_env {
            Some(v) => unsafe { std::env::set_var("ATOM_CMD", v); },
            None => unsafe { std::env::remove_var("ATOM_CMD"); },
        }
    }
}
