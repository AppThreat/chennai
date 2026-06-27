//! Spawns and talks to the `chennai-engine` Scala process over stdio NDJSON.

use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("engine binary not found; set CHENNAI_ENGINE or pass --engine")]
    NotFound,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("engine returned error: {0}")]
    Remote(String),
}

/// A live connection to a spawned engine subprocess.
pub struct Engine {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
}

impl Engine {
    /// Resolve the engine command from an explicit override, the `CHENNAI_ENGINE` env var, or a
    /// set of conventional staged locations relative to the current directory.
    pub fn resolve_command(explicit: Option<&str>) -> Option<PathBuf> {
        if let Some(p) = explicit {
            let pb = PathBuf::from(p);
            return pb.exists().then_some(pb);
        }
        if let Ok(p) = std::env::var("CHENNAI_ENGINE") {
            let pb = PathBuf::from(p);
            if pb.exists() {
                return Some(pb);
            }
        }
        // Look relative to the TUI binary (npm/bundled layout: bin/chennai + bin/chennai-engine)
        if let Ok(exe) = std::env::current_exe()
            && let Some(parent) = exe.parent() {
                let sibling = parent.join("chennai-engine");
                if sibling.exists() {
                    return Some(sibling);
                }
        }
        let candidates = [
            "engine/target/universal/stage/bin/chennai-engine",
            "../engine/target/universal/stage/bin/chennai-engine",
        ];
        candidates
            .iter()
            .map(PathBuf::from)
            .find(|pb| pb.exists())
    }

    /// Spawn the engine in `--serve` mode.
    pub fn spawn(command: &Path) -> Result<Self, EngineError> {
        let mut child = Command::new(command)
            .arg("--serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child.stdin.take().ok_or(EngineError::NotFound)?;
        let stdout = child.stdout.take().ok_or(EngineError::NotFound)?;
        Ok(Engine {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 0,
        })
    }

    /// Send a request and block for its response, returning the `data` payload deserialized.
    pub fn request<T: DeserializeOwned>(
        &mut self,
        cmd: &str,
        args: Value,
    ) -> Result<T, EngineError> {
        self.next_id += 1;
        let id = self.next_id;
        let req = json!({"id": id, "cmd": cmd, "args": args});
        writeln!(self.stdin, "{}", req)?;
        self.stdin.flush()?;

        let mut line = String::new();
        if self.stdout.read_line(&mut line)? == 0 {
            return Err(EngineError::Protocol("engine closed the connection".into()));
        }
        let resp: Value = serde_json::from_str(line.trim())
            .map_err(|e| EngineError::Protocol(format!("bad json: {e}")))?;

        if resp.get("ok").and_then(Value::as_bool) == Some(true) {
            let data = resp.get("data").cloned().unwrap_or(Value::Null);
            serde_json::from_value(data).map_err(|e| EngineError::Protocol(e.to_string()))
        } else {
            let msg = resp
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown error")
                .to_string();
            // Strip the Scala REPL's "-- Error: " prefix so the actual error shows directly.
            let msg = msg
                .strip_prefix("-- Error: ")
                .or_else(|| msg.strip_prefix("-- Error:\n"))
                .or_else(|| msg.strip_prefix("-- "))
                .map(|s| s.to_string())
                .unwrap_or(msg);
            Err(EngineError::Remote(msg))
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Given a user-supplied path (a directory or an `.atom` file), resolve the atom file to open.
#[allow(dead_code)]
pub fn resolve_atom(path: &Path) -> Result<PathBuf, EngineError> {
    if path.is_file() {
        return Ok(path.to_path_buf());
    }
    if path.is_dir() {
        let mut atoms: Vec<PathBuf> = std::fs::read_dir(path)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|e| e == "atom").unwrap_or(false))
            .collect();
        atoms.sort();
        return atoms
            .into_iter()
            .next()
            .ok_or_else(|| EngineError::Protocol(format!("no .atom file in {}", path.display())));
    }
    Err(EngineError::Protocol(format!(
        "path does not exist: {}",
        path.display()
    )))
}
