use crate::bom::store::BomStore;
use std::path::{Path, PathBuf};

/// Known lifecycle phases for multi-phase BOM generation.
pub const LIFECYCLES: &[&str] = &["build", "postbuild"];

/// Find and load existing .cdx.json BOM files from a directory.
/// Returns a loaded BomStore if any BOMs are found.
pub fn find_existing_boms(dir: &Path) -> BomStore {
    let mut store = BomStore::new();
    if dir.exists() {
        let _ = store.load_path(dir);
    }
    store
}

/// Check if the output directory already has a BOM file matching our naming convention.
#[allow(dead_code)]
pub fn has_existing_bom(dir: &Path) -> bool {
    if !dir.exists() {
        return false;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return false,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("sbom-") && name.ends_with(".cdx.json") {
            return true;
        }
    }
    false
}

/// Detect the programming language for a given source directory.
/// Returns a short identifier suitable for BOM naming (e.g. "js", "py", "java").
pub fn detect_language(source_dir: &Path) -> Option<String> {
    let markers = [
        ("package.json", "js"),
        ("yarn.lock", "js"),
        ("pnpm-lock.yaml", "js"),
        ("requirements.txt", "py"),
        ("Pipfile", "py"),
        ("pyproject.toml", "py"),
        ("poetry.lock", "py"),
        ("pom.xml", "java"),
        ("build.gradle", "java"),
        ("build.gradle.kts", "java"),
        ("gradle.lockfile", "java"),
        ("Cargo.toml", "rust"),
        ("Cargo.lock", "rust"),
        ("go.mod", "go"),
        ("go.sum", "go"),
        ("Gemfile", "rb"),
        ("Gemfile.lock", "rb"),
        ("composer.json", "php"),
        ("composer.lock", "php"),
        ("DESCRIPTION", "r"),
        ("cran.log", "r"),
        ("packages.config", "dotnet"),
        ("*.csproj", "dotnet"),
        ("*.fsproj", "dotnet"),
        ("*.vbproj", "dotnet"),
        ("project.clj", "clj"),
        ("deps.edn", "clj"),
        ("shadow-cljs.edn", "cljs"),
        ("mix.exs", "elixir"),
        ("rebar.config", "erlang"),
        ("build.sbt", "scala"),
        ("build.sc", "scala"),
        ("swift.package", "swift"),
        ("Package.swift", "swift"),
        ("Podfile", "objc"),
        ("Cartfile", "objc"),
        ("cpanfile", "perl"),
        ("Makefile.PL", "perl"),
        ("BUILD", "bazel"),
        ("WORKSPACE", "bazel"),
        ("conanfile.py", "cpp"),
        ("conanfile.txt", "cpp"),
        ("vcpkg.json", "cpp"),
        ("CMakeLists.txt", "cpp"),
    ];

    for (marker, lang) in &markers {
        if let Some(ext) = marker.strip_prefix('*') {
            if has_file_with_extension(source_dir, ext) {
                return Some(lang.to_string());
            }
        } else if source_dir.join(marker).exists() {
            return Some(lang.to_string());
        }
    }

    None
}

fn has_file_with_extension(dir: &Path, ext: &str) -> bool {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return false,
    };
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str()
            && name.ends_with(ext) {
                return true;
        }
    }
    false
}

/// Determine the appropriate output filename for a BOM given a language and lifecycle phase.
/// Format: `sbom-<language>-<lifecycle>.cdx.json` or `sbom-<lifecycle>.cdx.json` if language is unknown.
pub fn bom_filename(language: Option<&str>, lifecycle: &str) -> String {
    match language {
        Some(l) => format!("sbom-{l}-{lifecycle}.cdx.json"),
        None => format!("sbom-{lifecycle}.cdx.json"),
    }
}

/// Generate a CycloneDX SBOM using cdxgen for the given source directory.
///
/// The output file is named `sbom-{language}-{lifecycle}.cdx.json` and placed in `output_dir`.
/// If the language cannot be detected, the file is named `sbom-{lifecycle}.cdx.json`.
/// Returns the path to the generated file on success.
///
/// # Arguments
/// * `source_dir` - The project source directory to analyze
/// * `output_dir` - The directory to write the BOM file into
/// * `lifecycle` - The lifecycle phase (e.g. "build", "postbuild")
/// * `language` - Optional detected language identifier
pub fn generate_bom(
    source_dir: &Path,
    output_dir: &Path,
    lifecycle: &str,
    language: Option<&str>,
) -> Result<PathBuf, String> {
    let filename = bom_filename(language, lifecycle);
    let output_path = output_dir.join(&filename);

    // Ensure output directory exists
    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("failed to create output dir {}: {e}", output_dir.display()))?;

    // Check if cdxgen is available
    let cdxgen = find_cdxgen()?;

    // Build cdxgen arguments
    let mut cmd = std::process::Command::new(&cdxgen);
    cmd.arg("--output")
        .arg(output_path.to_str().unwrap_or("bom.json"));

    // Add lifecycle if supported
    if let Some(lifecycle_val) = lifecycle_option(lifecycle) {
        cmd.arg("--lifecycle").arg(lifecycle_val);
    }

    cmd.arg(source_dir.to_str().unwrap_or("."))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());

    let status = cmd
        .status()
        .map_err(|e| format!("failed to execute cdxgen: {e}"))?;

    if !status.success() {
        return Err(format!(
            "cdxgen exited with status {}. Ensure the tool is properly installed with: npm install -g @cyclonedx/cdxgen",
            status
        ));
    }

    Ok(output_path)
}

fn lifecycle_option(lifecycle: &str) -> Option<&'static str> {
    match lifecycle {
        "build" => Some("build"),
        "postbuild" => Some("post-build"),
        _ => None,
    }
}

/// Combined logic: look for existing BOMs first, generate if none found.
/// Returns the loaded BomStore and whether generation was attempted.
#[allow(dead_code)]
pub fn ensure_bom(
    source_dir: Option<&Path>,
    reports_dir: Option<&Path>,
) -> (BomStore, bool) {
    // Priority 1: Check the reports directory for existing BOMs
    if let Some(rdir) = reports_dir {
        let store = find_existing_boms(rdir);
        if store.loaded {
            return (store, false);
        }
    }

    // Priority 2: Check the source directory for existing BOMs
    if let Some(sdir) = source_dir {
        let store = find_existing_boms(sdir);
        if store.loaded {
            return (store, false);
        }
    }

    // Priority 3: No existing BOMs — try to generate one
    if let Some(sdir) = source_dir {
        let language = detect_language(sdir);
        let out_dir = reports_dir.unwrap_or(sdir);

        // Try each lifecycle phase in order
        for lifecycle in LIFECYCLES {
            match generate_bom(sdir, out_dir, lifecycle, language.as_deref()) {
                Ok(path) => {
                    let mut store = BomStore::new();
                    match store.load_path(&path) {
                        Ok(_) => return (store, true),
                        Err(e) => {
                            eprintln!("Warning: failed to load generated BOM: {e}");
                            return (BomStore::new(), true);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Warning: cdxgen generation ({lifecycle}) failed: {e}");
                }
            }
        }
        (BomStore::new(), true)
    } else {
        (BomStore::new(), false)
    }
}

/// Locate the cdxgen binary. Checks, in order:
/// 1. `CDXGEN` environment variable
/// 2. `cdxgen` in PATH
/// 3. `node_modules/.bin/cdxgen` relative to the TUI binary
pub fn find_cdxgen() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("CDXGEN") {
        let pb = PathBuf::from(&path);
        if pb.is_file() {
            return Ok(pb);
        }
    }

    if let Some(path) = which("cdxgen") {
        return Ok(path);
    }

    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent() {
            let candidates = [
                parent.join("node_modules").join(".bin").join("cdxgen"),
                parent.join("..").join("node_modules").join(".bin").join("cdxgen"),
            ];
            for c in &candidates {
                if c.is_file() {
                    return Ok(c.clone());
                }
            }
    }

    Err("cdxgen not found. Install it with: npm install -g @cyclonedx/cdxgen".to_string())
}

/// Simple `which` replacement that checks PATH.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_existing_boms_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let store = find_existing_boms(dir.path());
        assert!(!store.loaded);
    }

    #[test]
    fn test_find_existing_boms_with_file() {
        let dir = tempfile::tempdir().unwrap();
        let bom_content = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"test","version":"1.0"}]}"#;
        std::fs::write(dir.path().join("sbom-js-build.cdx.json"), bom_content).unwrap();

        let store = find_existing_boms(dir.path());
        assert!(store.loaded);
        assert_eq!(store.total_components, 1);
    }

    #[test]
    fn test_has_existing_bom() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!has_existing_bom(dir.path()));

        std::fs::write(dir.path().join("sbom-js-build.cdx.json"), "{}").unwrap();
        assert!(has_existing_bom(dir.path()));
    }

    #[test]
    fn test_has_existing_bom_nonexistent_dir() {
        assert!(!has_existing_bom(Path::new("/nonexistent/path")));
    }

    #[test]
    fn test_ensure_bom_no_source() {
        let (store, generated) = ensure_bom(None, None);
        assert!(!store.loaded);
        assert!(!generated);
    }

    #[test]
    fn test_has_existing_bom_wrong_prefix() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bom.json"), "{}").unwrap();
        assert!(!has_existing_bom(dir.path()));
    }

    #[test]
    fn test_bom_filename() {
        assert_eq!(bom_filename(Some("js"), "build"), "sbom-js-build.cdx.json");
        assert_eq!(bom_filename(Some("py"), "postbuild"), "sbom-py-postbuild.cdx.json");
        assert_eq!(bom_filename(None, "build"), "sbom-build.cdx.json");
    }

    #[test]
    fn test_detect_language_node() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        assert_eq!(detect_language(dir.path()).as_deref(), Some("js"));
    }

    #[test]
    fn test_detect_language_python() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "").unwrap();
        assert_eq!(detect_language(dir.path()).as_deref(), Some("py"));
    }

    #[test]
    fn test_detect_language_unknown() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("README.md"), "# Project").unwrap();
        assert!(detect_language(dir.path()).is_none());
    }

    #[test]
    fn test_detect_language_java() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pom.xml"), "<project/>").unwrap();
        assert_eq!(detect_language(dir.path()).as_deref(), Some("java"));
    }

    #[test]
    fn test_detect_language_rust() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]").unwrap();
        assert_eq!(detect_language(dir.path()).as_deref(), Some("rust"));
    }

    #[test]
    fn test_ensure_bom_existing_in_source() {
        let dir = tempfile::tempdir().unwrap();
        let bom_content = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"test","version":"1.0"}]}"#;
        std::fs::write(dir.path().join("sbom-js-build.cdx.json"), bom_content).unwrap();

        let (store, generated) = ensure_bom(Some(dir.path()), None);
        assert!(store.loaded);
        assert_eq!(store.total_components, 1);
        assert!(!generated);
    }

    #[test]
    fn test_ensure_bom_checks_reports_before_source() {
        let reports = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();

        std::fs::write(
            reports.path().join("sbom-py-build.cdx.json"),
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"report-comp","version":"1.0"}]}"#,
        ).unwrap();
        std::fs::write(
            source.path().join("sbom-js-build.cdx.json"),
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"source-comp","version":"2.0"}]}"#,
        ).unwrap();

        let (store, generated) = ensure_bom(Some(source.path()), Some(reports.path()));
        assert!(store.loaded);
        assert_eq!(store.components[0].name_display(), "report-comp");
        assert!(!generated);
    }
}
