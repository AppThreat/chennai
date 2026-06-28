use crate::shared::LoadedReport;
use std::path::Path;

/// All parsed blint output files for a single binary artifact.
#[derive(Clone)]
#[allow(dead_code)]
pub struct BlintReports {
    /// The primary metadata JSON (header, functions, symbols, imports/exports, etc.).
    pub metadata: LoadedReport,
    /// Optional security findings JSON.
    pub findings: Option<LoadedReport>,
    /// Optional capability reviews JSON.
    pub reviews: Option<LoadedReport>,
    /// Optional fuzzable-entry-points JSON.
    pub fuzzables: Option<LoadedReport>,
    /// Optional CycloneDX SBOM from `blint sbom`.
    pub sbom: Option<LoadedReport>,
    /// Path to the callgraph GraphML export, if generated.
    pub callgraph_path: Option<String>,
    /// Sidecar call graphs parsed from JSON, as `(label, callgraph_json)` pairs.
    /// blint emits these alongside the BOM when `--disassemble` is used:
    /// `<stem>-<app>.dex-callgraph.json` for Android APKs (Dalvik bytecode) and
    /// `<stem>-<app>-<bundle>.callgraph.json` for each Mach-O inside an iOS IPA.
    /// Native ELF/PE/Mach-O binaries instead carry their call graph inline in
    /// `metadata["callgraph"]`, so this is normally non-empty only for apk/ipa.
    pub extra_callgraphs: Vec<(String, serde_json::Value)>,
    /// The detected artifact type (apk, ipa, elf, pe, macho, wasm, etc.).
    pub artifact_type: String,
}

impl BlintReports {
    /// Load all available blint reports for a given artifact file.
    ///
    /// blint names its output files after the **full input file name including its
    /// extension** — e.g. an input `app.apk` produces `app.apk-metadata.json`,
    /// `app.apk-findings.json`, etc. `artifact_basename` must therefore be the file
    /// name with extension (not the stem). The SBOM and callgraph are written to
    /// fixed names (`sbom.cdx.json`, `callgraph.graphml`).
    pub fn load(artifact_basename: &str, output_dir: &Path) -> Result<Self, String> {
        let stem = artifact_basename;

        let metadata_path = output_dir.join(format!("{stem}-metadata.json"));
        let metadata = LoadedReport::from_file(&metadata_path)
            .map_err(|e| format!("failed to load blint metadata: {e}"))?;

        // blint names these either `<stem>-findings.json` or, depending on invocation,
        // a bare `findings.json` in the output dir. Try both.
        let findings = load_optional(output_dir, stem, "findings");
        let reviews = load_optional(output_dir, stem, "reviews");
        let fuzzables = load_optional(output_dir, stem, "fuzzables");

        let sbom_path = output_dir.join("sbom.cdx.json");
        let sbom = if sbom_path.is_file() {
            LoadedReport::from_file(&sbom_path).ok()
        } else {
            None
        };

        // blint exports the callgraph as `<stem>.graphml` (the stem varies by binary),
        // so accept the fixed name if present, otherwise the first `*.graphml` in the dir.
        let callgraph_path = first_graphml(output_dir).map(|p| p.to_string_lossy().to_string());

        // JSON call-graph sidecars (apk Dalvik + iOS Mach-O), emitted with --disassemble.
        let extra_callgraphs = load_callgraph_sidecars(output_dir);

        let artifact_type = detect_artifact_type(stem, &metadata.report);

        Ok(BlintReports {
            metadata,
            findings,
            reviews,
            fuzzables,
            sbom,
            callgraph_path,
            extra_callgraphs,
            artifact_type,
        })
    }
}

/// Load an optional blint report `<name>`, trying the stem-prefixed name
/// (`<stem>-<name>.json`) first and falling back to a bare `<name>.json`.
fn load_optional(dir: &Path, stem: &str, name: &str) -> Option<LoadedReport> {
    let prefixed = dir.join(format!("{stem}-{name}.json"));
    if prefixed.is_file() {
        return LoadedReport::from_file(&prefixed).ok();
    }
    let bare = dir.join(format!("{name}.json"));
    if bare.is_file() {
        return LoadedReport::from_file(&bare).ok();
    }
    None
}

/// Parse blint's JSON call-graph sidecars from `dir`. Matches files ending in
/// `.dex-callgraph.json` (Android Dalvik) or `.callgraph.json` (iOS Mach-O, one per
/// embedded binary). The label is the file name with the redundant suffix trimmed so
/// the agent sees which app/binary each graph belongs to. Sorted for determinism.
fn load_callgraph_sidecars(dir: &Path) -> Vec<(String, serde_json::Value)> {
    let mut out: Vec<(String, serde_json::Value)> = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return out };
    let mut paths: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with(".dex-callgraph.json") || n.ends_with(".callgraph.json"))
                .unwrap_or(false)
        })
        .collect();
    paths.sort();
    for p in paths {
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else { continue };
        let label = name
            .trim_end_matches(".dex-callgraph.json")
            .trim_end_matches(".callgraph.json")
            .to_string();
        if let Ok(report) = LoadedReport::from_file(&p)
            && report.report.get("nodes").map(|n| n.is_array()).unwrap_or(false)
        {
            out.push((label, report.report));
        }
    }
    out
}

/// Return a GraphML callgraph export from `dir`: the fixed `callgraph.graphml` if present,
/// otherwise the first file with a `.graphml` extension (blint names it `<stem>.graphml`).
fn first_graphml(dir: &Path) -> Option<std::path::PathBuf> {
    let fixed = dir.join("callgraph.graphml");
    if fixed.is_file() {
        return Some(fixed);
    }
    std::fs::read_dir(dir).ok()?.flatten().map(|e| e.path()).find(|p| {
        p.extension().and_then(|e| e.to_str()) == Some("graphml")
    })
}

/// Detect the binary artifact type, preferring blint's own metadata fields
/// (`exe_type` / `binary_type`) and falling back to the file-name extension.
fn detect_artifact_type(basename: &str, metadata: &serde_json::Value) -> String {
    if let Some(exe) = metadata["exe_type"].as_str() {
        match exe {
            "dexbinary" => return "apk".to_string(),
            other if !other.is_empty() => return other.to_string(),
            _ => {}
        }
    }
    if let Some(bt) = metadata["binary_type"].as_str()
        && !bt.is_empty()
    {
        return bt.to_string();
    }
    let lower = basename.to_lowercase();
    for (suffix, kind) in [
        (".apkm", "apk"), (".apk", "apk"), (".aab", "apk"),
        (".ipa", "ipa"), (".wasm", "wasm"),
        (".dll", "pe"), (".exe", "pe"),
        (".so", "elf"), (".dylib", "macho"),
    ] {
        if lower.ends_with(suffix) {
            return kind.to_string();
        }
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blint_loader_uses_full_filename_with_extension() {
        // blint names outputs after the full file name including the extension.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.apk-metadata.json"),
            r#"{"exe_type":"dexbinary","functions":[]}"#,
        )
        .unwrap();
        let reports = BlintReports::load("app.apk", dir.path()).unwrap();
        assert_eq!(reports.metadata.report["exe_type"].as_str(), Some("dexbinary"));
        assert_eq!(reports.artifact_type, "apk");
        assert!(reports.findings.is_none());
    }

    #[test]
    fn test_blint_loader_all_files() {
        let dir = tempfile::tempdir().unwrap();
        let base = "myapp.exe";
        std::fs::write(dir.path().join(format!("{base}-metadata.json")), r#"{"binary_type":"PE32"}"#).unwrap();
        std::fs::write(dir.path().join(format!("{base}-findings.json")), r#"{"findings":[]}"#).unwrap();
        std::fs::write(dir.path().join(format!("{base}-reviews.json")), r#"{"reviews":[]}"#).unwrap();
        std::fs::write(dir.path().join(format!("{base}-fuzzables.json")), r#"[]"#).unwrap();
        std::fs::write(dir.path().join("sbom.cdx.json"), r#"{"bomFormat":"CycloneDX"}"#).unwrap();
        std::fs::write(dir.path().join("callgraph.graphml"), r#"<?xml?>"#).unwrap();

        let reports = BlintReports::load(base, dir.path()).unwrap();
        assert!(reports.findings.is_some());
        assert!(reports.reviews.is_some());
        assert!(reports.fuzzables.is_some());
        assert!(reports.sbom.is_some());
        assert!(reports.callgraph_path.is_some());
        assert_eq!(reports.artifact_type, "PE32");
    }

    #[test]
    fn test_blint_loader_bare_findings_reviews() {
        // Some blint invocations write bare `findings.json` / `reviews.json` (no stem prefix).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.apk-metadata.json"), r#"{"exe_type":"dexbinary"}"#).unwrap();
        std::fs::write(dir.path().join("findings.json"), r#"{"findings":[]}"#).unwrap();
        std::fs::write(dir.path().join("reviews.json"), r#"{"reviews":[]}"#).unwrap();
        let reports = BlintReports::load("app.apk", dir.path()).unwrap();
        assert!(reports.findings.is_some());
        assert!(reports.reviews.is_some());
    }

    #[test]
    fn test_blint_loader_missing_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let result = BlintReports::load("test.apk", dir.path());
        assert!(result.is_err());
    }
}
