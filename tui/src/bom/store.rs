use crate::bom::schema::*;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct BomFile {
    pub bom: Bom,
    #[allow(dead_code)]
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SortField {
    Type,
    Name,
    Version,
    Purl,
    License,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SortOrder {
    Ascending,
    Descending,
}

#[allow(dead_code)]
impl SortOrder {
    pub fn toggle(self) -> Self {
        match self {
            SortOrder::Ascending => SortOrder::Descending,
            SortOrder::Descending => SortOrder::Ascending,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FilterState {
    pub query: String,
    pub component_type: Option<String>,
}

impl fmt::Display for SortField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SortField::Type => write!(f, "Type"),
            SortField::Name => write!(f, "Name"),
            SortField::Version => write!(f, "Version"),
            SortField::Purl => write!(f, "Purl"),
            SortField::License => write!(f, "License"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ComponentRow {
    pub component: Component,
}

impl ComponentRow {
    pub fn type_display(&self) -> &str {
        &self.component.component_type
    }

    pub fn name_display(&self) -> &str {
        self.component.name.as_deref().unwrap_or("-")
    }

    pub fn version_display(&self) -> &str {
        self.component.version.as_deref().unwrap_or("-")
    }

    pub fn purl_display(&self) -> &str {
        self.component.purl.as_deref().unwrap_or("-")
    }

    pub fn license_display(&self) -> String {
        self.component
            .licenses
            .as_ref()
            .and_then(|licenses| {
                licenses.first().and_then(|lc| {
                    lc.expression
                        .clone()
                        .or_else(|| lc.license.as_ref().and_then(|l| l.id.clone()))
                        .or_else(|| lc.license.as_ref().and_then(|l| l.name.clone()))
                })
            })
            .unwrap_or_else(|| "-".to_string())
    }

    pub fn bom_ref_display(&self) -> &str {
        self.component.bom_ref.as_deref().unwrap_or("-")
    }

    pub fn description_display(&self) -> &str {
        self.component.description.as_deref().unwrap_or("-")
    }

    pub fn crypto_algorithm(&self) -> Option<String> {
        self.component
            .crypto_properties
            .as_ref()
            .and_then(|cp| {
                cp.algorithm_properties
                    .as_ref()
                    .and_then(|ap| ap.primitive.clone())
            })
    }

    pub fn matches_query(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let q = query.to_lowercase();
        self.name_display().to_lowercase().contains(&q)
            || self.type_display().to_lowercase().contains(&q)
            || self.version_display().to_lowercase().contains(&q)
            || self.purl_display().to_lowercase().contains(&q)
            || self.license_display().to_lowercase().contains(&q)
            || self.bom_ref_display().to_lowercase().contains(&q)
            || self.description_display().to_lowercase().contains(&q)
            || self.component.group.as_deref().unwrap_or("").to_lowercase().contains(&q)
            || self
                .crypto_algorithm()
                .unwrap_or_default()
                .to_lowercase()
                .contains(&q)
    }
}

#[derive(Debug, Clone)]
pub struct ServiceRow {
    pub service: Service,
}

impl ServiceRow {
    pub fn name_display(&self) -> &str {
        self.service.name.as_deref().unwrap_or("-")
    }

    pub fn endpoints_display(&self) -> String {
        self.service
            .endpoints
            .as_ref()
            .map(|eps| eps.join(", "))
            .unwrap_or_else(|| "-".to_string())
    }

    #[allow(dead_code)]
    pub fn authenticated_display(&self) -> &str {
        match self.service.authenticated {
            Some(true) => "yes",
            Some(false) => "no",
            None => "-",
        }
    }

    pub fn description_display(&self) -> &str {
        self.service.description.as_deref().unwrap_or("-")
    }

    pub fn bom_ref_display(&self) -> &str {
        self.service.bom_ref.as_deref().unwrap_or("-")
    }
}

#[derive(Debug, Clone)]
pub struct BomStore {
    pub bom_files: Vec<BomFile>,
    pub components: Vec<ComponentRow>,
    pub crypto_assets: Vec<usize>,
    pub services: Vec<ServiceRow>,
    pub filtered_component_indices: Vec<usize>,
    pub filtered_service_indices: Vec<usize>,
    pub current_filter: FilterState,
    pub sort_field: SortField,
    pub sort_order: SortOrder,
    pub total_components: usize,
    pub total_services: usize,
    pub total_crypto: usize,
    pub total_formulas: usize,
    pub total_dependencies: usize,
    pub total_vulnerabilities: usize,
    pub loaded: bool,
}

impl BomStore {
    pub fn new() -> Self {
        Self {
            bom_files: Vec::new(),
            components: Vec::new(),
            crypto_assets: Vec::new(),
            services: Vec::new(),
            filtered_component_indices: Vec::new(),
            filtered_service_indices: Vec::new(),
            current_filter: FilterState::default(),
            sort_field: SortField::Name,
            sort_order: SortOrder::Ascending,
            total_components: 0,
            total_services: 0,
            total_crypto: 0,
            total_formulas: 0,
            total_dependencies: 0,
            total_vulnerabilities: 0,
            loaded: false,
        }
    }

    pub fn load_path(&mut self, path: &Path) -> Result<usize, LoadError> {
        if path.is_dir() {
            let count = self.load_directory(path)?;
            self.merge_duplicates();
            Ok(count)
        } else if path.is_file() {
            let n = self.load_file(path)?;
            self.merge_duplicates();
            Ok(n)
        } else {
            Err(LoadError::NotFound(path.to_path_buf()))
        }
    }

    fn load_file(&mut self, path: &Path) -> Result<usize, LoadError> {
        let content = fs::read_to_string(path).map_err(|e| LoadError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        let bom: Bom = serde_json::from_str(&content).map_err(|e| LoadError::Parse {
            path: path.to_path_buf(),
            source: e,
        })?;

        let path_str = path.to_string_lossy().to_string();
        let bom_file = BomFile {
            bom,
            path: path_str,
        };
        self.index_bom(&bom_file);
        self.bom_files.push(bom_file);
        self.rebuild_filtered_indices();
        self.loaded = true;
        Ok(1)
    }

    fn load_directory(&mut self, dir: &Path) -> Result<usize, LoadError> {
        let mut count = 0;
        let entries = fs::read_dir(dir).map_err(|e| LoadError::Io {
            path: dir.to_path_buf(),
            source: e,
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| LoadError::Io {
                path: dir.to_path_buf(),
                source: e,
            })?;
            let path = entry.path();
            if path.is_file() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name.ends_with(".cdx.json") || name.ends_with(".cdx") || name == "bom.json" {
                    if let Err(e) = self.load_file(&path) {
                        eprintln!("Warning: skipping BOM {}: {}", path.display(), e);
                    } else {
                        count += 1;
                    }
                }
            }
        }

        if count == 0 {
            return Err(LoadError::NoBomFiles(dir.to_path_buf()));
        }

        Ok(count)
    }

    fn merge_duplicates(&mut self) {
        if self.bom_files.len() < 2 {
            return;
        }

        let mut seen: HashMap<String, usize> = HashMap::new();
        let mut merged = Vec::new();
        let mut crypto_merged = Vec::new();
        let mut old_to_new: HashMap<usize, usize> = HashMap::new();

        for (i, comp) in self.components.iter().enumerate() {
            let key = comp
                .component
                .purl
                .clone()
                .or_else(|| comp.component.bom_ref.clone())
                .unwrap_or_else(|| {
                    format!(
                        "{}:{}:{}",
                        comp.component.component_type,
                        comp.name_display(),
                        comp.version_display()
                    )
                });

            if let Some(&existing_idx) = seen.get(&key) {
                let existing: &mut ComponentRow = &mut merged[existing_idx];
                merge_component_properties(&mut existing.component, &comp.component);
                old_to_new.insert(i, existing_idx);
            } else {
                let new_idx = merged.len();
                seen.insert(key, new_idx);
                old_to_new.insert(i, new_idx);
                merged.push(comp.clone());
            }
        }

        let old_crypto: Vec<usize> = self.crypto_assets.clone();
        for &old_idx in &old_crypto {
            if let Some(&new_idx) = old_to_new.get(&old_idx)
                && !crypto_merged.contains(&new_idx) {
                    crypto_merged.push(new_idx);
            }
        }

        self.components = merged;
        self.crypto_assets = crypto_merged;
        self.total_components = self.components.len();
        self.total_crypto = self.crypto_assets.len();
        self.rebuild_filtered_indices();
    }

    fn index_bom(&mut self, bom_file: &BomFile) {
        let bom = &bom_file.bom;

        if let Some(ref components) = bom.components {
            for component in components.iter() {
                let row = ComponentRow {
                    component: component.clone(),
                };
                if component.component_type == "cryptographic-asset" {
                    self.crypto_assets.push(self.components.len());
                }
                self.components.push(row);
            }
        }

        if let Some(ref services) = bom.services {
            for service in services.iter() {
                let row = ServiceRow {
                    service: service.clone(),
                };
                self.services.push(row);
            }
        }

        self.total_components = self.components.len();
        self.total_services = self.services.len();
        self.total_crypto = self.crypto_assets.len();
        self.total_formulas = bom.formulation.as_ref().map(|f| f.len()).unwrap_or(0);
        self.total_dependencies = bom.dependencies.as_ref().map(|d| d.len()).unwrap_or(0);
        self.total_vulnerabilities = bom.vulnerabilities.as_ref().map(|v| v.len()).unwrap_or(0);
    }

    pub fn search_components(&mut self, query: &str) {
        self.current_filter.query = query.to_string();
        self.rebuild_filtered_indices();
    }

    fn rebuild_filtered_indices(&mut self) {
        self.filtered_component_indices = self
            .components
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                let query_match = row.matches_query(&self.current_filter.query);
                let type_match = self
                    .current_filter
                    .component_type
                    .as_ref()
                    .map(|t| row.component.component_type == *t)
                    .unwrap_or(true);
                query_match && type_match
            })
            .map(|(i, _)| i)
            .collect();

        self.filtered_service_indices = self
            .services
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                let q = &self.current_filter.query;
                if q.is_empty() {
                    return true;
                }
                let ql = q.to_lowercase();
                row.name_display().to_lowercase().contains(&ql)
                    || row.endpoints_display().to_lowercase().contains(&ql)
                    || row.description_display().to_lowercase().contains(&ql)
                    || row.bom_ref_display().to_lowercase().contains(&ql)
            })
            .map(|(i, _)| i)
            .collect();

        self.sort_filtered();
    }

    pub fn sort_filtered(&mut self) {
        match self.sort_field {
            SortField::Name => {
                self.filtered_component_indices.sort_by(|a, b| {
                    let cmp = self.components[*a]
                        .name_display()
                        .to_lowercase()
                        .cmp(&self.components[*b].name_display().to_lowercase());
                    match self.sort_order {
                        SortOrder::Ascending => cmp,
                        SortOrder::Descending => cmp.reverse(),
                    }
                });
            }
            SortField::Type => {
                self.filtered_component_indices.sort_by(|a, b| {
                    let cmp = self.components[*a]
                        .type_display()
                        .to_lowercase()
                        .cmp(&self.components[*b].type_display().to_lowercase());
                    match self.sort_order {
                        SortOrder::Ascending => cmp,
                        SortOrder::Descending => cmp.reverse(),
                    }
                });
            }
            SortField::Version => {
                self.filtered_component_indices.sort_by(|a, b| {
                    let cmp = self.components[*a]
                        .version_display()
                        .to_lowercase()
                        .cmp(&self.components[*b].version_display().to_lowercase());
                    match self.sort_order {
                        SortOrder::Ascending => cmp,
                        SortOrder::Descending => cmp.reverse(),
                    }
                });
            }
            SortField::Purl => {
                self.filtered_component_indices.sort_by(|a, b| {
                    let cmp = self.components[*a]
                        .purl_display()
                        .to_lowercase()
                        .cmp(&self.components[*b].purl_display().to_lowercase());
                    match self.sort_order {
                        SortOrder::Ascending => cmp,
                        SortOrder::Descending => cmp.reverse(),
                    }
                });
            }
            SortField::License => {
                self.filtered_component_indices.sort_by(|a, b| {
                    let cmp = self.components[*a]
                        .license_display()
                        .to_lowercase()
                        .cmp(&self.components[*b].license_display().to_lowercase());
                    match self.sort_order {
                        SortOrder::Ascending => cmp,
                        SortOrder::Descending => cmp.reverse(),
                    }
                });
            }
        }
    }

    #[allow(dead_code)]
    pub fn cycle_sort(&mut self) {
        self.sort_field = match self.sort_field {
            SortField::Type => SortField::Name,
            SortField::Name => SortField::Version,
            SortField::Version => SortField::Purl,
            SortField::Purl => SortField::License,
            SortField::License => SortField::Type,
        };
        if matches!(self.sort_field, SortField::Type) {
            self.sort_order = self.sort_order.toggle();
        }
        self.sort_filtered();
    }

    #[allow(dead_code)]
    pub fn set_sort(&mut self, field: SortField) {
        if self.sort_field == field {
            self.sort_order = self.sort_order.toggle();
        } else {
            self.sort_field = field;
            self.sort_order = SortOrder::Ascending;
        }
        self.sort_filtered();
    }

    #[allow(dead_code)]
    pub fn filtered_component(&self, idx: usize) -> Option<&ComponentRow> {
        self.filtered_component_indices
            .get(idx)
            .and_then(|&i| self.components.get(i))
    }

    #[allow(dead_code)]
    pub fn filtered_service(&self, idx: usize) -> Option<&ServiceRow> {
        self.filtered_service_indices
            .get(idx)
            .and_then(|&i| self.services.get(i))
    }

    pub fn filtered_components_count(&self) -> usize {
        self.filtered_component_indices.len()
    }

    #[allow(dead_code)]
    pub fn filtered_services_count(&self) -> usize {
        self.filtered_service_indices.len()
    }

    #[allow(dead_code)]
    pub fn formula_count(&self) -> usize {
        self.bom_files
            .iter()
            .flat_map(|bf| bf.bom.formulation.as_ref())
            .map(|f| f.len())
            .sum()
    }

    #[allow(dead_code)]
    pub fn component_type_counts(&self) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for row in &self.components {
            *counts
                .entry(row.component.component_type.clone())
                .or_insert(0) += 1;
        }
        let mut result: Vec<(String, usize)> = counts.into_iter().collect();
        result.sort_by_key(|b| std::cmp::Reverse(b.1));
        result
    }

    pub fn set_type_filter(&mut self, component_type: Option<String>) {
        self.current_filter.component_type = component_type;
        self.rebuild_filtered_indices();
    }

    #[allow(dead_code)]
    pub fn resolve_ref(&self, ref_field: &str) -> String {
        for row in &self.components {
            if row.component.bom_ref.as_deref() == Some(ref_field) {
                return format!("{} {}", row.name_display(), row.version_display());
            }
        }
        for row in &self.services {
            if row.service.bom_ref.as_deref() == Some(ref_field) {
                return row.name_display().to_string();
            }
        }
        if ref_field.len() > 80 {
            format!("{}…", &ref_field[..77])
        } else {
            ref_field.to_string()
        }
    }

    #[allow(dead_code)]
    pub fn dependency_roots(&self) -> Vec<String> {
        let mut roots = Vec::new();
        let dep_children: std::collections::HashSet<String> = self
            .bom_files
            .iter()
            .flat_map(|bf| bf.bom.dependencies.as_deref().unwrap_or_default())
            .flat_map(|d| d.depends_on.as_deref().unwrap_or_default())
            .cloned()
            .collect();

        for bf in &self.bom_files {
            if let Some(ref deps) = bf.bom.dependencies {
                for d in deps {
                    if !dep_children.contains(&d.ref_field) {
                        roots.push(d.ref_field.clone());
                    }
                }
            }
        }
        roots
    }

    #[allow(dead_code)]
    pub fn dependency_children(&self, ref_field: &str) -> Vec<String> {
        for bf in &self.bom_files {
            if let Some(ref deps) = bf.bom.dependencies {
                for d in deps {
                    if d.ref_field == ref_field {
                        return d.depends_on.clone().unwrap_or_default();
                    }
                }
            }
        }
        Vec::new()
    }

    #[allow(dead_code)]
    pub fn all_dependencies(&self) -> Vec<&Dependency> {
        self.bom_files
            .iter()
            .flat_map(|bf| bf.bom.dependencies.as_deref().unwrap_or_default())
            .collect()
    }

    #[allow(dead_code)]
    pub fn get_component_by_ref(&self, ref_field: &str) -> Option<(usize, &ComponentRow)> {
        self.components
            .iter()
            .enumerate()
            .find(|(_, row)| row.component.bom_ref.as_deref() == Some(ref_field))
    }

    #[allow(dead_code)]
    pub fn file_count(&self) -> usize {
        self.bom_files.len()
    }

    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        parts.push(format!("components: {}", self.total_components));
        parts.push(format!("dependencies: {}", self.total_dependencies));
        parts.push(format!("services: {}", self.total_services));
        parts.push(format!("files: {}", self.bom_files.len()));

        let mut type_counts: HashMap<String, usize> = HashMap::new();
        for row in &self.components {
            *type_counts
                .entry(row.component.component_type.clone())
                .or_insert(0) += 1;
        }
        let mut type_list: Vec<String> = type_counts
            .into_iter()
            .map(|(t, c)| format!("{}: {}", t, c))
            .collect();
        type_list.sort();
        parts.push(format!("types: [{}]", type_list.join(", ")));

        if self.total_vulnerabilities > 0 {
            parts.push(format!("vulnerabilities: {}", self.total_vulnerabilities));
        }

        parts.join(" · ")
    }

    #[allow(dead_code)]
    pub fn dependency_tree(&self, ref_field: &str) -> Vec<(String, u32)> {
        let mut result = Vec::new();
        let mut stack = vec![(ref_field.to_string(), 0u32)];
        let mut seen = std::collections::HashSet::new();
        while let Some((current_ref, depth)) = stack.pop() {
            if !seen.insert(current_ref.clone()) {
                continue;
            }
            result.push((current_ref.clone(), depth));
            for child in self.dependency_children(&current_ref) {
                stack.push((child, depth + 1));
            }
        }
        result
    }
}

impl Default for BomStore {
    fn default() -> Self {
        Self::new()
    }
}

fn merge_component_properties(existing: &mut Component, duplicate: &Component) {
    if let Some(ref dup_props) = duplicate.properties {
        let existing_props = existing.properties.get_or_insert_with(Vec::new);
        for prop in dup_props {
            let is_new = !existing_props.iter().any(|p| {
                p.name == prop.name && p.value == prop.value
            });
            if is_new {
                existing_props.push(prop.clone());
            }
        }
    }

    if let Some(ref dup_ev) = duplicate.evidence {
        if existing.evidence.is_none() && !is_evidence_empty(dup_ev) {
            existing.evidence = Some(dup_ev.clone());
        } else if let Some(ref existing_ev) = existing.evidence {
            let mut merged_ev = existing_ev.clone();
            if let Some(ref ids) = dup_ev.identity {
                let eids = merged_ev.identity.get_or_insert_with(Vec::new);
                for id in ids {
                    if !eids.iter().any(|e| e.name == id.name) {
                        eids.push(id.clone());
                    }
                }
            }
            if let Some(ref occs) = dup_ev.occurrences {
                let eoccs = merged_ev.occurrences.get_or_insert_with(Vec::new);
                for occ in occs {
                    if !eoccs.iter().any(|e| e.location == occ.location) {
                        eoccs.push(occ.clone());
                    }
                }
            }
            existing.evidence = Some(merged_ev);
        }
    }

    if let Some(ref dup_hashes) = duplicate.hashes {
        let existing_hashes = existing.hashes.get_or_insert_with(Vec::new);
        for h in dup_hashes {
            let is_new = !existing_hashes.iter().any(|eh| {
                eh.alg == h.alg && eh.content == h.content
            });
            if is_new {
                existing_hashes.push(h.clone());
            }
        }
    }

    if let Some(ref dup_refs) = duplicate.external_references {
        let existing_refs = existing.external_references.get_or_insert_with(Vec::new);
        for eref in dup_refs {
            let is_new = !existing_refs.iter().any(|e| e.url == eref.url);
            if is_new {
                existing_refs.push(eref.clone());
            }
        }
    }

    if let Some(ref dup_licenses) = duplicate.licenses {
        let existing_licenses = existing.licenses.get_or_insert_with(Vec::new);
        for lic in dup_licenses {
            let is_new = !existing_licenses.iter().any(|el| {
                el.expression == lic.expression
                    && el.license.as_ref().and_then(|l| l.id.as_deref())
                        == lic.license.as_ref().and_then(|l| l.id.as_deref())
            });
            if is_new {
                existing_licenses.push(lic.clone());
            }
        }
    }
}

fn is_evidence_empty(ev: &ComponentEvidence) -> bool {
    ev.identity.as_ref().is_none_or(|v| v.is_empty())
        && ev.occurrences.as_ref().is_none_or(|v| v.is_empty())
        && ev.licenses.as_ref().is_none_or(|v| v.is_empty())
        && ev.copyright.as_ref().is_none_or(|v| v.is_empty())
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("path not found: {0}")]
    NotFound(PathBuf),

    #[error("no BOM files found in directory: {0}")]
    NoBomFiles(PathBuf),

    #[error("I/O error reading {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("JSON parse error in {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn sample_bom_json() -> &'static str {
        r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "serialNumber": "urn:uuid:test-123",
            "version": 1,
            "metadata": {
                "timestamp": "2025-01-01T00:00:00Z",
                "component": {
                    "type": "application",
                    "name": "test-app",
                    "version": "1.0.0"
                }
            },
            "components": [
                {
                    "type": "library",
                    "bom-ref": "pkg:npm/express@4.18.0",
                    "name": "express",
                    "version": "4.18.0",
                    "purl": "pkg:npm/express@4.18.0",
                    "licenses": [{"license": {"id": "MIT"}}]
                },
                {
                    "type": "cryptographic-asset",
                    "bom-ref": "crypto:openssl-aes",
                    "name": "AES-256-GCM",
                    "version": "1.0",
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {
                            "primitive": "AES",
                            "mode": "GCM",
                            "cryptoFunctions": ["encrypt", "decrypt"]
                        }
                    }
                },
                {
                    "type": "framework",
                    "bom-ref": "pkg:pip/django@5.0.0",
                    "name": "django",
                    "group": "django",
                    "version": "5.0.0",
                    "purl": "pkg:pip/django@5.0.0"
                }
            ],
            "services": [
                {
                    "bom-ref": "svc:api",
                    "name": "api-gateway",
                    "endpoints": ["https://api.example.com"],
                    "authenticated": true,
                    "description": "API Gateway service"
                }
            ],
            "dependencies": [
                {"ref": "pkg:npm/express@4.18.0", "dependsOn": []},
                {"ref": "crypto:openssl-aes", "dependsOn": ["pkg:npm/express@4.18.0"]}
            ],
            "formulation": [
                {
                    "name": "build-pipeline",
                    "description": "CI/CD build pipeline",
                    "workflows": [
                        {
                            "uid": "wf-1",
                            "name": "build-and-test",
                            "tasks": [
                                {
                                    "uid": "task-1",
                                    "name": "compile",
                                    "steps": [
                                        {
                                            "name": "cargo build",
                                            "commands": [{"executed": "cargo build --release"}]
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#
    }

    #[test]
    fn test_load_bom_from_file() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        let count = store.load_path(tmp.path()).unwrap();
        assert_eq!(count, 1);
        assert!(store.loaded);

        assert_eq!(store.total_components, 3);
        assert_eq!(store.total_services, 1);
        assert_eq!(store.total_crypto, 1);
        assert_eq!(store.total_formulas, 1);
        assert_eq!(store.total_dependencies, 2);
    }

    #[test]
    fn test_search_components() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        store.search_components("express");
        assert_eq!(store.filtered_components_count(), 1);

        store.search_components("aes");
        assert_eq!(store.filtered_components_count(), 1);

        store.search_components("");
        assert_eq!(store.filtered_components_count(), 3);
    }

    #[test]
    fn test_filter_by_type() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        store.set_type_filter(Some("library".to_string()));
        assert_eq!(store.filtered_components_count(), 1);

        store.set_type_filter(Some("cryptographic-asset".to_string()));
        assert_eq!(store.filtered_components_count(), 1);

        store.set_type_filter(None);
        assert_eq!(store.filtered_components_count(), 3);
    }

    #[test]
    fn test_sort_components() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        store.sort_field = SortField::Name;
        store.sort_order = SortOrder::Ascending;
        store.sort_filtered();

        let names: Vec<&str> = (0..store.filtered_components_count())
            .filter_map(|i| store.filtered_component(i).map(|r| r.name_display()))
            .collect();
        assert_eq!(names, vec!["AES-256-GCM", "django", "express"]);
    }

    #[test]
    fn test_load_nonexistent_file() {
        let mut store = BomStore::new();
        let result = store.load_path(Path::new("/nonexistent/path/bom.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_component_type_counts() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        let counts = store.component_type_counts();
        let library_count = counts
            .iter()
            .find(|(t, _)| t == "library")
            .map(|(_, c)| *c)
            .unwrap_or(0);
        assert_eq!(library_count, 1);
    }

    #[test]
    fn test_crypto_asset_detection() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        assert_eq!(store.total_crypto, 1);
        assert_eq!(store.crypto_assets.len(), 1);

        let crypto_row = &store.components[store.crypto_assets[0]];
        assert_eq!(
            crypto_row.component.crypto_properties.as_ref().and_then(|cp| cp.asset_type.clone()),
            Some("algorithm".to_string())
        );
        assert_eq!(crypto_row.crypto_algorithm().unwrap(), "AES");
    }

    #[test]
    fn test_load_directory() {
        let dir = tempfile::tempdir().unwrap();
        let bom_path = dir.path().join("sbom-test-build.cdx.json");
        std::fs::write(&bom_path, sample_bom_json()).unwrap();
        std::fs::write(dir.path().join("readme.txt"), "not a bom").unwrap();

        let mut store = BomStore::new();
        let count = store.load_path(dir.path()).unwrap();
        assert_eq!(count, 1);
        assert_eq!(store.total_components, 3);
    }

    #[test]
    fn test_load_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = BomStore::new();
        let result = store.load_path(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_cycle_sort() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        assert_eq!(store.sort_field, SortField::Name);
        store.cycle_sort();
        assert_eq!(store.sort_field, SortField::Version);
        store.cycle_sort();
        assert_eq!(store.sort_field, SortField::Purl);
        store.cycle_sort();
        assert_eq!(store.sort_field, SortField::License);
        store.cycle_sort();
        assert_eq!(store.sort_field, SortField::Type);
        store.cycle_sort();
        assert_eq!(store.sort_field, SortField::Name);
    }

    #[test]
    fn test_dependency_roots_and_children() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        let roots = store.dependency_roots();
        assert!(!roots.is_empty());
        let crypto_root = roots.iter().find(|r| r.contains("crypto:openssl-aes"));
        assert!(crypto_root.is_some());

        let children = store.dependency_children("crypto:openssl-aes");
        assert!(!children.is_empty());
        assert!(children.contains(&"pkg:npm/express@4.18.0".to_string()));
    }

    #[test]
    fn test_resolve_ref() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        let resolved = store.resolve_ref("pkg:npm/express@4.18.0");
        assert!(resolved.contains("express"));
        assert!(resolved.contains("4.18.0"));

        let resolved = store.resolve_ref("svc:api");
        assert!(resolved.contains("api-gateway"));
    }

    #[test]
    fn test_summary() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        let s = store.summary();
        assert!(s.contains("components: 3"));
        assert!(s.contains("dependencies: 2"));
    }

    #[test]
    fn test_set_type_filter() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        store.set_type_filter(Some("library".to_string()));
        assert_eq!(store.filtered_components_count(), 1);

        store.set_type_filter(Some("framework".to_string()));
        assert_eq!(store.filtered_components_count(), 1);

        store.set_type_filter(None);
        assert_eq!(store.filtered_components_count(), 3);
    }

    #[test]
    fn test_get_component_by_ref() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        let (_idx, row) = store.get_component_by_ref("pkg:npm/express@4.18.0").unwrap();
        assert_eq!(row.name_display(), "express");

        assert!(store.get_component_by_ref("nonexistent").is_none());
    }

    #[test]
    fn test_merge_duplicate_components() {
        let json_a = r#"{
            "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
            "components": [
                {"type": "library", "name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0", "licenses": [{"license": {"id": "MIT"}}], "properties": [{"name": "SrcFile", "value": "file-a.lock"}]},
                {"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}
            ]
        }"#;
        let json_b = r#"{
            "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
            "components": [
                {"type": "library", "name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0", "licenses": [{"license": {"id": "Apache-2.0"}}], "properties": [{"name": "SrcFile", "value": "file-b.lock"}, {"name": "Namespaces", "value": "test"}], "hashes": [{"alg": "SHA-256", "content": "abc"}]},
                {"type": "container", "name": "alpine", "version": "3.19", "purl": "pkg:docker/alpine@3.19"}
            ]
        }"#;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.cdx.json"), json_a).unwrap();
        std::fs::write(dir.path().join("b.cdx.json"), json_b).unwrap();

        let mut store = BomStore::new();
        store.load_path(dir.path()).unwrap();

        assert_eq!(store.total_components, 3, "express should be merged");

        let express = store.components.iter().find(|r| r.name_display() == "express").unwrap();
        let props = express.component.properties.as_ref().unwrap();
        assert_eq!(props.len(), 3, "3 unique properties after merge");
        let lic = express.component.licenses.as_ref().unwrap();
        assert_eq!(lic.len(), 2, "2 licenses after merge");
        let hashes = express.component.hashes.as_ref().unwrap();
        assert_eq!(hashes.len(), 1, "hashes merged");
    }

    #[test]
    fn test_matches_query_case_insensitive() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        store.search_components("EXPRESS");
        assert_eq!(store.filtered_components_count(), 1);

        store.search_components("LIBRARY");
        assert_eq!(store.filtered_components_count(), 1);
    }

    #[test]
    fn test_dependency_tree() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(sample_bom_json().as_bytes()).unwrap();

        let mut store = BomStore::new();
        store.load_path(tmp.path()).unwrap();

        let tree = store.dependency_tree("crypto:openssl-aes");
        assert!(tree.iter().any(|(r, _)| r == "pkg:npm/express@4.18.0"));
    }
}
