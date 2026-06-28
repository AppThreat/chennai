use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bom {
    #[serde(rename = "bomFormat")]
    pub bom_format: Option<String>,

    #[serde(rename = "specVersion")]
    pub spec_version: Option<String>,

    #[serde(rename = "serialNumber")]
    pub serial_number: Option<String>,

    pub version: Option<i32>,
    pub metadata: Option<Metadata>,
    pub components: Option<Vec<Component>>,
    pub services: Option<Vec<Service>>,
    pub dependencies: Option<Vec<Dependency>>,
    pub formulation: Option<Vec<Formula>>,
    pub compositions: Option<Vec<Composition>>,
    pub annotations: Option<Vec<Annotation>>,
    pub vulnerabilities: Option<Vec<Vulnerability>>,
    pub definitions: Option<Definitions>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub timestamp: Option<String>,
    pub tools: Option<Tools>,
    pub authors: Option<Vec<OrganizationalContact>>,
    pub component: Option<Component>,
    pub manufacture: Option<OrganizationalEntity>,
    pub supplier: Option<OrganizationalEntity>,
    pub licenses: Option<Vec<LicenseChoice>>,
    pub properties: Option<Vec<Property>>,
    pub lifecycles: Option<Vec<Lifecycle>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tools {
    pub components: Option<Vec<Component>>,
    pub services: Option<Vec<Service>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Component {
    #[serde(rename = "type")]
    pub component_type: String,

    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,

    pub name: Option<String>,
    pub group: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub scope: Option<String>,
    pub purl: Option<String>,
    pub licenses: Option<Vec<LicenseChoice>>,
    pub hashes: Option<Vec<Hash>>,
    pub evidence: Option<ComponentEvidence>,
    pub properties: Option<Vec<Property>>,
    pub components: Option<Vec<Component>>,

    #[serde(rename = "cryptoProperties")]
    pub crypto_properties: Option<CryptoProperties>,

    pub data: Option<Vec<ComponentData>>,
    pub pedigree: Option<Pedigree>,
    pub copyright: Option<String>,
    pub publisher: Option<String>,

    #[serde(rename = "externalReferences")]
    pub external_references: Option<Vec<ExternalReference>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoProperties {
    #[serde(rename = "assetType")]
    pub asset_type: Option<String>,

    #[serde(rename = "algorithmProperties")]
    pub algorithm_properties: Option<AlgorithmProperties>,

    #[serde(rename = "certificateProperties")]
    pub certificate_properties: Option<CertificateProperties>,

    pub oid: Option<String>,

    #[serde(rename = "relatedCryptoMaterialProperties")]
    pub related_crypto_material_properties: Option<Vec<RelatedCryptoMaterialProperties>>,

    #[serde(rename = "executionEnvironment")]
    pub execution_environment: Option<String>,

    #[serde(rename = "implementationPlatform")]
    pub implementation_platform: Option<String>,

    #[serde(rename = "certificationLevel")]
    pub certification_level: Option<Vec<String>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmProperties {
    #[serde(rename = "primitive")]
    pub primitive: Option<String>,

    #[serde(rename = "parameterSetIdentifier")]
    pub parameter_set_identifier: Option<String>,

    #[serde(rename = "curve")]
    pub curve: Option<String>,

    #[serde(rename = "executionEnvironment")]
    pub execution_environment: Option<String>,

    #[serde(rename = "implementationPlatform")]
    pub implementation_platform: Option<String>,

    #[serde(rename = "certificationLevel")]
    pub certification_level: Option<Vec<String>>,

    #[serde(rename = "mode")]
    pub mode: Option<String>,

    #[serde(rename = "padding")]
    pub padding: Option<String>,

    #[serde(rename = "cryptoFunctions")]
    pub crypto_functions: Option<Vec<String>>,

    #[serde(rename = "classicalSecurityLevel")]
    pub classical_security_level: Option<i32>,

    #[serde(rename = "nistQuantumSecurityLevel")]
    pub nist_quantum_security_level: Option<i32>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateProperties {
    #[serde(rename = "subjectName")]
    pub subject_name: Option<String>,

    #[serde(rename = "issuerName")]
    pub issuer_name: Option<String>,

    #[serde(rename = "notValidBefore")]
    pub not_valid_before: Option<String>,

    #[serde(rename = "notValidAfter")]
    pub not_valid_after: Option<String>,

    #[serde(rename = "signatureAlgorithmRef")]
    pub signature_algorithm_ref: Option<String>,

    #[serde(rename = "subjectPublicKeyRef")]
    pub subject_public_key_ref: Option<String>,

    #[serde(rename = "certificateFormat")]
    pub certificate_format: Option<String>,

    #[serde(rename = "certificateExtension")]
    pub certificate_extension: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedCryptoMaterialProperties {
    #[serde(rename = "type")]
    pub related_type: Option<String>,

    pub id: Option<String>,
    pub description: Option<String>,

    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,

    #[serde(rename = "validityPeriodStart")]
    pub validity_period_start: Option<String>,

    #[serde(rename = "validityPeriodEnd")]
    pub validity_period_end: Option<String>,

    pub state: Option<String>,
    pub algorithm: Option<String>,
    pub strength: Option<i32>,

    #[serde(rename = "relatedCryptoMaterialSize")]
    pub size: Option<i32>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,

    pub provider: Option<OrganizationalEntity>,
    pub group: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub endpoints: Option<Vec<String>>,

    pub authenticated: Option<bool>,

    #[serde(rename = "x-trust-boundary")]
    pub x_trust_boundary: Option<bool>,

    pub data: Option<Vec<ServiceData>>,
    pub licenses: Option<Vec<LicenseChoice>>,
    pub services: Option<Vec<Service>>,
    pub properties: Option<Vec<Property>>,

    #[serde(rename = "externalReferences")]
    pub external_references: Option<Vec<ExternalReference>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceData {
    pub classification: Option<String>,
    pub flow: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    #[serde(rename = "ref")]
    pub ref_field: String,

    #[serde(rename = "dependsOn")]
    pub depends_on: Option<Vec<String>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Formula {
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,

    pub name: Option<String>,
    pub description: Option<String>,
    pub components: Option<Vec<Component>>,
    pub services: Option<Vec<Service>>,
    pub workflows: Option<Vec<Workflow>>,
    pub tasks: Option<Vec<Task>>,
    pub properties: Option<Vec<Property>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,

    pub uid: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub tasks: Option<Vec<Task>>,

    #[serde(rename = "taskDependencies")]
    pub task_dependencies: Option<Vec<TaskDependency>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,

    pub uid: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub inputs: Option<Vec<InputOutput>>,
    pub outputs: Option<Vec<InputOutput>>,
    pub steps: Option<Vec<Step>>,
    pub properties: Option<Vec<Property>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskDependency {
    #[serde(rename = "ref")]
    pub ref_field: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub name: Option<String>,
    pub description: Option<String>,
    pub commands: Option<Vec<Command>>,
    pub properties: Option<Vec<Property>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub executed: Option<String>,
    pub properties: Option<Vec<Property>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputOutput {
    #[serde(rename = "type")]
    pub io_type: Option<String>,

    pub resource: Option<ResourceReferenceChoice>,
    pub properties: Option<Vec<Property>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Composition {
    pub aggregate: Option<String>,

    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,

    pub assemblies: Option<Vec<String>>,
    pub dependencies: Option<Vec<String>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,

    pub subjects: Option<Vec<String>>,
    pub text: Option<String>,

    #[serde(rename = "annotator")]
    pub annotator: Option<OrganizationalEntity>,

    pub timestamp: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,

    pub id: Option<String>,
    pub description: Option<String>,
    pub detail: Option<String>,
    pub recommendation: Option<String>,
    pub advisories: Option<Vec<Advisory>>,
    pub ratings: Option<Vec<Rating>>,
    pub affects: Option<Vec<Affect>>,
    pub properties: Option<Vec<Property>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    pub title: Option<String>,
    pub url: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rating {
    pub source: Option<RatingSource>,
    pub score: Option<f64>,
    pub severity: Option<String>,
    pub method: Option<String>,
    pub vector: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatingSource {
    pub name: Option<String>,
    pub url: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Affect {
    #[serde(rename = "ref")]
    pub ref_field: String,

    pub versions: Option<Vec<AffectedVersion>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedVersion {
    pub version: Option<String>,
    pub range: Option<String>,
    pub status: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Definitions {
    pub standards: Option<Vec<Standard>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Standard {
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,

    pub name: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub owner: Option<String>,
    pub requirements: Option<Vec<Requirement>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Requirement {
    #[serde(rename = "bom-ref")]
    pub bom_ref: Option<String>,

    pub identifier: Option<String>,
    pub title: Option<String>,
    pub text: Option<String>,
    pub description: Option<String>,

    #[serde(rename = "openCre")]
    pub open_cre: Option<Vec<String>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentEvidence {
    pub licenses: Option<Vec<LicenseChoice>>,
    pub copyright: Option<Vec<Copyright>>,
    #[serde(default, deserialize_with = "deserialize_identity")]
    pub identity: Option<Vec<ComponentIdentityEvidence>>,
    pub occurrences: Option<Vec<Occurrence>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentIdentityEvidence {
    pub field: Option<String>,
    pub confidence: Option<f64>,
    #[serde(rename = "concludedValue")]
    pub concluded_value: Option<String>,
    pub methods: Option<Vec<IdentityMethod>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityMethod {
    pub technique: Option<String>,
    pub confidence: Option<f64>,
    pub value: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

fn deserialize_identity<'de, D>(deserializer: D) -> Result<Option<Vec<ComponentIdentityEvidence>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let v: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    match v {
        None => Ok(None),
        Some(serde_json::Value::Array(arr)) => {
            let ids: Vec<ComponentIdentityEvidence> = serde_json::from_value(serde_json::Value::Array(arr))
                .map_err(D::Error::custom)?;
            Ok(Some(ids))
        }
        Some(obj) => {
            let id: ComponentIdentityEvidence = serde_json::from_value(obj)
                .map_err(D::Error::custom)?;
            Ok(Some(vec![id]))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Copyright {
    pub text: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Occurrence {
    pub location: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pedigree {
    pub ancestors: Option<Vec<Component>>,
    pub descendants: Option<Vec<Component>>,
    pub variants: Option<Vec<Component>>,
    pub commits: Option<Vec<Commit>>,
    pub patches: Option<Vec<Patch>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    pub uid: Option<String>,
    pub url: Option<String>,
    pub author: Option<OrganizationalContact>,
    pub message: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patch {
    #[serde(rename = "type")]
    pub patch_type: Option<String>,

    pub diff: Option<String>,
    pub resolves: Option<Vec<Issue>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    #[serde(rename = "type")]
    pub issue_type: Option<String>,

    pub id: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentData {
    pub name: Option<String>,
    pub contents: Option<String>,
    pub classification: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseChoice {
    pub license: Option<License>,
    pub expression: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub id: Option<String>,
    pub name: Option<String>,
    pub url: Option<String>,
    pub text: Option<Attachment>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    #[serde(rename = "contentType")]
    pub content_type: Option<String>,

    pub encoding: Option<String>,
    pub content: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hash {
    pub alg: Option<String>,
    pub content: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalReference {
    #[serde(rename = "type")]
    pub ref_type: Option<String>,

    pub url: Option<String>,
    pub comment: Option<String>,
    pub hashes: Option<Vec<Hash>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Property {
    pub name: Option<String>,
    pub value: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationalEntity {
    pub name: Option<String>,
    pub url: Option<Vec<String>>,
    pub contact: Option<Vec<OrganizationalContact>>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationalContact {
    pub name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lifecycle {
    pub phase: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceReferenceChoice {
    #[serde(rename = "ref")]
    pub ref_field: Option<String>,

    #[serde(rename = "externalReference")]
    pub external_reference: Option<ExternalReference>,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cyclonedx_bom() {
        let json = r#"{
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
                    "licenses": [{"license": {"id": "MIT"}}],
                    "properties": [{"name": "SrcFile", "value": "package.json"}]
                },
                {
                    "type": "framework",
                    "bom-ref": "pkg:pip/django@5.0.0",
                    "name": "django",
                    "group": "django",
                    "version": "5.0.0",
                    "purl": "pkg:pip/django@5.0.0",
                    "description": "A high-level Python web framework"
                }
            ],
            "dependencies": [
                {"ref": "pkg:npm/express@4.18.0", "dependsOn": []},
                {"ref": "pkg:pip/django@5.0.0", "dependsOn": ["pkg:npm/express@4.18.0"]}
            ]
        }"#;

        let bom: Bom = serde_json::from_str(json).unwrap();
        assert_eq!(bom.bom_format.as_deref(), Some("CycloneDX"));
        assert_eq!(bom.spec_version.as_deref(), Some("1.7"));
        assert!(bom.metadata.is_some());

        let components = bom.components.unwrap();
        assert_eq!(components.len(), 2);
        assert_eq!(components[0].name.as_deref(), Some("express"));
        assert_eq!(components[0].purl.as_deref(), Some("pkg:npm/express@4.18.0"));

        let deps = bom.dependencies.unwrap();
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn parse_minimal_bom() {
        let json = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}"#;
        let bom: Bom = serde_json::from_str(json).unwrap();
        assert!(bom.components.is_none());
        assert!(bom.dependencies.is_none());
    }

    #[test]
    fn component_extra_fields_preserved() {
        let json = r#"{"type":"library","name":"test","version":"1.0","customField":"value"}"#;
        let c: Component = serde_json::from_str(json).unwrap();
        assert_eq!(c.extra.get("customField").and_then(|v| v.as_str()), Some("value"));
    }

    #[test]
    fn crypto_asset_detection() {
        let json = r#"{
            "type": "cryptographic-asset",
            "bom-ref": "crypto:aes",
            "name": "AES-256-GCM",
            "version": "1.0",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "AES",
                    "mode": "GCM"
                }
            }
        }"#;
        let c: Component = serde_json::from_str(json).unwrap();
        assert_eq!(c.component_type, "cryptographic-asset");
        let cp = c.crypto_properties.unwrap();
        assert_eq!(cp.asset_type.as_deref(), Some("algorithm"));
        let ap = cp.algorithm_properties.unwrap();
        assert_eq!(ap.primitive.as_deref(), Some("AES"));
    }
}
