use anyhow::{Context, Result, bail};
use cultcache_rs::DatabaseEntry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const GAMECULT_RUNTIME_PRESENCE_HEALTH_SCHEMA: &str = "gamecult.runtime_presence_health.v1";
pub const GAMECULT_RUNTIME_PRESENCE_HEALTH_SIGNING_PURPOSE: &str =
    "gamecult.runtime_presence_health.v1";
pub const IDUNN_RUNTIME_ACTIVATION_SCHEMA: &str = "idunn.runtime_activation.v1";
pub const IDUNN_PROCESS_WRITE_LEASE_SCHEMA: &str = "idunn.process_write_lease.v1";
pub const IDUNN_EXPECTED_INCARNATION_SCHEMA: &str = "idunn.expected_incarnation.v1";
pub const ODIN_RUNTIME_TOPOLOGY_CORRELATION_SCHEMA: &str = "odin.runtime_topology_correlation.v1";
pub const ODIN_RUNTIME_TOPOLOGY_CORRELATION_SIGNING_PURPOSE: &str =
    "odin.runtime_topology_correlation.v1";

const MAX_RUNTIME_CAPABILITIES: usize = 256;
const MAX_RUNTIME_DEPENDENCIES: usize = 256;
const MAX_TOPOLOGY_DISAGREEMENTS: usize = 256;

/// One provider-owned capability claim inside a runtime-presence statement.
/// The enclosing vector is canonical only when these records are strictly
/// increasing by `(capability, schema, compatibility)`. Capacity describes
/// that one claim and does not create a second identity for the same claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GameCultRuntimeCapability {
    pub capability: String,
    pub schema: String,
    pub compatibility: String,
    pub capacity: u32,
}

/// Provider-signed claim from one exact runtime launch. Present authority
/// requires a matching Idunn-published current activation; this record cannot
/// establish admission by itself. The signature covers the canonical
/// positional encoding of this complete record with `signature` empty.
#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(
    type = "gamecult.runtime_presence_health",
    schema = "gamecult.runtime_presence_health.v1"
)]
pub struct GameCultRuntimePresenceHealthRecord {
    #[cultcache(key = 0)]
    pub schema_version: String,
    #[cultcache(key = 1)]
    pub target: String,
    #[cultcache(key = 2)]
    pub expected_projection_sha256: String,
    #[cultcache(key = 3)]
    pub plan_id: String,
    #[cultcache(key = 4)]
    pub incarnation_id: String,
    #[cultcache(key = 5)]
    pub sealed_release_id: String,
    #[cultcache(key = 6)]
    pub activation_witness_sha256: String,
    #[cultcache(key = 7)]
    pub state_schema_generation: Option<String>,
    #[cultcache(key = 8)]
    pub state_contract_sha256: Option<String>,
    #[cultcache(key = 9)]
    pub runtime_id: String,
    #[cultcache(key = 10)]
    pub runtime_instance_id: String,
    #[cultcache(key = 11)]
    pub bound_endpoint: Option<String>,
    #[cultcache(key = 12)]
    pub capabilities: Vec<GameCultRuntimeCapability>,
    #[cultcache(key = 13)]
    pub health_contract: String,
    #[cultcache(key = 14)]
    pub state: String,
    #[cultcache(key = 15)]
    pub detail: String,
    #[cultcache(key = 16)]
    pub write_lease_sha256: Option<String>,
    #[cultcache(key = 17)]
    pub signer_identity_id: String,
    #[cultcache(key = 18)]
    pub publisher_sequence: u64,
    #[cultcache(key = 19)]
    pub observed_at_unix_millis: u64,
    #[cultcache(key = 20)]
    pub signature_algorithm: String,
    #[cultcache(key = 21, bytes)]
    pub signature: Vec<u8>,
}

impl GameCultRuntimePresenceHealthRecord {
    /// Decode one exact current-generation positional record and return the
    /// canonical bytes that its provider signature covers.
    pub fn decode_canonical_signed_payload(payload: &[u8]) -> Result<(Self, Vec<u8>)> {
        if messagepack_array_len(payload) != Some(22) {
            bail!("runtime presence payload is not the 22-field positional contract");
        }
        let statement: Self =
            rmp_serde::from_slice(payload).context("decoding runtime presence health")?;
        if rmp_serde::to_vec(&statement)? != payload {
            bail!("runtime presence payload is not canonical positional MessagePack");
        }
        statement.validate()?;
        let unsigned = statement.unsigned_signature_payload()?;
        Ok((statement, unsigned))
    }

    /// Return the canonical signature payload. A caller may use this while
    /// constructing a statement with an empty signature or after decoding a
    /// complete signed statement.
    pub fn unsigned_signature_payload(&self) -> Result<Vec<u8>> {
        self.validate_shape(true)?;
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok(rmp_serde::to_vec(&unsigned)?)
    }

    /// Digest the complete signed presence record for an Odin correlation
    /// receipt. An unsigned construction value is deliberately not digestible.
    pub fn canonical_sha256(&self) -> Result<String> {
        self.validate()?;
        Ok(prefixed_sha256(&rmp_serde::to_vec(self)?))
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_shape(false)
    }

    fn validate_shape(&self, allow_unsigned: bool) -> Result<()> {
        if self.schema_version != GAMECULT_RUNTIME_PRESENCE_HEALTH_SCHEMA {
            bail!("runtime presence schema is unsupported");
        }
        validate_authority_identifier(&self.target, "target")?;
        validate_required_sha256(
            &self.expected_projection_sha256,
            "expected projection sha256",
        )?;
        validate_required_sha256(&self.plan_id, "plan id")?;
        validate_authority_identifier(&self.incarnation_id, "incarnation id")?;
        validate_required_sha256(&self.sealed_release_id, "sealed release id")?;
        validate_required_sha256(&self.activation_witness_sha256, "activation witness sha256")?;
        match (&self.state_schema_generation, &self.state_contract_sha256) {
            (Some(generation), Some(contract_sha256)) => {
                validate_authority_identifier(generation, "state schema generation")?;
                validate_required_sha256(contract_sha256, "state contract sha256")?;
            }
            (None, None) => {}
            _ => bail!("runtime presence state lineage is partial"),
        }
        validate_authority_identifier(&self.runtime_id, "runtime id")?;
        validate_required_sha256(&self.runtime_instance_id, "runtime instance id")?;
        validate_optional_endpoint(&self.bound_endpoint)?;
        validate_runtime_capabilities(&self.capabilities)?;
        validate_authority_identifier(&self.health_contract, "health contract")?;
        validate_authority_identifier(&self.signer_identity_id, "signer identity id")?;
        validate_optional_sha256(&self.write_lease_sha256, "write lease sha256")?;

        let signature_is_valid =
            self.signature.len() == 64 || (allow_unsigned && self.signature.is_empty());
        if self.publisher_sequence == 0
            || self.observed_at_unix_millis == 0
            || !matches!(
                self.state.as_str(),
                "warming" | "active" | "degraded" | "failed"
            )
            || self.detail.len() > 512
            || self.detail.chars().any(char::is_control)
            || self.signature_algorithm != "ed25519"
            || !signature_is_valid
        {
            bail!("runtime presence state, sequence, detail, or signature is invalid");
        }
        if self.state == "warming" && self.write_lease_sha256.is_some() {
            bail!("warming runtime presence cannot claim a process write lease");
        }
        if self.state_schema_generation.is_none() && self.write_lease_sha256.is_some() {
            bail!("stateless runtime presence cannot claim a process write lease");
        }
        Ok(())
    }
}

/// Public route facts admitted for one incarnation. These are service-facing
/// endpoints only; actuator paths, unit files, container sockets, and runner
/// credentials do not belong in the Expected projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdunnExpectedRoute {
    pub route_id: String,
    pub transport: String,
    pub stable_endpoint: String,
    pub candidate_endpoint: String,
}

impl IdunnExpectedRoute {
    fn validate(&self) -> Result<()> {
        validate_authority_identifier(&self.route_id, "route id")?;
        validate_endpoint(&self.stable_endpoint, "stable route endpoint")?;
        validate_endpoint(&self.candidate_endpoint, "candidate route endpoint")?;
        if self.stable_endpoint == self.candidate_endpoint {
            bail!("stable and candidate route endpoints are identical");
        }
        match self.transport.as_str() {
            "http" => {
                if !(self.stable_endpoint.starts_with("http://")
                    || self.stable_endpoint.starts_with("https://"))
                    || !self.candidate_endpoint.starts_with("http://")
                {
                    bail!("HTTP route endpoints use an unsupported scheme");
                }
            }
            "tcp" => {
                if !self.stable_endpoint.starts_with("tcp://")
                    || !self.candidate_endpoint.starts_with("tcp://")
                {
                    bail!("TCP route endpoints use an unsupported scheme");
                }
            }
            _ => bail!("route transport is unsupported"),
        }
        Ok(())
    }
}

/// One capability requirement and Idunn's exact admitted provider selection.
/// Provider fields are all absent while unresolved. Managed providers bind an
/// Expected digest; external operator bindings instead bind an endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdunnExpectedDependency {
    pub kind: String,
    pub capability: String,
    pub schema: String,
    pub compatibility: String,
    pub minimum_capacity: u32,
    pub startup: String,
    pub provider_id: Option<String>,
    pub provider_authority: Option<String>,
    pub provider_expected_projection_sha256: Option<String>,
    pub provider_endpoint: Option<String>,
}

impl IdunnExpectedDependency {
    fn identity(&self) -> (&str, &str, &str) {
        (&self.capability, &self.schema, &self.compatibility)
    }

    fn validate(&self) -> Result<()> {
        if !matches!(
            self.kind.as_str(),
            "bootstrap"
                | "required"
                | "optional"
                | "shared-infrastructure"
                | "private"
                | "external-operator-binding"
        ) {
            bail!("dependency kind is unsupported");
        }
        validate_authority_identifier(&self.capability, "dependency capability")?;
        validate_authority_identifier(&self.schema, "dependency schema")?;
        validate_authority_identifier(&self.compatibility, "dependency compatibility")?;
        if self.minimum_capacity == 0
            || !matches!(self.startup.as_str(), "before-start" | "before-promotion")
        {
            bail!("dependency capacity or startup condition is invalid");
        }
        if self.kind == "bootstrap" && self.startup != "before-start" {
            bail!("bootstrap dependency must be satisfied before start");
        }
        validate_optional_identifier(&self.provider_id, "dependency provider id")?;
        validate_optional_identifier(&self.provider_authority, "dependency provider authority")?;
        validate_optional_sha256(
            &self.provider_expected_projection_sha256,
            "dependency provider expected projection sha256",
        )?;
        validate_optional_endpoint_labeled(
            &self.provider_endpoint,
            "dependency provider endpoint",
        )?;

        match (
            &self.provider_id,
            &self.provider_authority,
            &self.provider_expected_projection_sha256,
            &self.provider_endpoint,
        ) {
            (None, None, None, None) => {}
            (Some(_), Some(authority), Some(_), _) if authority == "managed-incarnation" => {
                if self.kind == "external-operator-binding" {
                    bail!("external operator dependency cannot select a managed incarnation");
                }
            }
            (Some(_), Some(authority), None, Some(_))
                if authority == "external-operator-binding"
                    && self.kind == "external-operator-binding" => {}
            _ => bail!("dependency provider binding is partial or authority-incoherent"),
        }
        Ok(())
    }
}

/// Idunn-owned desired deployment identity published into CultMesh before
/// promotion. It describes the admitted incarnation and its public contracts,
/// never the private details needed to execute it on a particular host.
#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(
    type = "idunn.expected_incarnation",
    schema = "idunn.expected_incarnation.v1"
)]
pub struct IdunnExpectedIncarnationRecord {
    #[cultcache(key = 0)]
    pub schema_version: String,
    #[cultcache(key = 1)]
    pub target: String,
    #[cultcache(key = 2)]
    pub plan_id: String,
    #[cultcache(key = 3)]
    pub incarnation_id: String,
    #[cultcache(key = 4)]
    pub sealed_release_id: String,
    #[cultcache(key = 5)]
    pub source_repository: String,
    #[cultcache(key = 6)]
    pub source_revision: String,
    #[cultcache(key = 7)]
    pub recipe_sha256: String,
    #[cultcache(key = 8)]
    pub runtime_id: String,
    #[cultcache(key = 9)]
    pub expected_signer_identity_id: String,
    #[cultcache(key = 10)]
    pub health_contract: String,
    #[cultcache(key = 11)]
    pub artifact_sha256: String,
    #[cultcache(key = 12)]
    pub state_schema_generation: Option<String>,
    #[cultcache(key = 13)]
    pub state_contract_sha256: Option<String>,
    #[cultcache(key = 14)]
    pub write_lease_required: bool,
    #[cultcache(key = 15)]
    pub route: Option<IdunnExpectedRoute>,
    #[cultcache(key = 16)]
    pub capabilities: Vec<GameCultRuntimeCapability>,
    #[cultcache(key = 17)]
    pub dependencies: Vec<IdunnExpectedDependency>,
}

impl IdunnExpectedIncarnationRecord {
    pub fn decode_canonical(payload: &[u8]) -> Result<Self> {
        if messagepack_array_len(payload) != Some(18) {
            bail!("expected incarnation is not the 18-field positional contract");
        }
        let expected: Self =
            rmp_serde::from_slice(payload).context("decoding expected incarnation")?;
        if rmp_serde::to_vec(&expected)? != payload {
            bail!("expected incarnation is not canonical positional MessagePack");
        }
        expected.validate()?;
        Ok(expected)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(rmp_serde::to_vec(self)?)
    }

    pub fn canonical_sha256(&self) -> Result<String> {
        Ok(prefixed_sha256(&self.canonical_bytes()?))
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != IDUNN_EXPECTED_INCARNATION_SCHEMA {
            bail!("expected incarnation schema is unsupported");
        }
        validate_authority_identifier(&self.target, "target")?;
        validate_required_sha256(&self.plan_id, "plan id")?;
        validate_authority_identifier(&self.incarnation_id, "incarnation id")?;
        validate_required_sha256(&self.sealed_release_id, "sealed release id")?;
        validate_source_repository(&self.source_repository)?;
        if !is_lower_hex(&self.source_revision, 40) {
            bail!("source revision is not a lowercase Git object id");
        }
        validate_required_sha256(&self.recipe_sha256, "recipe sha256")?;
        validate_authority_identifier(&self.runtime_id, "runtime id")?;
        validate_authority_identifier(
            &self.expected_signer_identity_id,
            "expected signer identity id",
        )?;
        validate_authority_identifier(&self.health_contract, "health contract")?;
        validate_required_sha256(&self.artifact_sha256, "artifact sha256")?;
        match (&self.state_schema_generation, &self.state_contract_sha256) {
            (Some(generation), Some(contract_sha256)) => {
                validate_authority_identifier(generation, "state schema generation")?;
                validate_required_sha256(contract_sha256, "state contract sha256")?;
            }
            (None, None) => {}
            _ => bail!("expected incarnation state lineage is partial"),
        }
        if self.write_lease_required && self.state_schema_generation.is_none() {
            bail!("stateless incarnation cannot require a process write lease");
        }
        if let Some(route) = &self.route {
            route.validate()?;
        }
        validate_runtime_capabilities(&self.capabilities)?;
        validate_expected_dependencies(&self.dependencies)?;
        Ok(())
    }
}

/// Odin's observation of one dependency selected in the bound Expected
/// projection. Evidence digests identify the signed/provider-owned facts Odin
/// used; they do not copy those facts into Odin authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OdinRuntimeDependencyEvidence {
    pub kind: String,
    pub capability: String,
    pub schema: String,
    pub compatibility: String,
    pub provider_id: Option<String>,
    pub provider_authority: Option<String>,
    pub provider_expected_projection_sha256: Option<String>,
    pub provider_endpoint: Option<String>,
    pub observed_capacity: Option<u32>,
    pub provider_evidence_sha256: Option<String>,
    pub ready: bool,
}

impl OdinRuntimeDependencyEvidence {
    fn identity(&self) -> (&str, &str, &str) {
        (&self.capability, &self.schema, &self.compatibility)
    }

    fn validate(&self) -> Result<()> {
        if !matches!(
            self.kind.as_str(),
            "bootstrap"
                | "required"
                | "optional"
                | "shared-infrastructure"
                | "private"
                | "external-operator-binding"
        ) {
            bail!("dependency evidence kind is unsupported");
        }
        validate_authority_identifier(&self.kind, "dependency evidence kind")?;
        validate_authority_identifier(&self.capability, "dependency evidence capability")?;
        validate_authority_identifier(&self.schema, "dependency evidence schema")?;
        validate_authority_identifier(&self.compatibility, "dependency evidence compatibility")?;
        validate_optional_identifier(&self.provider_id, "dependency evidence provider id")?;
        validate_optional_identifier(
            &self.provider_authority,
            "dependency evidence provider authority",
        )?;
        validate_optional_sha256(
            &self.provider_expected_projection_sha256,
            "dependency evidence provider expected projection sha256",
        )?;
        validate_optional_endpoint_labeled(
            &self.provider_endpoint,
            "dependency evidence provider endpoint",
        )?;
        validate_optional_sha256(
            &self.provider_evidence_sha256,
            "dependency provider evidence sha256",
        )?;
        if self.observed_capacity == Some(0) {
            bail!("dependency evidence capacity is zero");
        }
        if self.provider_id.is_none()
            && (self.provider_authority.is_some()
                || self.provider_expected_projection_sha256.is_some()
                || self.provider_endpoint.is_some()
                || self.observed_capacity.is_some()
                || self.provider_evidence_sha256.is_some()
                || self.ready)
        {
            bail!("dependency evidence has facts without a provider");
        }
        if self.provider_id.is_some() && self.provider_authority.is_none() {
            bail!("dependency evidence provider authority is missing");
        }
        match (
            &self.provider_id,
            &self.provider_authority,
            &self.provider_expected_projection_sha256,
            &self.provider_endpoint,
        ) {
            (None, None, None, None) => {}
            (Some(_), Some(authority), Some(_), _) if authority == "managed-incarnation" => {
                if self.kind == "external-operator-binding" {
                    bail!("external dependency evidence names a managed incarnation");
                }
            }
            (Some(_), Some(authority), None, Some(_))
                if authority == "external-operator-binding"
                    && self.kind == "external-operator-binding" => {}
            _ => bail!("dependency evidence provider binding is authority-incoherent"),
        }
        if self.ready
            && (self.observed_capacity.is_none() || self.provider_evidence_sha256.is_none())
        {
            bail!("ready dependency lacks capacity or signed evidence");
        }
        Ok(())
    }
}

/// One explicit Expected/observed disagreement. Codes are unique and sorted so
/// the signed receipt has one canonical explanation for each disagreement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OdinTopologyDisagreement {
    pub code: String,
    pub expected: Option<String>,
    pub observed: Option<String>,
}

impl OdinTopologyDisagreement {
    fn validate(&self) -> Result<()> {
        validate_authority_identifier(&self.code, "topology disagreement code")?;
        validate_optional_detail(&self.expected, "topology disagreement expected value")?;
        validate_optional_detail(&self.observed, "topology disagreement observed value")?;
        if self.expected.is_none() && self.observed.is_none() {
            bail!("topology disagreement carries no expected or observed value");
        }
        Ok(())
    }
}

/// Odin-owned signed correlation of Idunn's exact Expected projection with
/// current Idunn activation and provider-signed presence. The signature covers
/// the canonical positional encoding with `signature` empty.
#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(
    type = "odin.runtime_topology_correlation",
    schema = "odin.runtime_topology_correlation.v1"
)]
pub struct OdinRuntimeTopologyCorrelationRecord {
    #[cultcache(key = 0)]
    pub schema_version: String,
    #[cultcache(key = 1)]
    pub target: String,
    #[cultcache(key = 2)]
    pub expected_projection_sha256: String,
    #[cultcache(key = 3)]
    pub expected: bool,
    #[cultcache(key = 4)]
    pub current_activation_sha256: Option<String>,
    #[cultcache(key = 5)]
    pub signed_presence_sha256: Option<String>,
    #[cultcache(key = 6)]
    pub runtime_id: String,
    #[cultcache(key = 7)]
    pub runtime_instance_id: Option<String>,
    #[cultcache(key = 8)]
    pub present: bool,
    #[cultcache(key = 9)]
    pub ready: bool,
    #[cultcache(key = 10)]
    pub dependencies: Vec<OdinRuntimeDependencyEvidence>,
    #[cultcache(key = 11)]
    pub disagreements: Vec<OdinTopologyDisagreement>,
    #[cultcache(key = 12)]
    pub signer_identity_id: String,
    #[cultcache(key = 13)]
    pub publisher_sequence: u64,
    #[cultcache(key = 14)]
    pub observed_at_unix_millis: u64,
    #[cultcache(key = 15)]
    pub signature_algorithm: String,
    #[cultcache(key = 16, bytes)]
    pub signature: Vec<u8>,
}

impl OdinRuntimeTopologyCorrelationRecord {
    pub fn decode_canonical_signed_payload(payload: &[u8]) -> Result<(Self, Vec<u8>)> {
        if messagepack_array_len(payload) != Some(17) {
            bail!("topology correlation is not the 17-field positional contract");
        }
        let receipt: Self =
            rmp_serde::from_slice(payload).context("decoding runtime topology correlation")?;
        if rmp_serde::to_vec(&receipt)? != payload {
            bail!("topology correlation is not canonical positional MessagePack");
        }
        receipt.validate()?;
        let unsigned = receipt.unsigned_signature_payload()?;
        Ok((receipt, unsigned))
    }

    pub fn unsigned_signature_payload(&self) -> Result<Vec<u8>> {
        self.validate_shape(true)?;
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok(rmp_serde::to_vec(&unsigned)?)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(rmp_serde::to_vec(self)?)
    }

    pub fn canonical_sha256(&self) -> Result<String> {
        Ok(prefixed_sha256(&self.canonical_bytes()?))
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_shape(false)
    }

    pub fn validate_against_expected(
        &self,
        expected: &IdunnExpectedIncarnationRecord,
    ) -> Result<()> {
        self.validate()?;
        expected.validate()?;
        if self.expected_projection_sha256 != expected.canonical_sha256()?
            || self.target != expected.target
            || self.runtime_id != expected.runtime_id
            || self.dependencies.len() != expected.dependencies.len()
        {
            bail!("topology correlation substitutes or omits Expected authority");
        }
        for (evidence, requirement) in self.dependencies.iter().zip(&expected.dependencies) {
            if evidence.identity() != requirement.identity()
                || evidence.kind != requirement.kind
                || evidence.provider_id != requirement.provider_id
                || evidence.provider_authority != requirement.provider_authority
                || evidence.provider_expected_projection_sha256
                    != requirement.provider_expected_projection_sha256
                || evidence.provider_endpoint != requirement.provider_endpoint
            {
                bail!("topology dependency evidence does not bind the Expected dependency");
            }
            if evidence.ready
                && evidence
                    .observed_capacity
                    .is_none_or(|capacity| capacity < requirement.minimum_capacity)
            {
                bail!("ready dependency does not meet Expected capacity");
            }
        }
        Ok(())
    }

    fn validate_shape(&self, allow_unsigned: bool) -> Result<()> {
        if self.schema_version != ODIN_RUNTIME_TOPOLOGY_CORRELATION_SCHEMA {
            bail!("topology correlation schema is unsupported");
        }
        validate_authority_identifier(&self.target, "target")?;
        validate_required_sha256(
            &self.expected_projection_sha256,
            "correlation expected projection sha256",
        )?;
        if !self.expected {
            bail!("topology correlation cannot deny the Expected record it binds");
        }
        validate_optional_sha256(&self.current_activation_sha256, "current activation sha256")?;
        validate_optional_sha256(&self.signed_presence_sha256, "signed presence sha256")?;
        validate_authority_identifier(&self.runtime_id, "runtime id")?;
        validate_optional_sha256(&self.runtime_instance_id, "runtime instance id")?;
        let has_runtime_evidence =
            self.current_activation_sha256.is_some() || self.signed_presence_sha256.is_some();
        if self.runtime_instance_id.is_some() != has_runtime_evidence {
            bail!("runtime instance identity and observation evidence are partial");
        }
        if self.present
            && (self.current_activation_sha256.is_none()
                || self.signed_presence_sha256.is_none()
                || self.runtime_instance_id.is_none())
        {
            bail!("Present topology state lacks activation or signed presence");
        }
        validate_dependency_evidence(&self.dependencies)?;
        validate_topology_disagreements(&self.disagreements)?;
        let has_activation = self.current_activation_sha256.is_some();
        let has_presence = self.signed_presence_sha256.is_some();
        if (has_activation != has_presence || (has_activation && !self.present))
            && self.disagreements.is_empty()
        {
            bail!("partial or rejected runtime evidence lacks an explicit disagreement");
        }
        if self.ready
            && (!self.present
                || !self.disagreements.is_empty()
                || self
                    .dependencies
                    .iter()
                    .any(|dependency| dependency.kind != "optional" && !dependency.ready))
        {
            bail!("Ready topology state is not supported by correlated evidence");
        }
        validate_authority_identifier(&self.signer_identity_id, "signer identity id")?;
        let signature_is_valid =
            self.signature.len() == 64 || (allow_unsigned && self.signature.is_empty());
        if self.publisher_sequence == 0
            || self.observed_at_unix_millis == 0
            || self.signature_algorithm != "ed25519"
            || !signature_is_valid
        {
            bail!("topology correlation sequence, time, or signature is invalid");
        }
        Ok(())
    }
}

/// Idunn-issued launch identity. The exact bytes are passed to one workload
/// launch alongside the Expected projection. Creation alone grants nothing:
/// Odin treats this as current process observation only while Idunn publishes
/// it on the authenticated observed-activation surface after the actuator
/// driver verifies the native runtime instance.
#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(
    type = "idunn.runtime_activation",
    schema = "idunn.runtime_activation.v1"
)]
pub struct IdunnRuntimeActivationRecord {
    #[cultcache(key = 0)]
    pub schema_version: String,
    #[cultcache(key = 1)]
    pub expected_projection_sha256: String,
    #[cultcache(key = 2)]
    pub runtime_instance_id: String,
    #[cultcache(key = 3)]
    pub issued_at_unix_millis: u64,
}

impl IdunnRuntimeActivationRecord {
    pub fn decode_canonical(payload: &[u8]) -> Result<Self> {
        if messagepack_array_len(payload) != Some(4) {
            bail!("runtime activation is not the 4-field positional contract");
        }
        let activation: Self =
            rmp_serde::from_slice(payload).context("decoding runtime activation")?;
        if rmp_serde::to_vec(&activation)? != payload {
            bail!("runtime activation is not canonical positional MessagePack");
        }
        activation.validate()?;
        Ok(activation)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(rmp_serde::to_vec(self)?)
    }

    pub fn canonical_sha256(&self) -> Result<String> {
        Ok(prefixed_sha256(&self.canonical_bytes()?))
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != IDUNN_RUNTIME_ACTIVATION_SCHEMA {
            bail!("runtime activation schema is unsupported");
        }
        validate_required_sha256(
            &self.expected_projection_sha256,
            "activation expected projection sha256",
        )?;
        validate_required_sha256(&self.runtime_instance_id, "runtime instance id")?;
        if self.issued_at_unix_millis == 0 {
            bail!("runtime activation issue time is invalid");
        }
        Ok(())
    }
}

/// Unsigned Idunn-owned local file that grants one exact process incarnation
/// state-write authority. It is authoritative only when read through the
/// root-owned admitted path and lock protocol; its bytes carry no route or
/// traffic authority.
#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(
    type = "idunn.process_write_lease",
    schema = "idunn.process_write_lease.v1"
)]
pub struct IdunnProcessWriteLeaseRecord {
    #[cultcache(key = 0)]
    pub schema_version: String,
    #[cultcache(key = 1)]
    pub target: String,
    #[cultcache(key = 2)]
    pub expected_projection_sha256: String,
    #[cultcache(key = 3)]
    pub plan_id: String,
    #[cultcache(key = 4)]
    pub incarnation_id: String,
    #[cultcache(key = 5)]
    pub sealed_release_id: String,
    #[cultcache(key = 6)]
    pub activation_witness_sha256: String,
    #[cultcache(key = 7)]
    pub state_schema_generation: String,
    #[cultcache(key = 8)]
    pub state_contract_sha256: String,
    #[cultcache(key = 9)]
    pub runtime_id: String,
    #[cultcache(key = 10)]
    pub runtime_instance_id: String,
    #[cultcache(key = 11)]
    pub warming_presence_sha256: String,
    #[cultcache(key = 12)]
    pub lease_epoch: u64,
    #[cultcache(key = 13)]
    pub issued_at_unix_millis: u64,
}

impl IdunnProcessWriteLeaseRecord {
    pub fn decode_canonical(payload: &[u8]) -> Result<Self> {
        if messagepack_array_len(payload) != Some(14) {
            bail!("process write lease is not the 14-field positional contract");
        }
        let lease: Self = rmp_serde::from_slice(payload).context("decoding process write lease")?;
        if rmp_serde::to_vec(&lease)? != payload {
            bail!("process write lease is not canonical positional MessagePack");
        }
        lease.validate()?;
        Ok(lease)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(rmp_serde::to_vec(self)?)
    }

    pub fn canonical_sha256(&self) -> Result<String> {
        Ok(prefixed_sha256(&self.canonical_bytes()?))
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != IDUNN_PROCESS_WRITE_LEASE_SCHEMA {
            bail!("process write lease schema is unsupported");
        }
        validate_authority_identifier(&self.target, "target")?;
        validate_required_sha256(
            &self.expected_projection_sha256,
            "lease expected projection sha256",
        )?;
        validate_required_sha256(&self.plan_id, "plan id")?;
        validate_authority_identifier(&self.incarnation_id, "incarnation id")?;
        validate_required_sha256(&self.sealed_release_id, "sealed release id")?;
        validate_required_sha256(&self.activation_witness_sha256, "activation witness sha256")?;
        validate_authority_identifier(&self.state_schema_generation, "state schema generation")?;
        validate_required_sha256(&self.state_contract_sha256, "state contract sha256")?;
        validate_authority_identifier(&self.runtime_id, "runtime id")?;
        validate_required_sha256(&self.runtime_instance_id, "runtime instance id")?;
        validate_required_sha256(&self.warming_presence_sha256, "warming presence sha256")?;
        if self.lease_epoch == 0 || self.issued_at_unix_millis == 0 {
            bail!("process write lease epoch or issue time is invalid");
        }
        Ok(())
    }
}

fn messagepack_array_len(payload: &[u8]) -> Option<usize> {
    match *payload.first()? {
        marker @ 0x90..=0x9f => Some(usize::from(marker & 0x0f)),
        0xdc => Some(usize::from(u16::from_be_bytes([
            *payload.get(1)?,
            *payload.get(2)?,
        ]))),
        0xdd => usize::try_from(u32::from_be_bytes([
            *payload.get(1)?,
            *payload.get(2)?,
            *payload.get(3)?,
            *payload.get(4)?,
        ]))
        .ok(),
        _ => None,
    }
}

fn validate_authority_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        bail!("{label} is empty, oversized, padded, or contains control characters");
    }
    Ok(())
}

fn validate_optional_identifier(value: &Option<String>, label: &str) -> Result<()> {
    if let Some(value) = value {
        validate_authority_identifier(value, label)?;
    }
    Ok(())
}

fn validate_source_repository(value: &str) -> Result<()> {
    validate_authority_identifier(value, "source repository")?;
    let segments: Vec<&str> = value.split('/').collect();
    if segments.len() < 3
        || !segments[0].contains('.')
        || segments.iter().any(|segment| {
            segment.is_empty()
                || matches!(*segment, "." | "..")
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        bail!("source repository is not a canonical host/owner/repository identity");
    }
    Ok(())
}

fn validate_endpoint(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 2048
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        bail!("{label} is empty, oversized, padded, or contains control characters");
    }
    Ok(())
}

fn validate_optional_endpoint_labeled(value: &Option<String>, label: &str) -> Result<()> {
    if let Some(endpoint) = value {
        validate_endpoint(endpoint, label)?;
    }
    Ok(())
}

fn validate_optional_endpoint(value: &Option<String>) -> Result<()> {
    validate_optional_endpoint_labeled(value, "bound endpoint")
}

fn validate_runtime_capabilities(capabilities: &[GameCultRuntimeCapability]) -> Result<()> {
    if capabilities.len() > MAX_RUNTIME_CAPABILITIES {
        bail!("runtime presence capability count exceeds its contract bound");
    }
    let mut previous: Option<(&str, &str, &str)> = None;
    for capability in capabilities {
        validate_authority_identifier(&capability.capability, "capability")?;
        validate_authority_identifier(&capability.schema, "capability schema")?;
        validate_authority_identifier(&capability.compatibility, "capability compatibility")?;
        if capability.capacity == 0 {
            bail!("runtime capability capacity is zero");
        }
        let identity = (
            capability.capability.as_str(),
            capability.schema.as_str(),
            capability.compatibility.as_str(),
        );
        if previous.is_some_and(|previous| previous >= identity) {
            bail!("runtime capabilities are not strictly sorted and unique");
        }
        previous = Some(identity);
    }
    Ok(())
}

fn validate_expected_dependencies(dependencies: &[IdunnExpectedDependency]) -> Result<()> {
    if dependencies.len() > MAX_RUNTIME_DEPENDENCIES {
        bail!("Expected dependency count exceeds its contract bound");
    }
    let mut previous: Option<(&str, &str, &str)> = None;
    for dependency in dependencies {
        dependency.validate()?;
        let identity = dependency.identity();
        if previous.is_some_and(|previous| previous >= identity) {
            bail!("Expected dependencies are not strictly sorted and unique");
        }
        previous = Some(identity);
    }
    Ok(())
}

fn validate_dependency_evidence(dependencies: &[OdinRuntimeDependencyEvidence]) -> Result<()> {
    if dependencies.len() > MAX_RUNTIME_DEPENDENCIES {
        bail!("dependency evidence count exceeds its contract bound");
    }
    let mut previous: Option<(&str, &str, &str)> = None;
    for dependency in dependencies {
        dependency.validate()?;
        let identity = dependency.identity();
        if previous.is_some_and(|previous| previous >= identity) {
            bail!("dependency evidence is not strictly sorted and unique");
        }
        previous = Some(identity);
    }
    Ok(())
}

fn validate_topology_disagreements(disagreements: &[OdinTopologyDisagreement]) -> Result<()> {
    if disagreements.len() > MAX_TOPOLOGY_DISAGREEMENTS {
        bail!("topology disagreement count exceeds its contract bound");
    }
    let mut previous: Option<&str> = None;
    for disagreement in disagreements {
        disagreement.validate()?;
        if previous.is_some_and(|previous| previous >= disagreement.code.as_str()) {
            bail!("topology disagreements are not strictly sorted and unique by code");
        }
        previous = Some(&disagreement.code);
    }
    Ok(())
}

fn validate_optional_detail(value: &Option<String>, label: &str) -> Result<()> {
    if value.as_deref().is_some_and(|value| {
        value.is_empty()
            || value.len() > 1024
            || value.trim() != value
            || value.chars().any(char::is_control)
    }) {
        bail!("{label} is empty, oversized, padded, or contains control characters");
    }
    Ok(())
}

fn validate_required_sha256(value: &str, label: &str) -> Result<()> {
    if !is_sha256(value) {
        bail!("{label} is malformed");
    }
    Ok(())
}

fn validate_optional_sha256(value: &Option<String>, label: &str) -> Result<()> {
    if value.as_deref().is_some_and(|value| !is_sha256(value)) {
        bail!("{label} is malformed");
    }
    Ok(())
}

fn prefixed_sha256(bytes: &[u8]) -> String {
    format!("sha256-{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256-")
        .is_some_and(|digest| is_lower_hex(digest, 64))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        GAMECULT_SERVICE_TRUST_ANCHOR_SCHEMA, GameCultProviderHealthIdentity,
        GameCultRuntimePresenceHealthPurpose, GameCultServiceTrustAnchorRecord,
        IDUNN_SIGNED_DAEMON_HEALTH_SCHEMA, IdunnServiceIdentity,
        OdinRuntimeTopologyCorrelationPurpose, OdinTopologyIdentity, ServiceIdentitySignature,
        ServiceSignaturePurpose, derive_service_identity_id, enroll_service_identity_at,
        verify_service_identity_signature,
    };

    struct WrongOdinTopologyPurpose;

    impl ServiceSignaturePurpose<OdinTopologyIdentity> for WrongOdinTopologyPurpose {
        const PURPOSE: &'static [u8] = b"odin.not-runtime-topology-correlation.v1";
    }

    fn digest(byte: char) -> String {
        format!("sha256-{}", byte.to_string().repeat(64))
    }

    fn runtime_capability(name: &str) -> GameCultRuntimeCapability {
        GameCultRuntimeCapability {
            capability: name.into(),
            schema: format!("{name}.v1"),
            compatibility: "v1".into(),
            capacity: 1,
        }
    }

    fn runtime_presence() -> GameCultRuntimePresenceHealthRecord {
        GameCultRuntimePresenceHealthRecord {
            schema_version: GAMECULT_RUNTIME_PRESENCE_HEALTH_SCHEMA.into(),
            target: "ghostlight".into(),
            expected_projection_sha256: digest('9'),
            plan_id: digest('e'),
            incarnation_id: "ghostlight/2026-09-02/1".into(),
            sealed_release_id: digest('f'),
            activation_witness_sha256: digest('a'),
            state_schema_generation: Some("world-v2".into()),
            state_contract_sha256: Some(digest('b')),
            runtime_id: "ghostlight-yggdrasil-1".into(),
            runtime_instance_id: digest('8'),
            bound_endpoint: Some("http://127.0.0.1:14103".into()),
            capabilities: vec![
                runtime_capability("conversation"),
                runtime_capability("state"),
            ],
            health_contract: "ghostlight.runtime-health.v1".into(),
            state: "active".into(),
            detail: "ready".into(),
            write_lease_sha256: Some(digest('c')),
            signer_identity_id: "provider-signing-key".into(),
            publisher_sequence: 1,
            observed_at_unix_millis: 100,
            signature_algorithm: "ed25519".into(),
            signature: vec![6; 64],
        }
    }

    fn runtime_activation() -> IdunnRuntimeActivationRecord {
        IdunnRuntimeActivationRecord {
            schema_version: IDUNN_RUNTIME_ACTIVATION_SCHEMA.into(),
            expected_projection_sha256: digest('9'),
            runtime_instance_id: digest('8'),
            issued_at_unix_millis: 99,
        }
    }

    fn process_write_lease() -> IdunnProcessWriteLeaseRecord {
        IdunnProcessWriteLeaseRecord {
            schema_version: IDUNN_PROCESS_WRITE_LEASE_SCHEMA.into(),
            target: "ghostlight".into(),
            expected_projection_sha256: digest('9'),
            plan_id: digest('e'),
            incarnation_id: "ghostlight/2026-09-02/1".into(),
            sealed_release_id: digest('f'),
            activation_witness_sha256: digest('a'),
            state_schema_generation: "world-v2".into(),
            state_contract_sha256: digest('b'),
            runtime_id: "ghostlight-yggdrasil-1".into(),
            runtime_instance_id: digest('8'),
            warming_presence_sha256: digest('d'),
            lease_epoch: 1,
            issued_at_unix_millis: 101,
        }
    }

    fn expected_dependency(
        kind: &str,
        capability: &str,
        provider_id: Option<&str>,
    ) -> IdunnExpectedDependency {
        IdunnExpectedDependency {
            kind: kind.into(),
            capability: capability.into(),
            schema: format!("{capability}.v1"),
            compatibility: "v1".into(),
            minimum_capacity: 1,
            startup: if kind == "bootstrap" {
                "before-start".into()
            } else {
                "before-promotion".into()
            },
            provider_id: provider_id.map(str::to_string),
            provider_authority: provider_id.map(|_| "managed-incarnation".into()),
            provider_expected_projection_sha256: provider_id.map(|_| digest('1')),
            provider_endpoint: provider_id.map(|_| "tcp://127.0.0.1:14100".into()),
        }
    }

    fn expected_incarnation() -> IdunnExpectedIncarnationRecord {
        IdunnExpectedIncarnationRecord {
            schema_version: IDUNN_EXPECTED_INCARNATION_SCHEMA.into(),
            target: "ghostlight".into(),
            plan_id: digest('2'),
            incarnation_id: "ghostlight/2026-09-02/1".into(),
            sealed_release_id: digest('3'),
            source_repository: "github.com/GameCult/Ghostlight".into(),
            source_revision: "4".repeat(40),
            recipe_sha256: digest('5'),
            runtime_id: "ghostlight-yggdrasil-1".into(),
            expected_signer_identity_id: "ghostlight-provider-signing-key".into(),
            health_contract: "ghostlight.runtime-health.v1".into(),
            artifact_sha256: digest('6'),
            state_schema_generation: Some("world-v2".into()),
            state_contract_sha256: Some(digest('7')),
            write_lease_required: true,
            route: Some(IdunnExpectedRoute {
                route_id: "ghostlight-public".into(),
                transport: "http".into(),
                stable_endpoint: "https://ghostlight.gamecult.net".into(),
                candidate_endpoint: "http://127.0.0.1:14103".into(),
            }),
            capabilities: vec![
                runtime_capability("conversation"),
                runtime_capability("state"),
            ],
            dependencies: vec![
                expected_dependency("shared-infrastructure", "rendezvous", Some("odin-ygg-1")),
                expected_dependency("optional", "telemetry", None),
            ],
        }
    }

    fn dependency_evidence(requirement: &IdunnExpectedDependency) -> OdinRuntimeDependencyEvidence {
        let selected = requirement.provider_id.is_some();
        OdinRuntimeDependencyEvidence {
            kind: requirement.kind.clone(),
            capability: requirement.capability.clone(),
            schema: requirement.schema.clone(),
            compatibility: requirement.compatibility.clone(),
            provider_id: requirement.provider_id.clone(),
            provider_authority: requirement.provider_authority.clone(),
            provider_expected_projection_sha256: requirement
                .provider_expected_projection_sha256
                .clone(),
            provider_endpoint: requirement.provider_endpoint.clone(),
            observed_capacity: selected.then_some(1),
            provider_evidence_sha256: selected.then(|| digest('8')),
            ready: selected,
        }
    }

    fn topology_correlation(
        expected: &IdunnExpectedIncarnationRecord,
    ) -> OdinRuntimeTopologyCorrelationRecord {
        OdinRuntimeTopologyCorrelationRecord {
            schema_version: ODIN_RUNTIME_TOPOLOGY_CORRELATION_SCHEMA.into(),
            target: expected.target.clone(),
            expected_projection_sha256: expected.canonical_sha256().unwrap(),
            expected: true,
            current_activation_sha256: Some(digest('9')),
            signed_presence_sha256: Some(digest('a')),
            runtime_id: expected.runtime_id.clone(),
            runtime_instance_id: Some(digest('b')),
            present: true,
            ready: true,
            dependencies: expected
                .dependencies
                .iter()
                .map(dependency_evidence)
                .collect(),
            disagreements: vec![],
            signer_identity_id: "odin-topology-signing-key".into(),
            publisher_sequence: 1,
            observed_at_unix_millis: 102,
            signature_algorithm: "ed25519".into(),
            signature: vec![7; 64],
        }
    }

    fn topology_anchor() -> GameCultServiceTrustAnchorRecord {
        let public_key = vec![9; 32];
        GameCultServiceTrustAnchorRecord {
            schema_version: GAMECULT_SERVICE_TRUST_ANCHOR_SCHEMA.into(),
            trust_anchor_id: "root/odin/runtime-topology".into(),
            service_id: "odin".into(),
            runtime_id: "odin-yggdrasil-1".into(),
            signer_identity_id: derive_service_identity_id::<OdinTopologyIdentity>(&public_key)
                .unwrap(),
            signer_public_key: public_key,
            signature_algorithm: "ed25519".into(),
            signing_purpose: ODIN_RUNTIME_TOPOLOGY_CORRELATION_SIGNING_PURPOSE.into(),
            signed_schema: ODIN_RUNTIME_TOPOLOGY_CORRELATION_SCHEMA.into(),
            binding_authority: "root".into(),
            bound_at_unix_millis: 100,
            expires_at_unix_millis: Some(200),
            private_state_exposed: false,
        }
    }

    fn runtime_presence_anchor() -> GameCultServiceTrustAnchorRecord {
        let public_key = vec![7; 32];
        GameCultServiceTrustAnchorRecord {
            schema_version: GAMECULT_SERVICE_TRUST_ANCHOR_SCHEMA.into(),
            trust_anchor_id: "root/ghostlight/runtime-presence".into(),
            service_id: "ghostlight".into(),
            runtime_id: "ghostlight-yggdrasil-1".into(),
            signer_identity_id: derive_service_identity_id::<GameCultProviderHealthIdentity>(
                &public_key,
            )
            .unwrap(),
            signer_public_key: public_key,
            signature_algorithm: "ed25519".into(),
            signing_purpose: GAMECULT_RUNTIME_PRESENCE_HEALTH_SIGNING_PURPOSE.into(),
            signed_schema: GAMECULT_RUNTIME_PRESENCE_HEALTH_SCHEMA.into(),
            binding_authority: "root".into(),
            bound_at_unix_millis: 100,
            expires_at_unix_millis: Some(200),
            private_state_exposed: false,
        }
    }

    #[test]
    fn runtime_authority_contracts_round_trip_as_canonical_positional_records() -> Result<()> {
        let presence = runtime_presence();
        presence.validate()?;
        let encoded_presence = rmp_serde::to_vec(&presence)?;
        assert_eq!(messagepack_array_len(&encoded_presence), Some(22));
        let (decoded_presence, unsigned) =
            GameCultRuntimePresenceHealthRecord::decode_canonical_signed_payload(
                &encoded_presence,
            )?;
        assert_eq!(decoded_presence, presence);
        let unsigned_presence: GameCultRuntimePresenceHealthRecord =
            rmp_serde::from_slice(&unsigned)?;
        assert!(unsigned_presence.signature.is_empty());
        assert_eq!(unsigned, presence.unsigned_signature_payload()?);

        let activation = runtime_activation();
        let encoded_activation = activation.canonical_bytes()?;
        assert_eq!(messagepack_array_len(&encoded_activation), Some(4));
        assert_eq!(
            IdunnRuntimeActivationRecord::decode_canonical(&encoded_activation)?,
            activation
        );
        assert_eq!(
            activation.canonical_sha256()?,
            prefixed_sha256(&encoded_activation)
        );

        let lease = process_write_lease();
        lease.validate()?;
        let encoded_lease = lease.canonical_bytes()?;
        assert_eq!(messagepack_array_len(&encoded_lease), Some(14));
        assert_eq!(
            IdunnProcessWriteLeaseRecord::decode_canonical(&encoded_lease)?,
            lease
        );
        assert_eq!(lease.canonical_sha256()?, prefixed_sha256(&encoded_lease));
        Ok(())
    }

    #[test]
    fn runtime_presence_signature_covers_the_exact_canonical_record() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let signer = enroll_service_identity_at::<GameCultProviderHealthIdentity>(
            &temp.path().join("runtime-presence.cc"),
        )?;
        let anchor = signer.trust_anchor()?;
        let mut presence = runtime_presence();
        presence.signer_identity_id = anchor.identity_id.clone();
        presence.signature.clear();
        let unsigned = presence.unsigned_signature_payload()?;
        let proof = signer.sign::<GameCultRuntimePresenceHealthPurpose>(&unsigned);
        presence.signature = proof.signature.clone();

        let encoded = rmp_serde::to_vec(&presence)?;
        let (decoded, decoded_unsigned) =
            GameCultRuntimePresenceHealthRecord::decode_canonical_signed_payload(&encoded)?;
        verify_service_identity_signature::<
            GameCultProviderHealthIdentity,
            GameCultRuntimePresenceHealthPurpose,
        >(
            &anchor,
            &decoded_unsigned,
            &ServiceIdentitySignature {
                identity_id: decoded.signer_identity_id,
                signature: decoded.signature,
            },
        )?;

        let mut changed = decoded_unsigned;
        changed.push(0);
        assert!(
            verify_service_identity_signature::<
                GameCultProviderHealthIdentity,
                GameCultRuntimePresenceHealthPurpose,
            >(&anchor, &changed, &proof)
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn runtime_authority_decoders_reject_malformed_and_noncanonical_bytes() -> Result<()> {
        assert!(
            GameCultRuntimePresenceHealthRecord::decode_canonical_signed_payload(&[0x91, 0xc0])
                .is_err()
        );
        assert!(IdunnRuntimeActivationRecord::decode_canonical(&[0x91, 0xc0]).is_err());
        assert!(IdunnProcessWriteLeaseRecord::decode_canonical(&[0x91, 0xc0]).is_err());

        let presence = rmp_serde::to_vec(&runtime_presence())?;
        assert_eq!(&presence[..3], &[0xdc, 0, 22]);
        let mut noncanonical_presence = vec![0xdd, 0, 0, 0, 22];
        noncanonical_presence.extend_from_slice(&presence[3..]);
        assert!(
            GameCultRuntimePresenceHealthRecord::decode_canonical_signed_payload(
                &noncanonical_presence,
            )
            .is_err()
        );

        let activation = runtime_activation().canonical_bytes()?;
        assert_eq!(activation[0], 0x94);
        let mut noncanonical_activation = vec![0xdc, 0, 4];
        noncanonical_activation.extend_from_slice(&activation[1..]);
        assert!(IdunnRuntimeActivationRecord::decode_canonical(&noncanonical_activation).is_err());

        let lease = process_write_lease().canonical_bytes()?;
        assert_eq!(lease[0], 0x9e);
        let mut noncanonical_lease = vec![0xdc, 0, 14];
        noncanonical_lease.extend_from_slice(&lease[1..]);
        assert!(IdunnProcessWriteLeaseRecord::decode_canonical(&noncanonical_lease).is_err());
        Ok(())
    }

    #[test]
    fn runtime_presence_refuses_capability_and_warming_lease_ambiguity() {
        let mut value = runtime_presence();
        value.capabilities.reverse();
        assert!(value.validate().is_err());

        let mut value = runtime_presence();
        let mut duplicate = runtime_capability("state");
        duplicate.capacity = 2;
        value.capabilities.push(duplicate);
        assert!(value.validate().is_err());

        let mut value = runtime_presence();
        value.capabilities[0].capacity = 0;
        assert!(value.validate().is_err());

        let mut value = runtime_presence();
        value.state = "warming".into();
        assert!(value.validate().is_err());
        value.write_lease_sha256 = None;
        assert!(value.validate().is_ok());

        let mut value = runtime_presence();
        value.state_schema_generation = None;
        assert!(value.validate().is_err());
        value.state_contract_sha256 = None;
        assert!(value.validate().is_err());
        value.write_lease_sha256 = None;
        assert!(value.validate().is_ok());
    }

    #[test]
    fn runtime_authority_refuses_malformed_digest_process_and_epoch_bindings() {
        let mut value = runtime_presence();
        value.activation_witness_sha256 = digest('A');
        assert!(value.validate().is_err());

        let mut value = runtime_presence();
        value.plan_id = "plan-1".into();
        assert!(value.validate().is_err());

        let mut value = runtime_presence();
        value.sealed_release_id = "release-1".into();
        assert!(value.validate().is_err());

        let mut value = runtime_presence();
        value.runtime_instance_id = "systemd-invocation-1".into();
        assert!(value.validate().is_err());

        let mut value = runtime_presence();
        value.expected_projection_sha256 = "expected-1".into();
        assert!(value.validate().is_err());

        let mut value = runtime_presence();
        value.write_lease_sha256 = Some("lease-1".into());
        assert!(value.validate().is_err());

        let mut value = process_write_lease();
        value.warming_presence_sha256 = digest('D');
        assert!(value.validate().is_err());

        let mut value = process_write_lease();
        value.plan_id = "plan-1".into();
        assert!(value.validate().is_err());

        let mut value = process_write_lease();
        value.runtime_instance_id = "pid-4242".into();
        assert!(value.validate().is_err());

        let mut value = process_write_lease();
        value.lease_epoch = 0;
        assert!(value.validate().is_err());

        let mut value = runtime_activation();
        value.runtime_instance_id = digest('A');
        assert!(value.validate().is_err());

        let mut value = runtime_activation();
        value.expected_projection_sha256 = "expected-1".into();
        assert!(value.validate().is_err());
    }

    #[test]
    fn runtime_presence_trust_anchor_is_provider_profile_and_purpose_bound() -> Result<()> {
        let anchor = runtime_presence_anchor();
        anchor.validate()?;

        let mut value = anchor.clone();
        value.signing_purpose = "idunn.signed_daemon_health.v1".into();
        assert!(value.validate().is_err());

        let mut value = anchor.clone();
        value.signed_schema = IDUNN_SIGNED_DAEMON_HEALTH_SCHEMA.into();
        assert!(value.validate().is_err());

        let mut value = anchor;
        value.signer_identity_id =
            derive_service_identity_id::<IdunnServiceIdentity>(&value.signer_public_key)?;
        assert!(value.validate().is_err());
        Ok(())
    }

    #[test]
    fn process_write_lease_cannot_encode_route_or_traffic_authority() -> Result<()> {
        let canonical = process_write_lease().canonical_bytes()?;
        assert_eq!(messagepack_array_len(&canonical), Some(14));

        for forbidden in ["route", "traffic"] {
            let mut with_extra_authority = vec![0xdc, 0, 15];
            with_extra_authority.extend_from_slice(&canonical[1..]);
            with_extra_authority.extend_from_slice(&rmp_serde::to_vec(&forbidden)?);
            assert!(IdunnProcessWriteLeaseRecord::decode_canonical(&with_extra_authority).is_err());
        }
        Ok(())
    }

    #[test]
    fn expected_and_topology_correlation_round_trip_canonically() -> Result<()> {
        let expected = expected_incarnation();
        let expected_bytes = expected.canonical_bytes()?;
        assert_eq!(&expected_bytes[..3], &[0xdc, 0, 18]);
        assert_eq!(
            IdunnExpectedIncarnationRecord::decode_canonical(&expected_bytes)?,
            expected
        );
        assert_eq!(
            expected.canonical_sha256()?,
            prefixed_sha256(&expected_bytes)
        );

        let receipt = topology_correlation(&expected);
        receipt.validate_against_expected(&expected)?;
        let receipt_bytes = receipt.canonical_bytes()?;
        assert_eq!(&receipt_bytes[..3], &[0xdc, 0, 17]);
        let (decoded, unsigned) =
            OdinRuntimeTopologyCorrelationRecord::decode_canonical_signed_payload(&receipt_bytes)?;
        assert_eq!(decoded, receipt);
        let unsigned_receipt: OdinRuntimeTopologyCorrelationRecord =
            rmp_serde::from_slice(&unsigned)?;
        assert!(unsigned_receipt.signature.is_empty());
        assert_eq!(unsigned, receipt.unsigned_signature_payload()?);
        assert_eq!(receipt.canonical_sha256()?, prefixed_sha256(&receipt_bytes));
        Ok(())
    }

    #[test]
    fn expected_and_topology_decoders_reject_noncanonical_or_extended_records() -> Result<()> {
        assert!(IdunnExpectedIncarnationRecord::decode_canonical(&[0x91, 0xc0]).is_err());
        assert!(
            OdinRuntimeTopologyCorrelationRecord::decode_canonical_signed_payload(&[0x91, 0xc0])
                .is_err()
        );

        let expected = expected_incarnation().canonical_bytes()?;
        let mut noncanonical_expected = vec![0xdd, 0, 0, 0, 18];
        noncanonical_expected.extend_from_slice(&expected[3..]);
        assert!(IdunnExpectedIncarnationRecord::decode_canonical(&noncanonical_expected).is_err());

        let receipt = topology_correlation(&expected_incarnation()).canonical_bytes()?;
        let mut noncanonical_receipt = vec![0xdd, 0, 0, 0, 17];
        noncanonical_receipt.extend_from_slice(&receipt[3..]);
        assert!(
            OdinRuntimeTopologyCorrelationRecord::decode_canonical_signed_payload(
                &noncanonical_receipt,
            )
            .is_err()
        );

        for forbidden in ["private-host-path", "runner-secret"] {
            let mut extended = vec![0xdc, 0, 19];
            extended.extend_from_slice(&expected[3..]);
            extended.extend_from_slice(&rmp_serde::to_vec(&forbidden)?);
            assert!(IdunnExpectedIncarnationRecord::decode_canonical(&extended).is_err());
        }
        Ok(())
    }

    #[test]
    fn expected_refuses_partial_state_and_noncanonical_claim_sets() {
        let mut value = expected_incarnation();
        value.state_contract_sha256 = None;
        assert!(value.validate().is_err());

        let mut value = expected_incarnation();
        value.state_schema_generation = None;
        assert!(value.validate().is_err());

        let mut value = expected_incarnation();
        value.state_schema_generation = None;
        value.state_contract_sha256 = None;
        assert!(value.validate().is_err());
        value.write_lease_required = false;
        assert!(value.validate().is_ok());

        let mut value = expected_incarnation();
        value.capabilities.reverse();
        assert!(value.validate().is_err());

        let mut value = expected_incarnation();
        value.capabilities.push(runtime_capability("state"));
        assert!(value.validate().is_err());

        let mut value = expected_incarnation();
        value.dependencies.reverse();
        assert!(value.validate().is_err());

        let mut value = expected_incarnation();
        value.dependencies.push(value.dependencies[1].clone());
        assert!(value.validate().is_err());

        let mut value = expected_incarnation();
        let mut duplicate = value.dependencies[1].clone();
        duplicate.kind = "required".into();
        value.dependencies.push(duplicate);
        assert!(value.validate().is_err());

        let mut value = expected_incarnation();
        value.dependencies[0].provider_authority = None;
        assert!(value.validate().is_err());

        let mut value = expected_incarnation();
        value.source_revision = "A".repeat(40);
        assert!(value.validate().is_err());

        for private_source in [
            "F:\\Projects\\Ghostlight",
            "/srv/build/Ghostlight",
            "https://token@github.com/GameCult/Ghostlight",
        ] {
            let mut value = expected_incarnation();
            value.source_repository = private_source.into();
            assert!(value.validate().is_err());
        }

        let mut value = expected_incarnation();
        let stable_endpoint = value.route.as_ref().unwrap().stable_endpoint.clone();
        value.route.as_mut().unwrap().candidate_endpoint = stable_endpoint;
        assert!(value.validate().is_err());
    }

    #[test]
    fn topology_correlation_refuses_expected_substitution_and_dependency_omission() {
        let expected = expected_incarnation();

        let mut value = topology_correlation(&expected);
        value.target = "epiphany".into();
        assert!(value.validate().is_ok());
        assert!(value.validate_against_expected(&expected).is_err());

        let mut value = topology_correlation(&expected);
        value.runtime_id = "ghostlight-other-runtime".into();
        assert!(value.validate_against_expected(&expected).is_err());

        let mut value = topology_correlation(&expected);
        value.expected_projection_sha256 = digest('c');
        assert!(value.validate_against_expected(&expected).is_err());

        let mut value = topology_correlation(&expected);
        value.dependencies.pop();
        assert!(value.validate().is_ok());
        assert!(value.validate_against_expected(&expected).is_err());

        let mut value = topology_correlation(&expected);
        value.dependencies[0].provider_id = Some("odin-substitute".into());
        assert!(value.validate().is_ok());
        assert!(value.validate_against_expected(&expected).is_err());

        let mut value = topology_correlation(&expected);
        value.dependencies[0].kind = "required".into();
        assert!(value.validate().is_ok());
        assert!(value.validate_against_expected(&expected).is_err());

        let mut value = topology_correlation(&expected);
        value.dependencies[0].observed_capacity = Some(0);
        assert!(value.validate().is_err());

        let mut value = topology_correlation(&expected);
        value.dependencies[0].observed_capacity = Some(1);
        let mut stricter = expected.clone();
        stricter.dependencies[0].minimum_capacity = 2;
        value.expected_projection_sha256 = stricter.canonical_sha256().unwrap();
        assert!(value.validate_against_expected(&stricter).is_err());
    }

    #[test]
    fn topology_correlation_requires_explicit_coherent_partial_states() {
        let expected = expected_incarnation();
        let mut value = topology_correlation(&expected);
        value.signed_presence_sha256 = None;
        value.present = false;
        value.ready = false;
        assert!(value.validate().is_err());

        value.disagreements.push(OdinTopologyDisagreement {
            code: "presence-missing".into(),
            expected: Some("signed-runtime-presence".into()),
            observed: None,
        });
        assert!(value.validate().is_ok());

        let mut value = topology_correlation(&expected);
        value.runtime_instance_id = None;
        assert!(value.validate().is_err());

        let mut value = topology_correlation(&expected);
        value.current_activation_sha256 = None;
        value.present = true;
        value.ready = false;
        value.disagreements.push(OdinTopologyDisagreement {
            code: "activation-missing".into(),
            expected: Some("current-activation".into()),
            observed: None,
        });
        assert!(value.validate().is_err());

        let mut value = topology_correlation(&expected);
        value.expected = false;
        value.present = false;
        value.ready = false;
        assert!(value.validate().is_err());
    }

    #[test]
    fn topology_correlation_refuses_unsorted_or_duplicate_claims() {
        let expected = expected_incarnation();
        let mut value = topology_correlation(&expected);
        value.dependencies.reverse();
        assert!(value.validate().is_err());

        let mut value = topology_correlation(&expected);
        value.dependencies.push(value.dependencies[1].clone());
        assert!(value.validate().is_err());

        let mut value = topology_correlation(&expected);
        value.ready = false;
        value.disagreements = vec![
            OdinTopologyDisagreement {
                code: "schema-mismatch".into(),
                expected: Some("state.v2".into()),
                observed: Some("state.v1".into()),
            },
            OdinTopologyDisagreement {
                code: "endpoint-mismatch".into(),
                expected: Some("route-a".into()),
                observed: Some("route-b".into()),
            },
        ];
        assert!(value.validate().is_err());

        value.disagreements[1].code = "schema-mismatch".into();
        assert!(value.validate().is_err());
    }

    #[test]
    fn topology_correlation_cannot_manufacture_ready() {
        let expected = expected_incarnation();
        let mut value = topology_correlation(&expected);
        value.dependencies[0].ready = false;
        assert!(value.validate().is_err());

        let mut value = topology_correlation(&expected);
        value.disagreements.push(OdinTopologyDisagreement {
            code: "capability-mismatch".into(),
            expected: Some("conversation.v1".into()),
            observed: Some("conversation.v0".into()),
        });
        assert!(value.validate().is_err());

        let mut value = topology_correlation(&expected);
        value.present = false;
        value.disagreements.push(OdinTopologyDisagreement {
            code: "identity-mismatch".into(),
            expected: Some("expected-runtime".into()),
            observed: Some("other-runtime".into()),
        });
        assert!(value.validate().is_err());

        let mut value = topology_correlation(&expected);
        value.dependencies[0].provider_evidence_sha256 = None;
        assert!(value.validate().is_err());
    }

    #[test]
    fn topology_signature_is_exact_and_purpose_bound() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let signer = enroll_service_identity_at::<OdinTopologyIdentity>(
            &temp.path().join("odin-topology.cc"),
        )?;
        let anchor = signer.trust_anchor()?;
        let expected = expected_incarnation();
        let mut receipt = topology_correlation(&expected);
        receipt.signer_identity_id = anchor.identity_id.clone();
        receipt.signature.clear();
        let unsigned = receipt.unsigned_signature_payload()?;
        let proof = signer.sign::<OdinRuntimeTopologyCorrelationPurpose>(&unsigned);
        receipt.signature = proof.signature.clone();

        let encoded = receipt.canonical_bytes()?;
        let (decoded, decoded_unsigned) =
            OdinRuntimeTopologyCorrelationRecord::decode_canonical_signed_payload(&encoded)?;
        verify_service_identity_signature::<
            OdinTopologyIdentity,
            OdinRuntimeTopologyCorrelationPurpose,
        >(
            &anchor,
            &decoded_unsigned,
            &ServiceIdentitySignature {
                identity_id: decoded.signer_identity_id,
                signature: decoded.signature,
            },
        )?;

        let mut substituted = decoded_unsigned.clone();
        substituted.push(0);
        assert!(
            verify_service_identity_signature::<
                OdinTopologyIdentity,
                OdinRuntimeTopologyCorrelationPurpose,
            >(&anchor, &substituted, &proof)
            .is_err()
        );

        let wrong_purpose = signer.sign::<WrongOdinTopologyPurpose>(&decoded_unsigned);
        assert!(
            verify_service_identity_signature::<
                OdinTopologyIdentity,
                OdinRuntimeTopologyCorrelationPurpose,
            >(&anchor, &decoded_unsigned, &wrong_purpose)
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn topology_trust_anchor_is_odin_profile_and_purpose_bound() -> Result<()> {
        let anchor = topology_anchor();
        anchor.validate()?;

        let mut value = anchor.clone();
        value.service_id = "idunn".into();
        assert!(value.validate().is_err());

        let mut value = anchor.clone();
        value.signing_purpose = GAMECULT_RUNTIME_PRESENCE_HEALTH_SIGNING_PURPOSE.into();
        assert!(value.validate().is_err());

        let mut value = anchor.clone();
        value.signed_schema = GAMECULT_RUNTIME_PRESENCE_HEALTH_SCHEMA.into();
        assert!(value.validate().is_err());

        let mut value = anchor;
        value.signer_identity_id =
            derive_service_identity_id::<IdunnServiceIdentity>(&value.signer_public_key)?;
        assert!(value.validate().is_err());
        Ok(())
    }
}
