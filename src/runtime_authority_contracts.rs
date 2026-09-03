use anyhow::{Context, Result, bail, ensure};
use cultcache_rs::DatabaseEntry;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use zeroize::Zeroizing;

pub const GAMECULT_RUNTIME_PRESENCE_HEALTH_SCHEMA: &str = "gamecult.runtime_presence_health.v2";
pub const GAMECULT_RUNTIME_PRESENCE_HEALTH_SIGNING_PURPOSE: &str =
    "gamecult.runtime_presence_health.v2";
pub const GAMECULT_RUNTIME_ACTIVATION_PROOF_SIGNING_PURPOSE: &str =
    "gamecult.runtime_presence.activation-proof.v1";
pub const IDUNN_RUNTIME_ACTIVATION_SCHEMA: &str = "idunn.runtime_activation.v2";
pub const IDUNN_RUNTIME_ACTIVATION_SIGNING_PURPOSE: &str = "idunn.runtime_activation.v2";
pub const IDUNN_RUNTIME_ACTIVATION_CREDENTIAL_NAME: &str = "gamecult-idunn-runtime-activation-key";
pub const IDUNN_PROCESS_WRITE_LEASE_SCHEMA: &str = "idunn.process_write_lease.v1";
pub const IDUNN_EXPECTED_INCARNATION_SCHEMA: &str = "idunn.expected_incarnation.v2";
pub const ODIN_RUNTIME_TOPOLOGY_CORRELATION_SCHEMA: &str = "odin.runtime_topology_correlation.v2";
pub const ODIN_RUNTIME_TOPOLOGY_CORRELATION_SIGNING_PURPOSE: &str =
    "odin.runtime_topology_correlation.v2";

const MAX_RUNTIME_CAPABILITIES: usize = 256;
const MAX_RUNTIME_DEPENDENCIES: usize = 256;
const MAX_TOPOLOGY_DISAGREEMENTS: usize = 256;
const IDUNN_RUNTIME_ACTIVATION_ID_DOMAIN: &[u8] = b"idunn.runtime-activation.id.v1\0";
const IDUNN_RUNTIME_ACTIVATION_SIGNATURE_DOMAIN: &[u8] = b"idunn.runtime-activation.signature.v1\0";

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

impl GameCultRuntimeCapability {
    fn identity(&self) -> (&str, &str, &str) {
        (&self.capability, &self.schema, &self.compatibility)
    }
}

/// Idunn's admitted requirement for one provider-owned runtime capability.
/// The provider reports actual capacity in `GameCultRuntimeCapability`; this
/// record states only the minimum needed for this incarnation to be Ready.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdunnExpectedCapability {
    pub capability: String,
    pub schema: String,
    pub compatibility: String,
    pub minimum_capacity: u32,
}

impl IdunnExpectedCapability {
    fn identity(&self) -> (&str, &str, &str) {
        (&self.capability, &self.schema, &self.compatibility)
    }
}

/// Dual-proved claim from one exact runtime launch. The stable provider key and
/// Idunn's activation-scoped ephemeral key both sign `canonical_proof_payload`:
/// the canonical positional encoding of this complete record with both proof
/// byte fields empty. Present authority requires a matching Idunn-published
/// current activation; neither proof can establish admission by itself.
#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(
    type = "gamecult.runtime_presence_health",
    schema = "gamecult.runtime_presence_health.v2"
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
    #[cultcache(key = 22)]
    pub activation_signer_identity_id: String,
    #[cultcache(key = 23, bytes)]
    pub activation_signature: Vec<u8>,
}

impl GameCultRuntimePresenceHealthRecord {
    /// Return the one canonical payload covered by both the stable provider
    /// signature and the activation-scoped proof. Both signature fields are
    /// empty in these bytes, avoiding circular signatures while binding every
    /// authority-bearing statement field and both signer identities.
    pub fn canonical_proof_payload(&self) -> Result<Vec<u8>> {
        self.validate_shape(true)?;
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned.activation_signature.clear();
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
        validate_authority_identifier(
            &self.activation_signer_identity_id,
            "activation signer identity id",
        )?;
        validate_optional_sha256(&self.write_lease_sha256, "write lease sha256")?;

        let signature_is_valid =
            self.signature.len() == 64 || (allow_unsigned && self.signature.is_empty());
        let activation_signature_is_valid = self.activation_signature.len() == 64
            || (allow_unsigned && self.activation_signature.is_empty());
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
            || !activation_signature_is_valid
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
            "rudp" => {
                if !self.stable_endpoint.starts_with("rudp://")
                    || !self.candidate_endpoint.starts_with("rudp://")
                {
                    bail!("RUDP route endpoints use an unsupported scheme");
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
    schema = "idunn.expected_incarnation.v2"
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
    pub capabilities: Vec<IdunnExpectedCapability>,
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
        validate_expected_capabilities(&self.capabilities)?;
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
/// current Idunn activation and provider-signed presence. Presence state and
/// write-lease observation remain explicit so an opaque Ready bit cannot cross
/// Idunn's warming/fencing boundary. The signature covers the canonical
/// positional encoding with `signature` empty.
#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(
    type = "odin.runtime_topology_correlation",
    schema = "odin.runtime_topology_correlation.v2"
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
    pub observed_presence_state: Option<String>,
    #[cultcache(key = 7)]
    pub observed_presence_publisher_sequence: Option<u64>,
    #[cultcache(key = 8)]
    pub observed_write_lease_sha256: Option<String>,
    #[cultcache(key = 9)]
    pub observed_capabilities: Vec<GameCultRuntimeCapability>,
    #[cultcache(key = 10)]
    pub runtime_id: String,
    #[cultcache(key = 11)]
    pub runtime_instance_id: Option<String>,
    #[cultcache(key = 12)]
    pub present: bool,
    #[cultcache(key = 13)]
    pub ready: bool,
    #[cultcache(key = 14)]
    pub dependencies: Vec<OdinRuntimeDependencyEvidence>,
    #[cultcache(key = 15)]
    pub disagreements: Vec<OdinTopologyDisagreement>,
    #[cultcache(key = 16)]
    pub signer_identity_id: String,
    #[cultcache(key = 17)]
    pub publisher_sequence: u64,
    #[cultcache(key = 18)]
    pub observed_at_unix_millis: u64,
    #[cultcache(key = 19)]
    pub signature_algorithm: String,
    #[cultcache(key = 20, bytes)]
    pub signature: Vec<u8>,
}

impl OdinRuntimeTopologyCorrelationRecord {
    pub fn decode_canonical_signed_payload(payload: &[u8]) -> Result<(Self, Vec<u8>)> {
        if messagepack_array_len(payload) != Some(21) {
            bail!("topology correlation is not the 21-field positional contract");
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
        current_write_lease_sha256: Option<&str>,
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
        let mut capability_disagreements = Vec::new();
        correlate_capabilities(
            &mut capability_disagreements,
            &expected.capabilities,
            &self.observed_capabilities,
        );
        for disagreement in &capability_disagreements {
            if !self.disagreements.contains(disagreement) {
                bail!("topology correlation omits an observed capability disagreement");
            }
        }
        if let Some(current_write_lease_sha256) = current_write_lease_sha256 {
            validate_required_sha256(current_write_lease_sha256, "current write lease sha256")?;
        }
        if expected.write_lease_required {
            if self
                .observed_write_lease_sha256
                .as_deref()
                .is_some_and(|observed| Some(observed) != current_write_lease_sha256)
            {
                bail!("observed write lease is not the current Idunn grant");
            }
            if self.ready
                && (self.observed_write_lease_sha256.is_none()
                    || current_write_lease_sha256.is_none())
            {
                bail!("Ready stateful topology lacks the exact current write lease");
            }
        } else if self.observed_write_lease_sha256.is_some() || current_write_lease_sha256.is_some()
        {
            bail!("stateless Expected topology cannot carry a process write lease");
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
        validate_optional_identifier(&self.observed_presence_state, "observed presence state")?;
        if self.observed_presence_publisher_sequence == Some(0) {
            bail!("observed presence publisher sequence is zero");
        }
        validate_optional_sha256(
            &self.observed_write_lease_sha256,
            "observed write lease sha256",
        )?;
        validate_runtime_capabilities(&self.observed_capabilities)?;
        if self.signed_presence_sha256.is_none() && !self.observed_capabilities.is_empty() {
            bail!("topology correlation has capabilities without signed presence");
        }
        match (
            &self.signed_presence_sha256,
            &self.observed_presence_state,
            self.observed_presence_publisher_sequence,
            &self.observed_write_lease_sha256,
        ) {
            (None, None, None, None) => {}
            (Some(_), Some(state), Some(_), write_lease)
                if matches!(state.as_str(), "warming" | "active" | "degraded" | "failed") =>
            {
                if state == "warming" && write_lease.is_some() {
                    bail!("warming topology presence cannot carry a process write lease");
                }
            }
            _ => bail!("signed presence state, sequence, or write-lease observation is partial"),
        }
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
                || self.observed_presence_publisher_sequence.is_none()
                || self.runtime_instance_id.is_none())
        {
            bail!("Present topology state lacks an authenticated runtime session");
        }
        validate_dependency_evidence(&self.dependencies)?;
        validate_topology_disagreements(&self.disagreements)?;
        let has_activation = self.current_activation_sha256.is_some();
        let has_presence = self.signed_presence_sha256.is_some();
        if has_activation && has_presence && !self.present {
            bail!("authenticated runtime session cannot be projected as not Present");
        }
        if has_activation != has_presence && self.disagreements.is_empty() {
            bail!("partial or rejected runtime evidence lacks an explicit disagreement");
        }
        if self.ready
            && (!self.present
                || self.observed_presence_state.as_deref() != Some("active")
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

/// An in-memory activation-scoped signer reconstructed by the launched service
/// from its protected systemd credential. The stable service identity never
/// receives this key, and the public activation record never contains it.
pub struct IdunnRuntimeActivationSigner {
    signing_key: SigningKey,
}

impl IdunnRuntimeActivationSigner {
    fn generate() -> Self {
        let mut seed = Zeroizing::new([0_u8; 32]);
        rand::rng().fill_bytes(seed.as_mut());
        Self {
            signing_key: SigningKey::from_bytes(&*seed),
        }
    }

    /// Open the exact raw 32-byte Ed25519 seed supplied through Idunn's systemd
    /// credential without retaining an ordinary heap copy. No persistent key
    /// schema exists: this authority lives for one activation and is replaced
    /// on every launch.
    pub fn from_credential_reader(mut credential: impl Read) -> Result<Self> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        credential
            .read_exact(seed.as_mut())
            .context("reading runtime activation credential")?;
        let mut extra = [0_u8; 1];
        if credential.read(&mut extra)? != 0 {
            bail!("runtime activation credential is longer than 32 bytes");
        }
        Ok(Self {
            signing_key: SigningKey::from_bytes(&*seed),
        })
    }

    fn write_credential(&self, mut destination: impl Write) -> Result<()> {
        let seed = Zeroizing::new(self.signing_key.to_bytes());
        destination
            .write_all(seed.as_ref())
            .context("writing runtime activation credential")
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    pub fn identity_id(&self) -> String {
        derive_idunn_runtime_activation_identity_id(&self.public_key())
            .expect("an Ed25519 activation signer always has a 32-byte public key")
    }

    pub fn sign_presence_proof(
        &self,
        presence: &GameCultRuntimePresenceHealthRecord,
    ) -> Result<Vec<u8>> {
        if presence.activation_signer_identity_id != self.identity_id() {
            bail!("runtime presence names a different activation signer");
        }
        let payload = presence.canonical_proof_payload()?;
        Ok(self
            .signing_key
            .sign(&runtime_activation_signing_message(&payload))
            .to_bytes()
            .to_vec())
    }
}

/// Idunn's one-shot launch material. Issuance always creates a fresh key, and
/// writing the protected credential consumes the only Idunn-side signer.
pub struct IdunnRuntimeActivationLaunch {
    activation: IdunnRuntimeActivationRecord,
    signer: IdunnRuntimeActivationSigner,
}

impl IdunnRuntimeActivationLaunch {
    pub fn issue(
        expected: &IdunnExpectedIncarnationRecord,
        runtime_instance_id: String,
        issued_at_unix_millis: u64,
        idunn_signer: &crate::ServiceIdentitySigner<crate::IdunnServiceIdentity>,
    ) -> Result<Self> {
        let signer = IdunnRuntimeActivationSigner::generate();
        let activation = IdunnRuntimeActivationRecord::issue_with_signer(
            expected,
            runtime_instance_id,
            &signer,
            issued_at_unix_millis,
            idunn_signer,
        )?;
        Ok(Self { activation, signer })
    }

    pub fn activation(&self) -> &IdunnRuntimeActivationRecord {
        &self.activation
    }

    pub fn write_credential(self, destination: impl Write) -> Result<IdunnRuntimeActivationRecord> {
        self.signer.write_credential(destination)?;
        Ok(self.activation)
    }
}

/// Derive the activation-scoped identity from the Idunn-issued public key. The
/// domain is dedicated to runtime activation and cannot be substituted for a
/// stable provider, Idunn, or Odin service identity.
pub fn derive_idunn_runtime_activation_identity_id(public_key: &[u8]) -> Result<String> {
    if public_key.len() != 32 {
        bail!("runtime activation public key has invalid length");
    }
    Ok(format!(
        "{:x}",
        Sha256::digest([IDUNN_RUNTIME_ACTIVATION_ID_DOMAIN, public_key].concat())
    ))
}

/// Current Idunn authority for one launch. Idunn's stable signature binds the
/// complete Expected digest and activation key; Expected in turn pins the
/// provider signer identity. The provider public key is lookup material, not a
/// second authority: its profile-derived identity must equal Idunn's signed
/// selection exactly.
#[derive(Clone, Debug)]
pub struct VerifiedRuntimeAuthority {
    expected: IdunnExpectedIncarnationRecord,
    activation: IdunnRuntimeActivationRecord,
    provider_signer_public_key: Vec<u8>,
    expected_sha256: String,
    activation_sha256: String,
}

impl VerifiedRuntimeAuthority {
    pub fn expected(&self) -> &IdunnExpectedIncarnationRecord {
        &self.expected
    }

    pub fn activation(&self) -> &IdunnRuntimeActivationRecord {
        &self.activation
    }

    pub fn expected_sha256(&self) -> &str {
        &self.expected_sha256
    }

    pub fn activation_sha256(&self) -> &str {
        &self.activation_sha256
    }
}

pub fn verify_runtime_authority(
    expected: &IdunnExpectedIncarnationRecord,
    activation: &IdunnRuntimeActivationRecord,
    idunn_anchor: &crate::ServiceIdentityTrustAnchor,
    provider_signer_public_key: &[u8],
) -> Result<VerifiedRuntimeAuthority> {
    expected.validate()?;
    activation.verify_for_expected(expected, idunn_anchor)?;
    if crate::derive_service_identity_id::<crate::GameCultProviderHealthIdentity>(
        provider_signer_public_key,
    )? != expected.expected_signer_identity_id
    {
        bail!("provider public key is not Idunn's Expected signer selection");
    }
    Ok(VerifiedRuntimeAuthority {
        expected: expected.clone(),
        activation: activation.clone(),
        provider_signer_public_key: provider_signer_public_key.to_vec(),
        expected_sha256: expected.canonical_sha256()?,
        activation_sha256: activation.canonical_sha256()?,
    })
}

#[derive(Clone, Copy, Debug)]
pub struct RuntimePresenceAuthenticationContext {
    pub trusted_received_at_unix_millis: u64,
    pub maximum_age_millis: u64,
    pub maximum_future_skew_millis: u64,
}

/// Canonical runtime bytes authenticated by both the Expected provider key and
/// the current activation key. No semantic claim has yet been accepted as
/// Present; Odin must correlate this observation against current authority.
#[derive(Clone, Debug)]
pub struct AuthenticatedRuntimePresenceClaim {
    record: GameCultRuntimePresenceHealthRecord,
    canonical_bytes: Vec<u8>,
    signed_presence_sha256: String,
    received_at_unix_millis: u64,
}

impl AuthenticatedRuntimePresenceClaim {
    pub fn record(&self) -> &GameCultRuntimePresenceHealthRecord {
        &self.record
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn signed_presence_sha256(&self) -> &str {
        &self.signed_presence_sha256
    }

    pub fn received_at_unix_millis(&self) -> u64 {
        self.received_at_unix_millis
    }
}

/// A signed Odin receipt authenticated against the exact current Expected,
/// activation, write lease, Idunn-admitted topology key, and trusted receipt
/// time. This is evidence, not a replay cursor or route-promotion grant. The
/// caller must source the key from Idunn's admitted Odin binding. Idunn's
/// durable admission owner must atomically check and advance Odin's publisher
/// sequence before treating the receipt as current.
#[derive(Clone, Debug)]
pub struct AuthenticatedOdinRuntimeTopologyCorrelation {
    record: OdinRuntimeTopologyCorrelationRecord,
    canonical_bytes: Vec<u8>,
}

impl AuthenticatedOdinRuntimeTopologyCorrelation {
    pub fn record(&self) -> &OdinRuntimeTopologyCorrelationRecord {
        &self.record
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

#[derive(Clone, Copy, Debug)]
pub struct OdinTopologyAuthenticationContext {
    pub trusted_received_at_unix_millis: u64,
    pub maximum_age_millis: u64,
    pub maximum_future_skew_millis: u64,
}

pub fn authenticate_odin_runtime_topology_correlation(
    canonical_correlation: &[u8],
    authority: &VerifiedRuntimeAuthority,
    current_write_lease_sha256: Option<&str>,
    admitted_odin_signer_public_key: &[u8],
    context: OdinTopologyAuthenticationContext,
) -> Result<AuthenticatedOdinRuntimeTopologyCorrelation> {
    ensure!(
        context.trusted_received_at_unix_millis > 0 && context.maximum_age_millis > 0,
        "Odin topology trusted time and maximum age must be positive"
    );
    let (record, unsigned) = OdinRuntimeTopologyCorrelationRecord::decode_canonical_signed_payload(
        canonical_correlation,
    )?;
    record.validate_against_expected(authority.expected(), current_write_lease_sha256)?;
    if record.current_activation_sha256.as_deref() != Some(authority.activation_sha256())
        || record.runtime_instance_id.as_deref()
            != Some(authority.activation.runtime_instance_id.as_str())
    {
        bail!("topology correlation does not bind the current activation");
    }
    let latest_trusted_timestamp = context
        .trusted_received_at_unix_millis
        .saturating_add(context.maximum_future_skew_millis);
    if record.observed_at_unix_millis > latest_trusted_timestamp
        || context
            .trusted_received_at_unix_millis
            .saturating_sub(record.observed_at_unix_millis)
            > context.maximum_age_millis
    {
        bail!("Odin topology correlation is outside the trusted observation window");
    }
    crate::verify_service_identity_signature_with_public_key::<
        crate::OdinTopologyIdentity,
        crate::OdinRuntimeTopologyCorrelationPurpose,
    >(
        admitted_odin_signer_public_key,
        &unsigned,
        &crate::ServiceIdentitySignature {
            identity_id: record.signer_identity_id.clone(),
            signature: record.signature.clone(),
        },
    )?;
    Ok(AuthenticatedOdinRuntimeTopologyCorrelation {
        record,
        canonical_bytes: canonical_correlation.to_vec(),
    })
}

/// Odin's deterministic interpretation of an authenticated provider claim.
/// Authentication of the stable provider and current activation establishes
/// Present. Correlation disagreements remain explicit and deny Ready; they do
/// not erase the observed session that produced them.
#[derive(Clone, Debug)]
pub struct RuntimePresenceCorrelation {
    presence: VerifiedRuntimePresence,
    disagreements: Vec<OdinTopologyDisagreement>,
}

impl RuntimePresenceCorrelation {
    pub fn claim(&self) -> &AuthenticatedRuntimePresenceClaim {
        &self.presence.claim
    }

    pub fn disagreements(&self) -> &[OdinTopologyDisagreement] {
        &self.disagreements
    }

    pub fn into_present(self) -> VerifiedRuntimePresence {
        self.presence
    }

    pub fn into_undisputed_present(self) -> Result<VerifiedRuntimePresence> {
        if !self.disagreements.is_empty() {
            bail!("runtime presence disagrees with current Expected projection");
        }
        Ok(self.presence)
    }
}

/// A dual-authenticated claim that matches current authority. This is the only
/// value that represents semantic Present. Replay admission deliberately does
/// not live here: Odin's durable store must atomically check and advance every
/// authenticated provider sequence, including disagreement-bearing claims,
/// before it signs a topology correlation.
#[derive(Clone, Debug)]
pub struct VerifiedRuntimePresence {
    claim: AuthenticatedRuntimePresenceClaim,
}

impl VerifiedRuntimePresence {
    pub fn record(&self) -> &GameCultRuntimePresenceHealthRecord {
        self.claim.record()
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        self.claim.canonical_bytes()
    }

    pub fn signed_presence_sha256(&self) -> &str {
        self.claim.signed_presence_sha256()
    }

    pub fn accepted_at_unix_millis(&self) -> u64 {
        self.claim.received_at_unix_millis()
    }
}

pub fn authenticate_runtime_presence_claim(
    canonical_presence: &[u8],
    authority: &VerifiedRuntimeAuthority,
    context: RuntimePresenceAuthenticationContext,
) -> Result<AuthenticatedRuntimePresenceClaim> {
    ensure!(
        context.trusted_received_at_unix_millis > 0 && context.maximum_age_millis > 0,
        "runtime presence trusted time and maximum age must be positive"
    );
    if messagepack_array_len(canonical_presence) != Some(24) {
        bail!("runtime presence payload is not the 24-field positional contract");
    }
    let presence: GameCultRuntimePresenceHealthRecord =
        rmp_serde::from_slice(canonical_presence).context("decoding runtime presence health")?;
    if rmp_serde::to_vec(&presence)? != canonical_presence {
        bail!("runtime presence payload is not canonical positional MessagePack");
    }
    presence.validate()?;
    let latest_trusted_timestamp = context
        .trusted_received_at_unix_millis
        .saturating_add(context.maximum_future_skew_millis);
    if presence.observed_at_unix_millis > latest_trusted_timestamp
        || authority.activation.issued_at_unix_millis > latest_trusted_timestamp
        || context
            .trusted_received_at_unix_millis
            .saturating_sub(presence.observed_at_unix_millis)
            > context.maximum_age_millis
    {
        bail!("runtime presence is outside the trusted observation window");
    }
    if presence.signer_identity_id != authority.expected.expected_signer_identity_id {
        bail!("runtime presence signer is not Idunn's Expected signer selection");
    }

    let proof_payload = presence.canonical_proof_payload()?;
    crate::verify_service_identity_signature_with_public_key::<
        crate::GameCultProviderHealthIdentity,
        crate::GameCultRuntimePresenceHealthPurpose,
    >(
        &authority.provider_signer_public_key,
        &proof_payload,
        &crate::ServiceIdentitySignature {
            identity_id: presence.signer_identity_id.clone(),
            signature: presence.signature.clone(),
        },
    )?;
    let activation_public_key: [u8; 32] = authority
        .activation
        .activation_signer_public_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("runtime activation public key has invalid length"))?;
    let activation_signature = Signature::from_slice(&presence.activation_signature)
        .map_err(|_| anyhow::anyhow!("runtime activation signature has invalid length"))?;
    VerifyingKey::from_bytes(&activation_public_key)?
        .verify(
            &runtime_activation_signing_message(&proof_payload),
            &activation_signature,
        )
        .map_err(|_| anyhow::anyhow!("runtime activation proof verification failed"))?;

    Ok(AuthenticatedRuntimePresenceClaim {
        record: presence,
        canonical_bytes: canonical_presence.to_vec(),
        signed_presence_sha256: prefixed_sha256(canonical_presence),
        received_at_unix_millis: context.trusted_received_at_unix_millis,
    })
}

pub fn correlate_runtime_presence_claim(
    claim: AuthenticatedRuntimePresenceClaim,
    authority: &VerifiedRuntimeAuthority,
) -> Result<RuntimePresenceCorrelation> {
    let expected = authority.expected();
    let activation = authority.activation();
    let presence = claim.record();
    let expected_endpoint = expected
        .route
        .as_ref()
        .map(|route| route.candidate_endpoint.clone());
    let mut disagreements = Vec::new();
    push_disagreement(
        &mut disagreements,
        "activation-signer-identity",
        Some(&activation.activation_signer_identity_id),
        Some(&presence.activation_signer_identity_id),
    );
    push_disagreement(
        &mut disagreements,
        "activation-witness",
        Some(authority.activation_sha256()),
        Some(&presence.activation_witness_sha256),
    );
    push_disagreement(
        &mut disagreements,
        "bound-endpoint",
        expected_endpoint.as_deref(),
        presence.bound_endpoint.as_deref(),
    );
    push_disagreement(
        &mut disagreements,
        "expected-projection",
        Some(authority.expected_sha256()),
        Some(&presence.expected_projection_sha256),
    );
    push_disagreement(
        &mut disagreements,
        "health-contract",
        Some(&expected.health_contract),
        Some(&presence.health_contract),
    );
    push_disagreement(
        &mut disagreements,
        "incarnation-id",
        Some(&expected.incarnation_id),
        Some(&presence.incarnation_id),
    );
    push_disagreement(
        &mut disagreements,
        "plan-id",
        Some(&expected.plan_id),
        Some(&presence.plan_id),
    );
    push_disagreement(
        &mut disagreements,
        "runtime-id",
        Some(&expected.runtime_id),
        Some(&presence.runtime_id),
    );
    push_disagreement(
        &mut disagreements,
        "runtime-instance-id",
        Some(&activation.runtime_instance_id),
        Some(&presence.runtime_instance_id),
    );
    push_disagreement(
        &mut disagreements,
        "sealed-release-id",
        Some(&expected.sealed_release_id),
        Some(&presence.sealed_release_id),
    );
    push_disagreement(
        &mut disagreements,
        "signer-identity",
        Some(&expected.expected_signer_identity_id),
        Some(&presence.signer_identity_id),
    );
    push_disagreement(
        &mut disagreements,
        "state-contract",
        expected.state_contract_sha256.as_deref(),
        presence.state_contract_sha256.as_deref(),
    );
    push_disagreement(
        &mut disagreements,
        "state-schema-generation",
        expected.state_schema_generation.as_deref(),
        presence.state_schema_generation.as_deref(),
    );
    push_disagreement(
        &mut disagreements,
        "target",
        Some(&expected.target),
        Some(&presence.target),
    );
    if activation.issued_at_unix_millis > presence.observed_at_unix_millis {
        disagreements.push(OdinTopologyDisagreement {
            code: "activation-issued-after-presence".into(),
            expected: Some(format!("at-most:{}", presence.observed_at_unix_millis)),
            observed: Some(activation.issued_at_unix_millis.to_string()),
        });
    }
    correlate_capabilities(
        &mut disagreements,
        &expected.capabilities,
        &presence.capabilities,
    );
    disagreements.sort_by(|left, right| left.code.cmp(&right.code));
    validate_topology_disagreements(&disagreements)?;
    Ok(RuntimePresenceCorrelation {
        presence: VerifiedRuntimePresence { claim },
        disagreements,
    })
}

fn push_disagreement(
    disagreements: &mut Vec<OdinTopologyDisagreement>,
    code: &str,
    expected: Option<&str>,
    observed: Option<&str>,
) {
    if expected != observed {
        disagreements.push(OdinTopologyDisagreement {
            code: code.into(),
            expected: expected.map(str::to_string),
            observed: observed.map(str::to_string),
        });
    }
}

fn correlate_capabilities(
    disagreements: &mut Vec<OdinTopologyDisagreement>,
    expected: &[IdunnExpectedCapability],
    observed: &[GameCultRuntimeCapability],
) {
    for (index, required) in expected.iter().enumerate() {
        let actual = observed
            .iter()
            .find(|actual| actual.identity() == required.identity());
        let requirement = format!(
            "{}/{}/{} capacity>={}",
            required.capability, required.schema, required.compatibility, required.minimum_capacity
        );
        match actual {
            None => disagreements.push(OdinTopologyDisagreement {
                code: format!("expected-capability-{index:03}-missing"),
                expected: Some(requirement),
                observed: None,
            }),
            Some(actual) if actual.capacity < required.minimum_capacity => {
                disagreements.push(OdinTopologyDisagreement {
                    code: format!("expected-capability-{index:03}-capacity"),
                    expected: Some(requirement),
                    observed: Some(format!("capacity={}", actual.capacity)),
                });
            }
            Some(_) => {}
        }
    }
}

fn runtime_activation_signing_message(payload: &[u8]) -> Vec<u8> {
    let purpose = GAMECULT_RUNTIME_ACTIVATION_PROOF_SIGNING_PURPOSE.as_bytes();
    let mut out = Vec::with_capacity(
        IDUNN_RUNTIME_ACTIVATION_SIGNATURE_DOMAIN.len() + purpose.len() + payload.len() + 16,
    );
    out.extend_from_slice(IDUNN_RUNTIME_ACTIVATION_SIGNATURE_DOMAIN);
    out.extend_from_slice(&(purpose.len() as u64).to_be_bytes());
    out.extend_from_slice(purpose);
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Idunn-issued launch identity. Idunn's stable service identity signs the
/// complete activation, including the ephemeral public key, before the private
/// credential is passed to one workload alongside Expected. Odin still treats
/// it as current only after Idunn publishes an observed native process.
#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(
    type = "idunn.runtime_activation",
    schema = "idunn.runtime_activation.v2"
)]
pub struct IdunnRuntimeActivationRecord {
    #[cultcache(key = 0)]
    pub schema_version: String,
    #[cultcache(key = 1)]
    pub expected_projection_sha256: String,
    #[cultcache(key = 2)]
    pub runtime_id: String,
    #[cultcache(key = 3)]
    pub runtime_instance_id: String,
    #[cultcache(key = 4)]
    pub activation_signer_identity_id: String,
    #[cultcache(key = 5, bytes)]
    pub activation_signer_public_key: Vec<u8>,
    #[cultcache(key = 6)]
    pub issued_at_unix_millis: u64,
    #[cultcache(key = 7)]
    pub idunn_signer_identity_id: String,
    #[cultcache(key = 8)]
    pub signature_algorithm: String,
    #[cultcache(key = 9, bytes)]
    pub signature: Vec<u8>,
}

impl IdunnRuntimeActivationRecord {
    fn issue_with_signer(
        expected: &IdunnExpectedIncarnationRecord,
        runtime_instance_id: String,
        activation_signer: &IdunnRuntimeActivationSigner,
        issued_at_unix_millis: u64,
        idunn_signer: &crate::ServiceIdentitySigner<crate::IdunnServiceIdentity>,
    ) -> Result<Self> {
        expected.validate()?;
        let mut activation = Self {
            schema_version: IDUNN_RUNTIME_ACTIVATION_SCHEMA.into(),
            expected_projection_sha256: expected.canonical_sha256()?,
            runtime_id: expected.runtime_id.clone(),
            runtime_instance_id,
            activation_signer_identity_id: activation_signer.identity_id(),
            activation_signer_public_key: activation_signer.public_key(),
            issued_at_unix_millis,
            idunn_signer_identity_id: idunn_signer.entry().identity_id.clone(),
            signature_algorithm: "ed25519".into(),
            signature: Vec::new(),
        };
        let proof = idunn_signer.sign::<crate::IdunnRuntimeActivationPurpose>(
            &activation.unsigned_signature_payload()?,
        );
        activation.signature = proof.signature;
        activation.validate()?;
        Ok(activation)
    }

    pub fn decode_canonical(payload: &[u8]) -> Result<Self> {
        if messagepack_array_len(payload) != Some(10) {
            bail!("runtime activation is not the 10-field positional contract");
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

    pub fn unsigned_signature_payload(&self) -> Result<Vec<u8>> {
        self.validate_shape(true)?;
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok(rmp_serde::to_vec(&unsigned)?)
    }

    pub fn verify_for_expected(
        &self,
        expected: &IdunnExpectedIncarnationRecord,
        idunn_anchor: &crate::ServiceIdentityTrustAnchor,
    ) -> Result<()> {
        self.validate()?;
        expected.validate()?;
        if self.expected_projection_sha256 != expected.canonical_sha256()?
            || self.runtime_id != expected.runtime_id
        {
            bail!("runtime activation does not bind the current Expected incarnation");
        }
        crate::verify_service_identity_signature::<
            crate::IdunnServiceIdentity,
            crate::IdunnRuntimeActivationPurpose,
        >(
            idunn_anchor,
            &self.unsigned_signature_payload()?,
            &crate::ServiceIdentitySignature {
                identity_id: self.idunn_signer_identity_id.clone(),
                signature: self.signature.clone(),
            },
        )
        .context("verifying Idunn runtime activation signature")
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_shape(false)
    }

    fn validate_shape(&self, allow_unsigned: bool) -> Result<()> {
        if self.schema_version != IDUNN_RUNTIME_ACTIVATION_SCHEMA {
            bail!("runtime activation schema is unsupported");
        }
        validate_required_sha256(
            &self.expected_projection_sha256,
            "activation expected projection sha256",
        )?;
        validate_authority_identifier(&self.runtime_id, "activation runtime id")?;
        validate_required_sha256(&self.runtime_instance_id, "runtime instance id")?;
        validate_authority_identifier(
            &self.activation_signer_identity_id,
            "activation signer identity id",
        )?;
        if self.activation_signer_identity_id
            != derive_idunn_runtime_activation_identity_id(&self.activation_signer_public_key)?
        {
            bail!("runtime activation signer identity does not match its public key");
        }
        validate_authority_identifier(
            &self.idunn_signer_identity_id,
            "Idunn activation signer identity id",
        )?;
        let signature_is_valid =
            self.signature.len() == 64 || (allow_unsigned && self.signature.is_empty());
        if self.issued_at_unix_millis == 0
            || self.signature_algorithm != "ed25519"
            || !signature_is_valid
        {
            bail!("runtime activation issue time or signature is invalid");
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

fn validate_expected_capabilities(capabilities: &[IdunnExpectedCapability]) -> Result<()> {
    if capabilities.len() > MAX_RUNTIME_CAPABILITIES {
        bail!("Expected capability count exceeds its contract bound");
    }
    let mut previous: Option<(&str, &str, &str)> = None;
    for capability in capabilities {
        validate_authority_identifier(&capability.capability, "Expected capability")?;
        validate_authority_identifier(&capability.schema, "Expected capability schema")?;
        validate_authority_identifier(
            &capability.compatibility,
            "Expected capability compatibility",
        )?;
        if capability.minimum_capacity == 0 {
            bail!("Expected capability minimum capacity is zero");
        }
        let identity = capability.identity();
        if previous.is_some_and(|previous| previous >= identity) {
            bail!("Expected capabilities are not strictly sorted and unique");
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
        ServiceIdentitySigner, ServiceSignaturePurpose, derive_service_identity_id,
        enroll_service_identity_at, verify_service_identity_signature,
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

    fn expected_capability(name: &str) -> IdunnExpectedCapability {
        IdunnExpectedCapability {
            capability: name.into(),
            schema: format!("{name}.v1"),
            compatibility: "v1".into(),
            minimum_capacity: 1,
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
            activation_signer_identity_id: "activation-signing-key".into(),
            activation_signature: vec![7; 64],
        }
    }

    fn runtime_activation() -> IdunnRuntimeActivationRecord {
        let signer = IdunnRuntimeActivationSigner::from_credential_reader(&[8; 32][..]).unwrap();
        IdunnRuntimeActivationRecord {
            schema_version: IDUNN_RUNTIME_ACTIVATION_SCHEMA.into(),
            expected_projection_sha256: digest('9'),
            runtime_id: "ghostlight-yggdrasil-1".into(),
            runtime_instance_id: digest('8'),
            activation_signer_identity_id: signer.identity_id(),
            activation_signer_public_key: signer.public_key(),
            issued_at_unix_millis: 99,
            idunn_signer_identity_id: "idunn-signing-key".into(),
            signature_algorithm: "ed25519".into(),
            signature: vec![5; 64],
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
                expected_capability("conversation"),
                expected_capability("state"),
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
            observed_presence_state: Some("active".into()),
            observed_presence_publisher_sequence: Some(1),
            observed_write_lease_sha256: Some(digest('c')),
            observed_capabilities: expected
                .capabilities
                .iter()
                .map(|capability| GameCultRuntimeCapability {
                    capability: capability.capability.clone(),
                    schema: capability.schema.clone(),
                    compatibility: capability.compatibility.clone(),
                    capacity: capability.minimum_capacity,
                })
                .collect(),
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

    fn validate_against_current_lease(
        receipt: &OdinRuntimeTopologyCorrelationRecord,
        expected: &IdunnExpectedIncarnationRecord,
    ) -> Result<()> {
        let current_lease = digest('c');
        receipt.validate_against_expected(expected, Some(&current_lease))
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

    struct DualProofFixture {
        stable_signer: ServiceIdentitySigner<GameCultProviderHealthIdentity>,
        activation_signer: IdunnRuntimeActivationSigner,
        odin_signer: ServiceIdentitySigner<OdinTopologyIdentity>,
        idunn_anchor: crate::ServiceIdentityTrustAnchor,
        stable_public_key: Vec<u8>,
        odin_anchor: GameCultServiceTrustAnchorRecord,
        expected: IdunnExpectedIncarnationRecord,
        activation: IdunnRuntimeActivationRecord,
        presence: GameCultRuntimePresenceHealthRecord,
    }

    fn dual_proof_fixture(identity_path: &std::path::Path) -> Result<DualProofFixture> {
        let stable_signer =
            enroll_service_identity_at::<GameCultProviderHealthIdentity>(identity_path)?;
        let stable_public = stable_signer.trust_anchor()?;
        let idunn_signer = enroll_service_identity_at::<IdunnServiceIdentity>(
            &identity_path.with_extension("idunn.cc"),
        )?;
        let idunn_anchor = idunn_signer.trust_anchor()?;
        let odin_signer = enroll_service_identity_at::<OdinTopologyIdentity>(
            &identity_path.with_extension("odin.cc"),
        )?;
        let odin_public = odin_signer.trust_anchor()?;
        let mut expected = expected_incarnation();
        expected.expected_signer_identity_id = stable_public.identity_id.clone();
        expected.capabilities[0].minimum_capacity = 2;
        let launch =
            IdunnRuntimeActivationLaunch::issue(&expected, digest('8'), 99, &idunn_signer)?;
        let activation = launch.activation().clone();
        let mut activation_credential = Vec::new();
        assert_eq!(
            launch.write_credential(&mut activation_credential)?,
            activation
        );
        let activation_signer =
            IdunnRuntimeActivationSigner::from_credential_reader(&activation_credential[..])?;

        let stable_public_key = stable_public.public_key.clone();
        let odin_anchor = GameCultServiceTrustAnchorRecord {
            schema_version: GAMECULT_SERVICE_TRUST_ANCHOR_SCHEMA.into(),
            trust_anchor_id: "root/odin/runtime-topology".into(),
            service_id: "odin".into(),
            runtime_id: "odin-yggdrasil-1".into(),
            signer_identity_id: odin_public.identity_id,
            signer_public_key: odin_public.public_key,
            signature_algorithm: "ed25519".into(),
            signing_purpose: ODIN_RUNTIME_TOPOLOGY_CORRELATION_SIGNING_PURPOSE.into(),
            signed_schema: ODIN_RUNTIME_TOPOLOGY_CORRELATION_SCHEMA.into(),
            binding_authority: "root".into(),
            bound_at_unix_millis: 1,
            expires_at_unix_millis: Some(1_000),
            private_state_exposed: false,
        };

        let mut presence = runtime_presence();
        presence.target = expected.target.clone();
        presence.plan_id = expected.plan_id.clone();
        presence.incarnation_id = expected.incarnation_id.clone();
        presence.sealed_release_id = expected.sealed_release_id.clone();
        presence.state_schema_generation = expected.state_schema_generation.clone();
        presence.state_contract_sha256 = expected.state_contract_sha256.clone();
        presence.bound_endpoint = expected
            .route
            .as_ref()
            .map(|route| route.candidate_endpoint.clone());
        presence.capabilities = expected
            .capabilities
            .iter()
            .map(|capability| GameCultRuntimeCapability {
                capability: capability.capability.clone(),
                schema: capability.schema.clone(),
                compatibility: capability.compatibility.clone(),
                capacity: capability.minimum_capacity,
            })
            .collect();
        presence.health_contract = expected.health_contract.clone();
        presence.runtime_id = activation.runtime_id.clone();
        presence.runtime_instance_id = activation.runtime_instance_id.clone();
        presence.expected_projection_sha256 = activation.expected_projection_sha256.clone();
        presence.activation_witness_sha256 = activation.canonical_sha256()?;
        presence.signer_identity_id = stable_public.identity_id;
        presence.activation_signer_identity_id = activation_signer.identity_id();
        presence.observed_at_unix_millis = 110;
        presence.signature.clear();
        presence.activation_signature.clear();
        let proof_payload = presence.canonical_proof_payload()?;
        presence.signature = stable_signer
            .sign::<GameCultRuntimePresenceHealthPurpose>(&proof_payload)
            .signature;
        presence.activation_signature = activation_signer.sign_presence_proof(&presence)?;

        Ok(DualProofFixture {
            stable_signer,
            activation_signer,
            odin_signer,
            idunn_anchor,
            stable_public_key,
            odin_anchor,
            expected,
            activation,
            presence,
        })
    }

    fn resign_presence(fixture: &mut DualProofFixture) -> Result<Vec<u8>> {
        fixture.presence.signature.clear();
        fixture.presence.activation_signature.clear();
        let proof_payload = fixture.presence.canonical_proof_payload()?;
        fixture.presence.signature = fixture
            .stable_signer
            .sign::<GameCultRuntimePresenceHealthPurpose>(&proof_payload)
            .signature;
        fixture.presence.activation_signature = fixture
            .activation_signer
            .sign_presence_proof(&fixture.presence)?;
        Ok(rmp_serde::to_vec(&fixture.presence)?)
    }

    fn fixture_authority(fixture: &DualProofFixture) -> Result<VerifiedRuntimeAuthority> {
        verify_runtime_authority(
            &fixture.expected,
            &fixture.activation,
            &fixture.idunn_anchor,
            &fixture.stable_public_key,
        )
    }

    fn authenticate_fixture(
        fixture: &DualProofFixture,
    ) -> Result<AuthenticatedRuntimePresenceClaim> {
        authenticate_runtime_presence_claim(
            &rmp_serde::to_vec(&fixture.presence)?,
            &fixture_authority(fixture)?,
            RuntimePresenceAuthenticationContext {
                trusted_received_at_unix_millis: 120,
                maximum_age_millis: 30,
                maximum_future_skew_millis: 5,
            },
        )
    }

    fn correlate_fixture(fixture: &DualProofFixture) -> Result<RuntimePresenceCorrelation> {
        correlate_runtime_presence_claim(
            authenticate_fixture(fixture)?,
            &fixture_authority(fixture)?,
        )
    }

    fn verify_fixture(fixture: &DualProofFixture) -> Result<VerifiedRuntimePresence> {
        correlate_fixture(fixture)?.into_undisputed_present()
    }

    fn authenticated_topology_receipt(
        fixture: &DualProofFixture,
        presence: &VerifiedRuntimePresence,
        present: bool,
        disagreements: Vec<OdinTopologyDisagreement>,
    ) -> Result<AuthenticatedOdinRuntimeTopologyCorrelation> {
        let authority = fixture_authority(fixture)?;
        let mut receipt = topology_correlation(&fixture.expected);
        receipt.current_activation_sha256 = Some(authority.activation_sha256().into());
        receipt.signed_presence_sha256 = Some(presence.signed_presence_sha256().into());
        receipt.observed_presence_state = Some(presence.record().state.clone());
        receipt.observed_presence_publisher_sequence = Some(presence.record().publisher_sequence);
        receipt.observed_write_lease_sha256 = presence.record().write_lease_sha256.clone();
        receipt.observed_capabilities = presence.record().capabilities.clone();
        receipt.runtime_instance_id = Some(fixture.activation.runtime_instance_id.clone());
        receipt.present = present;
        receipt.ready = present && presence.record().state == "active";
        receipt.disagreements = disagreements;
        receipt.signer_identity_id = fixture.odin_anchor.signer_identity_id.clone();
        receipt.signature.clear();
        receipt.signature = fixture
            .odin_signer
            .sign::<OdinRuntimeTopologyCorrelationPurpose>(&receipt.unsigned_signature_payload()?)
            .signature;
        let encoded = receipt.canonical_bytes()?;
        authenticate_odin_runtime_topology_correlation(
            &encoded,
            &authority,
            presence.record().write_lease_sha256.as_deref(),
            &fixture.odin_anchor.signer_public_key,
            OdinTopologyAuthenticationContext {
                trusted_received_at_unix_millis: 120,
                maximum_age_millis: 30,
                maximum_future_skew_millis: 5,
            },
        )
    }

    #[test]
    fn runtime_authority_contracts_round_trip_as_canonical_positional_records() -> Result<()> {
        let presence = runtime_presence();
        presence.validate()?;
        let encoded_presence = rmp_serde::to_vec(&presence)?;
        assert_eq!(messagepack_array_len(&encoded_presence), Some(24));
        let decoded_presence: GameCultRuntimePresenceHealthRecord =
            rmp_serde::from_slice(&encoded_presence)?;
        assert_eq!(decoded_presence, presence);
        let unsigned = presence.canonical_proof_payload()?;
        let unsigned_presence: GameCultRuntimePresenceHealthRecord =
            rmp_serde::from_slice(&unsigned)?;
        assert!(unsigned_presence.signature.is_empty());
        assert!(unsigned_presence.activation_signature.is_empty());

        let activation = runtime_activation();
        let encoded_activation = activation.canonical_bytes()?;
        assert_eq!(messagepack_array_len(&encoded_activation), Some(10));
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
    fn exact_stable_and_activation_proofs_admit_runtime_presence() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let fixture = dual_proof_fixture(&temp.path().join("runtime-presence.cc"))?;
        assert_eq!(fixture.activation.activation_signer_public_key.len(), 32);
        let verified = verify_fixture(&fixture)?;
        assert_eq!(verified.record(), &fixture.presence);
        Ok(())
    }

    #[test]
    fn authenticated_expected_disagreements_remain_typed_present_and_not_ready() -> Result<()> {
        type Mutation = fn(&mut GameCultRuntimePresenceHealthRecord);
        let cases: &[(&str, &str, Mutation)] = &[
            ("target", "target", |value| value.target = "epiphany".into()),
            ("projection", "expected-projection", |value| {
                value.expected_projection_sha256 = digest('0')
            }),
            ("plan", "plan-id", |value| value.plan_id = digest('0')),
            ("incarnation", "incarnation-id", |value| {
                value.incarnation_id = "ghostlight/other/1".into()
            }),
            ("release", "sealed-release-id", |value| {
                value.sealed_release_id = digest('0')
            }),
            ("runtime", "runtime-id", |value| {
                value.runtime_id = "ghostlight-other-runtime".into()
            }),
            ("process", "runtime-instance-id", |value| {
                value.runtime_instance_id = digest('0')
            }),
            ("endpoint", "bound-endpoint", |value| {
                value.bound_endpoint = Some("http://127.0.0.1:14104".into())
            }),
            ("health", "health-contract", |value| {
                value.health_contract = "ghostlight.other-health.v1".into()
            }),
            ("state-generation", "state-schema-generation", |value| {
                value.state_schema_generation = Some("world-v3".into())
            }),
            ("state-contract", "state-contract", |value| {
                value.state_contract_sha256 = Some(digest('0'))
            }),
            ("activation", "activation-witness", |value| {
                value.activation_witness_sha256 = digest('0')
            }),
        ];

        let temp = tempfile::tempdir()?;
        for (name, expected_code, mutate) in cases {
            let mut fixture = dual_proof_fixture(&temp.path().join(format!("{name}.cc")))?;
            mutate(&mut fixture.presence);
            resign_presence(&mut fixture)?;
            let correlation = correlate_fixture(&fixture)?;
            assert!(
                correlation
                    .disagreements()
                    .iter()
                    .any(|disagreement| disagreement.code == *expected_code),
                "missing {expected_code} disagreement for {name}"
            );
            assert_eq!(
                correlation.claim().record().runtime_instance_id,
                fixture.presence.runtime_instance_id
            );
            assert!(correlation.into_undisputed_present().is_err());
        }
        Ok(())
    }

    #[test]
    fn provider_owns_observed_capacity_while_expected_owns_only_the_minimum() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut fixture = dual_proof_fixture(&temp.path().join("runtime-presence.cc"))?;
        fixture.presence.capabilities[0].capacity = 50;
        fixture
            .presence
            .capabilities
            .push(runtime_capability("telemetry"));
        resign_presence(&mut fixture)?;
        verify_fixture(&fixture)?;

        fixture.presence.capabilities[0].capacity = 1;
        fixture
            .presence
            .capabilities
            .retain(|capability| capability.capability != "state");
        resign_presence(&mut fixture)?;
        let correlation = correlate_fixture(&fixture)?;
        let codes = correlation
            .disagreements()
            .iter()
            .map(|disagreement| disagreement.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"expected-capability-000-capacity"));
        assert!(codes.contains(&"expected-capability-001-missing"));
        assert!(!codes.iter().any(|code| code.contains("unexpected")));
        Ok(())
    }

    #[test]
    fn stable_proof_and_provider_key_substitution_fail_closed() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut fixture = dual_proof_fixture(&temp.path().join("runtime-presence.cc"))?;
        fixture.presence.detail = "tampered after signing".into();
        assert!(authenticate_fixture(&fixture).is_err());

        let other_idunn = enroll_service_identity_at::<IdunnServiceIdentity>(
            &temp.path().join("other-idunn.cc"),
        )?;
        assert!(
            verify_runtime_authority(
                &fixture.expected,
                &fixture.activation,
                &other_idunn.trust_anchor()?,
                &fixture.stable_public_key,
            )
            .is_err()
        );

        fixture.stable_public_key = vec![9; 32];
        assert!(fixture_authority(&fixture).is_err());
        Ok(())
    }

    #[test]
    fn incumbent_stable_key_without_activation_key_cannot_claim_presence() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut fixture = dual_proof_fixture(&temp.path().join("runtime-presence.cc"))?;
        fixture.presence.activation_signature = vec![0; 64];
        let proof_payload = fixture.presence.canonical_proof_payload()?;
        fixture.presence.signature = fixture
            .stable_signer
            .sign::<GameCultRuntimePresenceHealthPurpose>(&proof_payload)
            .signature;

        let error = verify_fixture(&fixture).unwrap_err();
        assert!(error.to_string().contains("activation proof verification"));
        Ok(())
    }

    #[test]
    fn activation_cannot_substitute_another_expected_runtime_id() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut fixture = dual_proof_fixture(&temp.path().join("runtime-presence.cc"))?;
        fixture.activation.runtime_id = "ghostlight-yggdrasil-2".into();
        fixture.presence.runtime_id = fixture.activation.runtime_id.clone();
        fixture.presence.activation_witness_sha256 = fixture.activation.canonical_sha256()?;

        // The stable service key can re-sign the altered canonical statement,
        // but the activation proof still came from the other runtime id.
        let proof_payload = fixture.presence.canonical_proof_payload()?;
        fixture.presence.signature = fixture
            .stable_signer
            .sign::<GameCultRuntimePresenceHealthPurpose>(&proof_payload)
            .signature;
        let error = fixture_authority(&fixture).unwrap_err();
        assert!(error.to_string().contains("current Expected"));
        Ok(())
    }

    #[test]
    fn idunn_signature_prevents_provider_minted_activation() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut fixture = dual_proof_fixture(&temp.path().join("runtime-presence.cc"))?;
        fixture.activation.issued_at_unix_millis += 1;
        fixture.presence.activation_witness_sha256 = fixture.activation.canonical_sha256()?;
        resign_presence(&mut fixture)?;
        let error = fixture_authority(&fixture).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Idunn runtime activation signature")
        );
        Ok(())
    }

    #[test]
    fn authenticated_odin_receipt_is_fresh_evidence_not_replay_authority() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let fixture = dual_proof_fixture(&temp.path().join("runtime-presence.cc"))?;
        let authority = fixture_authority(&fixture)?;
        let presence = verify_fixture(&fixture)?;
        let accepted = authenticated_topology_receipt(&fixture, &presence, true, Vec::new())?;
        assert_eq!(
            accepted.record().observed_presence_publisher_sequence,
            Some(fixture.presence.publisher_sequence)
        );
        assert_eq!(
            accepted.record().signed_presence_sha256.as_deref(),
            Some(presence.signed_presence_sha256())
        );

        let mut tampered = accepted.record().clone();
        tampered.signature = vec![0; 64];
        assert!(
            authenticate_odin_runtime_topology_correlation(
                &tampered.canonical_bytes()?,
                &authority,
                presence.record().write_lease_sha256.as_deref(),
                &fixture.odin_anchor.signer_public_key,
                OdinTopologyAuthenticationContext {
                    trusted_received_at_unix_millis: 120,
                    maximum_age_millis: 30,
                    maximum_future_skew_millis: 5,
                },
            )
            .is_err()
        );
        assert!(
            authenticate_odin_runtime_topology_correlation(
                accepted.canonical_bytes(),
                &authority,
                presence.record().write_lease_sha256.as_deref(),
                &fixture.odin_anchor.signer_public_key,
                OdinTopologyAuthenticationContext {
                    trusted_received_at_unix_millis: 200,
                    maximum_age_millis: 30,
                    maximum_future_skew_millis: 5,
                },
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn separate_launches_receive_distinct_activation_identities() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let idunn =
            enroll_service_identity_at::<IdunnServiceIdentity>(&temp.path().join("idunn.cc"))?;
        let expected = expected_incarnation();
        let first = IdunnRuntimeActivationLaunch::issue(&expected, digest('8'), 99, &idunn)?;
        let second = IdunnRuntimeActivationLaunch::issue(&expected, digest('9'), 100, &idunn)?;
        assert_ne!(
            first.activation().activation_signer_identity_id,
            second.activation().activation_signer_identity_id
        );
        Ok(())
    }

    #[test]
    fn trusted_time_rejects_stale_and_future_presence() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let mut fixture = dual_proof_fixture(&temp.path().join("runtime-presence.cc"))?;
        let authority = fixture_authority(&fixture)?;
        let canonical = rmp_serde::to_vec(&fixture.presence)?;
        assert!(
            authenticate_runtime_presence_claim(
                &canonical,
                &authority,
                RuntimePresenceAuthenticationContext {
                    trusted_received_at_unix_millis: 200,
                    maximum_age_millis: 10,
                    maximum_future_skew_millis: 5,
                },
            )
            .is_err()
        );

        fixture.presence.observed_at_unix_millis = 126;
        resign_presence(&mut fixture)?;
        assert!(
            authenticate_runtime_presence_claim(
                &rmp_serde::to_vec(&fixture.presence)?,
                &authority,
                RuntimePresenceAuthenticationContext {
                    trusted_received_at_unix_millis: 120,
                    maximum_age_millis: 30,
                    maximum_future_skew_millis: 5,
                },
            )
            .is_err()
        );

        Ok(())
    }

    #[test]
    fn runtime_authority_decoders_reject_malformed_and_noncanonical_bytes() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let fixture = dual_proof_fixture(&temp.path().join("runtime-presence.cc"))?;
        assert!(
            authenticate_runtime_presence_claim(
                &[0x91, 0xc0],
                &fixture_authority(&fixture)?,
                RuntimePresenceAuthenticationContext {
                    trusted_received_at_unix_millis: 120,
                    maximum_age_millis: 30,
                    maximum_future_skew_millis: 5,
                },
            )
            .is_err()
        );
        assert!(IdunnRuntimeActivationRecord::decode_canonical(&[0x91, 0xc0]).is_err());
        assert!(IdunnProcessWriteLeaseRecord::decode_canonical(&[0x91, 0xc0]).is_err());

        let mut legacy_presence = fixture.presence.clone();
        legacy_presence.schema_version = "gamecult.runtime_presence_health.v1".into();
        assert!(
            authenticate_runtime_presence_claim(
                &rmp_serde::to_vec(&legacy_presence)?,
                &fixture_authority(&fixture)?,
                RuntimePresenceAuthenticationContext {
                    trusted_received_at_unix_millis: 120,
                    maximum_age_millis: 30,
                    maximum_future_skew_millis: 5,
                },
            )
            .is_err()
        );
        let mut legacy_activation = fixture.activation.clone();
        legacy_activation.schema_version = "idunn.runtime_activation.v1".into();
        assert!(
            IdunnRuntimeActivationRecord::decode_canonical(&rmp_serde::to_vec(&legacy_activation)?)
                .is_err()
        );
        let mut legacy_expected = fixture.expected.clone();
        legacy_expected.schema_version = "idunn.expected_incarnation.v1".into();
        assert!(
            IdunnExpectedIncarnationRecord::decode_canonical(&rmp_serde::to_vec(&legacy_expected)?)
                .is_err()
        );
        let mut legacy_topology = topology_correlation(&fixture.expected);
        legacy_topology.schema_version = "odin.runtime_topology_correlation.v1".into();
        assert!(
            OdinRuntimeTopologyCorrelationRecord::decode_canonical_signed_payload(
                &rmp_serde::to_vec(&legacy_topology)?,
            )
            .is_err()
        );

        let presence = rmp_serde::to_vec(&runtime_presence())?;
        assert_eq!(&presence[..3], &[0xdc, 0, 24]);
        let mut noncanonical_presence = vec![0xdd, 0, 0, 0, 24];
        noncanonical_presence.extend_from_slice(&presence[3..]);
        assert!(
            authenticate_runtime_presence_claim(
                &noncanonical_presence,
                &fixture_authority(&fixture)?,
                RuntimePresenceAuthenticationContext {
                    trusted_received_at_unix_millis: 120,
                    maximum_age_millis: 30,
                    maximum_future_skew_millis: 5,
                },
            )
            .is_err()
        );

        let activation = runtime_activation().canonical_bytes()?;
        assert_eq!(activation[0], 0x9a);
        let mut noncanonical_activation = vec![0xdc, 0, 10];
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

        let mut value = anchor.clone();
        value.signing_purpose = "gamecult.runtime_presence_health.v1".into();
        value.signed_schema = "gamecult.runtime_presence_health.v1".into();
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
        validate_against_current_lease(&receipt, &expected)?;
        let receipt_bytes = receipt.canonical_bytes()?;
        assert_eq!(&receipt_bytes[..3], &[0xdc, 0, 21]);
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
        let mut noncanonical_receipt = vec![0xdd, 0, 0, 0, 21];
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
        value.capabilities.push(expected_capability("state"));
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
    fn expected_route_keeps_rudp_distinct_and_scheme_exact() {
        let mut value = expected_incarnation();
        value.route = Some(IdunnExpectedRoute {
            route_id: "odin-rendezvous".into(),
            transport: "rudp".into(),
            stable_endpoint: "rudp://10.77.0.1:17871".into(),
            candidate_endpoint: "rudp://127.0.0.1:24171".into(),
        });
        assert!(value.validate().is_ok());

        value.route.as_mut().unwrap().candidate_endpoint = "tcp://127.0.0.1:24171".into();
        assert!(value.validate().is_err());

        value.route.as_mut().unwrap().candidate_endpoint = "udp://127.0.0.1:24171".into();
        assert!(value.validate().is_err());
    }

    #[test]
    fn topology_correlation_refuses_expected_substitution_and_dependency_omission() {
        let expected = expected_incarnation();

        let mut value = topology_correlation(&expected);
        value.target = "epiphany".into();
        assert!(value.validate().is_ok());
        assert!(validate_against_current_lease(&value, &expected).is_err());

        let mut value = topology_correlation(&expected);
        value.runtime_id = "ghostlight-other-runtime".into();
        assert!(validate_against_current_lease(&value, &expected).is_err());

        let mut value = topology_correlation(&expected);
        value.expected_projection_sha256 = digest('c');
        assert!(validate_against_current_lease(&value, &expected).is_err());

        let mut value = topology_correlation(&expected);
        value.dependencies.pop();
        assert!(value.validate().is_ok());
        assert!(validate_against_current_lease(&value, &expected).is_err());

        let mut value = topology_correlation(&expected);
        value.dependencies[0].provider_id = Some("odin-substitute".into());
        assert!(value.validate().is_ok());
        assert!(validate_against_current_lease(&value, &expected).is_err());

        let mut value = topology_correlation(&expected);
        value.dependencies[0].kind = "required".into();
        assert!(value.validate().is_ok());
        assert!(validate_against_current_lease(&value, &expected).is_err());

        let mut value = topology_correlation(&expected);
        value.dependencies[0].observed_capacity = Some(0);
        assert!(value.validate().is_err());

        let mut value = topology_correlation(&expected);
        value.dependencies[0].observed_capacity = Some(1);
        let mut stricter = expected.clone();
        stricter.dependencies[0].minimum_capacity = 2;
        value.expected_projection_sha256 = stricter.canonical_sha256().unwrap();
        assert!(validate_against_current_lease(&value, &stricter).is_err());
    }

    #[test]
    fn topology_correlation_requires_explicit_coherent_partial_states() {
        let expected = expected_incarnation();
        let mut value = topology_correlation(&expected);
        value.signed_presence_sha256 = None;
        value.observed_presence_state = None;
        value.observed_presence_publisher_sequence = None;
        value.observed_write_lease_sha256 = None;
        value.observed_capabilities.clear();
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
    fn topology_correlation_preserves_warming_and_exact_write_lease_authority() {
        let expected = expected_incarnation();
        let value = topology_correlation(&expected);
        validate_against_current_lease(&value, &expected).unwrap();
        assert!(
            value
                .validate_against_expected(&expected, Some(&digest('d')))
                .is_err()
        );
        assert!(value.validate_against_expected(&expected, None).is_err());

        let mut digest_only_ready = topology_correlation(&expected);
        digest_only_ready.observed_write_lease_sha256 = None;
        digest_only_ready.validate().unwrap();
        assert!(
            digest_only_ready
                .validate_against_expected(&expected, Some(&digest('c')))
                .is_err()
        );

        let mut warming = topology_correlation(&expected);
        warming.observed_presence_state = Some("warming".into());
        warming.ready = false;
        assert!(warming.validate().is_err());
        warming.observed_write_lease_sha256 = None;
        warming.validate().unwrap();
        warming.validate_against_expected(&expected, None).unwrap();
        warming.ready = true;
        assert!(warming.validate().is_err());

        let mut partial = topology_correlation(&expected);
        partial.observed_presence_state = None;
        assert!(partial.validate().is_err());
        let mut partial = topology_correlation(&expected);
        partial.signed_presence_sha256 = None;
        assert!(partial.validate().is_err());

        let mut stateless = expected.clone();
        stateless.state_schema_generation = None;
        stateless.state_contract_sha256 = None;
        stateless.write_lease_required = false;
        let mut stateless_receipt = topology_correlation(&stateless);
        stateless_receipt.observed_write_lease_sha256 = None;
        stateless_receipt
            .validate_against_expected(&stateless, None)
            .unwrap();
        stateless_receipt.observed_write_lease_sha256 = Some(digest('c'));
        assert!(
            stateless_receipt
                .validate_against_expected(&stateless, Some(&digest('c')))
                .is_err()
        );
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

        let mut missing_capability = topology_correlation(&expected);
        missing_capability.observed_capabilities.pop();
        assert!(missing_capability.validate().is_ok());
        assert!(
            missing_capability
                .validate_against_expected(&expected, Some(&digest('c')))
                .is_err()
        );
        missing_capability.present = true;
        missing_capability.ready = false;
        missing_capability.disagreements = vec![OdinTopologyDisagreement {
            code: "generic-mismatch".into(),
            expected: Some("expected".into()),
            observed: Some("observed".into()),
        }];
        assert!(
            missing_capability
                .validate_against_expected(&expected, Some(&digest('c')))
                .is_err()
        );
        correlate_capabilities(
            &mut missing_capability.disagreements,
            &expected.capabilities,
            &missing_capability.observed_capabilities,
        );
        missing_capability
            .disagreements
            .sort_by(|left, right| left.code.cmp(&right.code));
        missing_capability
            .validate_against_expected(&expected, Some(&digest('c')))
            .unwrap();

        let mut additional_capability = topology_correlation(&expected);
        additional_capability
            .observed_capabilities
            .push(runtime_capability("telemetry"));
        additional_capability
            .validate_against_expected(&expected, Some(&digest('c')))
            .unwrap();
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
