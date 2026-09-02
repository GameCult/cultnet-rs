use anyhow::{Context, Result, bail};
use cultcache_rs::DatabaseEntry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const GAMECULT_RUNTIME_PRESENCE_HEALTH_SCHEMA: &str = "gamecult.runtime_presence_health.v1";
pub const GAMECULT_RUNTIME_PRESENCE_HEALTH_SIGNING_PURPOSE: &str =
    "gamecult.runtime_presence_health.v1";
pub const IDUNN_RUNTIME_ACTIVATION_SCHEMA: &str = "idunn.runtime_activation.v1";
pub const IDUNN_PROCESS_WRITE_LEASE_SCHEMA: &str = "idunn.process_write_lease.v1";

const MAX_RUNTIME_CAPABILITIES: usize = 256;

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

fn validate_optional_endpoint(value: &Option<String>) -> Result<()> {
    if let Some(endpoint) = value
        && (endpoint.is_empty()
            || endpoint.len() > 2048
            || endpoint.trim() != endpoint
            || endpoint.chars().any(char::is_control))
    {
        bail!("bound endpoint is empty, oversized, padded, or contains control characters");
    }
    Ok(())
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
        IDUNN_SIGNED_DAEMON_HEALTH_SCHEMA, IdunnServiceIdentity, ServiceIdentitySignature,
        derive_service_identity_id, enroll_service_identity_at, verify_service_identity_signature,
    };

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
}
