use anyhow::{Result, anyhow, bail};
use cultcache_rs::DatabaseEntry;

use crate::{IdunnServiceIdentity, derive_service_identity_id};

pub const GAMECULT_SERVICE_TRUST_ANCHOR_SCHEMA: &str = "gamecult.service_trust_anchor.v1";
pub const IDUNN_AUTHENTICATED_PROVIDER_HEALTH_PROJECTION_SCHEMA: &str =
    "idunn.authenticated_provider_health_projection.v1";
pub const IDUNN_SIGNED_DAEMON_HEALTH_SCHEMA: &str = "idunn.signed_daemon_health.v1";
pub const IDUNN_AUTHENTICATED_PROVIDER_HEALTH_PROJECTION_SIGNING_PURPOSE: &str =
    "idunn.authenticated-provider-health-projection.v1";
pub const IDUNN_PROVIDER_ACTIVE_REASON: &str = "authenticated_provider_active";
pub const IDUNN_PROVIDER_WARMING_REASON: &str = "authenticated_provider_warming";
pub const IDUNN_PROVIDER_DEGRADED_REASON: &str = "authenticated_provider_degraded";
pub const IDUNN_PROVIDER_FAILED_REASON: &str = "authenticated_provider_failed";

/// Provider-owned health statement. Ingress verifies `signature` over the
/// complete positional record with this field empty before admitting it.
#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(
    type = "idunn.signed_daemon_health",
    schema = "idunn.signed_daemon_health.v1"
)]
pub struct IdunnSignedDaemonHealthRecord {
    #[cultcache(key = 0)]
    pub schema_version: String,
    #[cultcache(key = 1)]
    pub daemon_id: String,
    #[cultcache(key = 2)]
    pub health_contract: String,
    #[cultcache(key = 3)]
    pub source_runtime_id: String,
    #[cultcache(key = 4)]
    pub state: String,
    #[cultcache(key = 5)]
    pub detail: String,
    #[cultcache(key = 6)]
    pub signer_identity_id: String,
    #[cultcache(key = 7)]
    pub publisher_incarnation_id: String,
    #[cultcache(key = 8)]
    pub publisher_sequence: u64,
    #[cultcache(key = 9)]
    pub observed_at_unix_millis: u64,
    #[cultcache(key = 10)]
    pub release_id: Option<String>,
    #[cultcache(key = 11)]
    pub release_witness_sha256: Option<String>,
    #[cultcache(key = 12)]
    pub source_commit: Option<String>,
    #[cultcache(key = 13)]
    pub deployment_id: Option<String>,
    #[cultcache(key = 14)]
    pub signature_algorithm: String,
    #[cultcache(key = 15)]
    pub signature: Vec<u8>,
    #[cultcache(key = 16)]
    pub private_state_exposed: bool,
}

impl IdunnSignedDaemonHealthRecord {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != IDUNN_SIGNED_DAEMON_HEALTH_SCHEMA {
            bail!("signed daemon health schema is unsupported");
        }
        validate_identifier(&self.daemon_id, "daemon id")?;
        validate_identifier(&self.health_contract, "health contract")?;
        validate_identifier(&self.source_runtime_id, "source runtime id")?;
        validate_identifier(&self.signer_identity_id, "signer identity id")?;
        validate_identifier(&self.publisher_incarnation_id, "publisher incarnation id")?;
        if !matches!(
            self.state.as_str(),
            "active" | "warming" | "degraded" | "failed"
        ) || self.detail.len() > 512
            || self.signature_algorithm != "ed25519"
            || self.signature.len() != 64
            || self.publisher_sequence == 0
            || self.observed_at_unix_millis == 0
        {
            bail!("signed daemon health shape is invalid");
        }
        validate_optional_release_binding(
            &self.release_id,
            &self.release_witness_sha256,
            &self.source_commit,
        )?;
        validate_optional_identifier(&self.deployment_id, "deployment id")?;
        if self.private_state_exposed {
            bail!("signed daemon health exposes private state");
        }
        Ok(())
    }
}

/// Root-distributed public key binding for one service-owned signed contract.
/// Consumers pin this document; a self-declared key inside a signed projection
/// is never authority.
#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(
    type = "gamecult.service_trust_anchor",
    schema = "gamecult.service_trust_anchor.v1"
)]
pub struct GameCultServiceTrustAnchorRecord {
    #[cultcache(key = 0)]
    pub schema_version: String,
    #[cultcache(key = 1)]
    pub trust_anchor_id: String,
    #[cultcache(key = 2)]
    pub service_id: String,
    #[cultcache(key = 3)]
    pub runtime_id: String,
    #[cultcache(key = 4)]
    pub signer_identity_id: String,
    #[cultcache(key = 5)]
    pub signer_public_key: Vec<u8>,
    #[cultcache(key = 6)]
    pub signature_algorithm: String,
    #[cultcache(key = 7)]
    pub signing_purpose: String,
    #[cultcache(key = 8)]
    pub signed_schema: String,
    #[cultcache(key = 9)]
    pub binding_authority: String,
    #[cultcache(key = 10)]
    pub bound_at_unix_millis: u64,
    #[cultcache(key = 11)]
    pub expires_at_unix_millis: Option<u64>,
    #[cultcache(key = 12)]
    pub private_state_exposed: bool,
}

impl GameCultServiceTrustAnchorRecord {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != GAMECULT_SERVICE_TRUST_ANCHOR_SCHEMA {
            bail!("service trust anchor schema is unsupported");
        }
        validate_identifier(&self.trust_anchor_id, "trust anchor id")?;
        validate_identifier(&self.service_id, "service id")?;
        validate_identifier(&self.runtime_id, "runtime id")?;
        validate_identifier(&self.signer_identity_id, "signer identity id")?;
        validate_identifier(&self.signing_purpose, "signing purpose")?;
        validate_identifier(&self.signed_schema, "signed schema")?;
        if self.signer_public_key.len() != 32
            || self.signature_algorithm != "ed25519"
            || self.binding_authority != "root"
            || self.bound_at_unix_millis == 0
            || self
                .expires_at_unix_millis
                .is_some_and(|expires_at| expires_at <= self.bound_at_unix_millis)
            || self.private_state_exposed
        {
            bail!("service trust anchor authority, key, lifetime, or privacy is invalid");
        }
        if self.signed_schema == IDUNN_AUTHENTICATED_PROVIDER_HEALTH_PROJECTION_SCHEMA
            && (self.service_id != "idunn"
                || self.signing_purpose
                    != IDUNN_AUTHENTICATED_PROVIDER_HEALTH_PROJECTION_SIGNING_PURPOSE
                || self.signer_identity_id
                    != derive_service_identity_id::<IdunnServiceIdentity>(&self.signer_public_key)?)
        {
            bail!("Idunn provider-health trust anchor profile is invalid");
        }
        Ok(())
    }
}

/// Idunn-owned public projection of one current authenticated generic provider
/// admission. Absence and dependency failure produce no record; they are not
/// provider states Idunn may manufacture.
#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(
    type = "idunn.authenticated_provider_health_projection",
    schema = "idunn.authenticated_provider_health_projection.v1"
)]
pub struct IdunnAuthenticatedProviderHealthProjectionRecord {
    #[cultcache(key = 0)]
    pub schema_version: String,
    #[cultcache(key = 1)]
    pub projection_id: String,
    #[cultcache(key = 2)]
    pub daemon_id: String,
    #[cultcache(key = 3)]
    pub health_contract: String,
    #[cultcache(key = 4)]
    pub provider_state: String,
    #[cultcache(key = 5)]
    pub reason_code: String,
    #[cultcache(key = 6)]
    pub provider_observed_at_unix_millis: u64,
    #[cultcache(key = 7)]
    pub admitted_at_unix_millis: u64,
    #[cultcache(key = 8)]
    pub evaluated_at_unix_millis: u64,
    #[cultcache(key = 9)]
    pub trust_binding_id: String,
    #[cultcache(key = 10)]
    pub trust_binding_sha256: String,
    #[cultcache(key = 11)]
    pub signed_health_sha256: String,
    #[cultcache(key = 12)]
    pub authenticated_admission_sha256: String,
    #[cultcache(key = 13)]
    pub provider_signer_identity_id: String,
    #[cultcache(key = 14)]
    pub provider_incarnation_id: String,
    #[cultcache(key = 15)]
    pub provider_sequence: u64,
    #[cultcache(key = 16)]
    pub release_id: Option<String>,
    #[cultcache(key = 17)]
    pub release_witness_sha256: Option<String>,
    #[cultcache(key = 18)]
    pub source_commit: Option<String>,
    #[cultcache(key = 19)]
    pub deployment_id: Option<String>,
    #[cultcache(key = 20)]
    pub idunn_runtime_id: String,
    #[cultcache(key = 21)]
    pub idunn_signer_identity_id: String,
    #[cultcache(key = 22)]
    pub projection_incarnation_id: String,
    #[cultcache(key = 23)]
    pub projection_sequence: u64,
    #[cultcache(key = 24)]
    pub signature_algorithm: String,
    #[cultcache(key = 25)]
    pub signature: Vec<u8>,
    #[cultcache(key = 26)]
    pub private_state_exposed: bool,
    #[cultcache(key = 27)]
    pub expires_at_unix_millis: u64,
}

/// Closed derivation for an authenticated provider state. `None` means no
/// provider-health projection may be published.
pub fn authenticated_provider_health_reason_code(state: &str) -> Option<&'static str> {
    match state {
        "active" => Some(IDUNN_PROVIDER_ACTIVE_REASON),
        "warming" => Some(IDUNN_PROVIDER_WARMING_REASON),
        "degraded" => Some(IDUNN_PROVIDER_DEGRADED_REASON),
        "failed" => Some(IDUNN_PROVIDER_FAILED_REASON),
        _ => None,
    }
}

impl IdunnAuthenticatedProviderHealthProjectionRecord {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != IDUNN_AUTHENTICATED_PROVIDER_HEALTH_PROJECTION_SCHEMA {
            bail!("authenticated provider health projection schema is unsupported");
        }
        validate_identifier(&self.projection_id, "projection id")?;
        validate_identifier(&self.daemon_id, "daemon id")?;
        validate_identifier(&self.health_contract, "health contract")?;
        validate_identifier(&self.trust_binding_id, "trust binding id")?;
        validate_identifier(
            &self.provider_signer_identity_id,
            "provider signer identity id",
        )?;
        validate_identifier(&self.provider_incarnation_id, "provider incarnation id")?;
        validate_identifier(&self.idunn_runtime_id, "Idunn runtime id")?;
        validate_identifier(&self.idunn_signer_identity_id, "Idunn signer identity id")?;
        validate_identifier(&self.projection_incarnation_id, "projection incarnation id")?;
        let reason_is_valid = authenticated_provider_health_reason_code(&self.provider_state)
            .is_some_and(|reason| reason == self.reason_code);
        if !reason_is_valid
            || self.provider_observed_at_unix_millis == 0
            || self.admitted_at_unix_millis < self.provider_observed_at_unix_millis
            || self.evaluated_at_unix_millis < self.admitted_at_unix_millis
            || self.expires_at_unix_millis <= self.evaluated_at_unix_millis
            || self.provider_sequence == 0
            || self.projection_sequence == 0
            || !is_sha256(&self.trust_binding_sha256)
            || !is_sha256(&self.signed_health_sha256)
            || !is_sha256(&self.authenticated_admission_sha256)
            || self.signature_algorithm != "ed25519"
            || self.signature.len() != 64
            || self.private_state_exposed
        {
            bail!(
                "authenticated provider health projection shape, lineage, reason, signature, or privacy is invalid"
            );
        }
        validate_optional_release_binding(
            &self.release_id,
            &self.release_witness_sha256,
            &self.source_commit,
        )?;
        validate_optional_identifier(&self.deployment_id, "deployment id")?;
        if self.deployment_id.is_some() != self.release_id.is_some() {
            bail!("authenticated provider health projection release lineage is partial");
        }
        Ok(())
    }
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        bail!("{label} is empty, oversized, or contains control characters");
    }
    Ok(())
}

fn validate_optional_identifier(value: &Option<String>, label: &str) -> Result<()> {
    if let Some(value) = value {
        validate_identifier(value, label)?;
    }
    Ok(())
}

fn validate_optional_release_binding(
    release_id: &Option<String>,
    witness: &Option<String>,
    source_commit: &Option<String>,
) -> Result<()> {
    if release_id.is_some() || witness.is_some() || source_commit.is_some() {
        validate_optional_identifier(release_id, "release id")?;
        let witness = witness
            .as_deref()
            .ok_or_else(|| anyhow!("release witness is absent"))?;
        let commit = source_commit
            .as_deref()
            .ok_or_else(|| anyhow!("source commit is absent"))?;
        if release_id.is_none() || !is_sha256(witness) || !is_lower_hex(commit, 40) {
            bail!("release binding is incomplete or malformed");
        }
    }
    Ok(())
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

    fn signed_health() -> IdunnSignedDaemonHealthRecord {
        IdunnSignedDaemonHealthRecord {
            schema_version: IDUNN_SIGNED_DAEMON_HEALTH_SCHEMA.into(),
            daemon_id: "epiphany".into(),
            health_contract: "epiphany.cultnet-rudp-runtime-health".into(),
            source_runtime_id: "epiphany-yggdrasil".into(),
            state: "active".into(),
            detail: "managed-services-current".into(),
            signer_identity_id: "provider-signing-key".into(),
            publisher_incarnation_id: "9c2cba2e-c2de-4750-b222-b732f97d0435".into(),
            publisher_sequence: 1,
            observed_at_unix_millis: 100,
            release_id: Some("release-1".into()),
            release_witness_sha256: Some(format!("sha256-{}", "d".repeat(64))),
            source_commit: Some("e".repeat(40)),
            deployment_id: Some("deployment-1".into()),
            signature_algorithm: "ed25519".into(),
            signature: vec![6; 64],
            private_state_exposed: false,
        }
    }

    fn anchor() -> GameCultServiceTrustAnchorRecord {
        let public_key = vec![5; 32];
        GameCultServiceTrustAnchorRecord {
            schema_version: GAMECULT_SERVICE_TRUST_ANCHOR_SCHEMA.into(),
            trust_anchor_id: "root/idunn/provider-health".into(),
            service_id: "idunn".into(),
            runtime_id: "idunn-yggdrasil".into(),
            signer_identity_id: derive_service_identity_id::<IdunnServiceIdentity>(&public_key)
                .unwrap(),
            signer_public_key: public_key,
            signature_algorithm: "ed25519".into(),
            signing_purpose: IDUNN_AUTHENTICATED_PROVIDER_HEALTH_PROJECTION_SIGNING_PURPOSE.into(),
            signed_schema: IDUNN_AUTHENTICATED_PROVIDER_HEALTH_PROJECTION_SCHEMA.into(),
            binding_authority: "root".into(),
            bound_at_unix_millis: 100,
            expires_at_unix_millis: Some(200),
            private_state_exposed: false,
        }
    }

    fn projection() -> IdunnAuthenticatedProviderHealthProjectionRecord {
        IdunnAuthenticatedProviderHealthProjectionRecord {
            schema_version: IDUNN_AUTHENTICATED_PROVIDER_HEALTH_PROJECTION_SCHEMA.into(),
            projection_id: "authenticated-provider-health:epiphany".into(),
            daemon_id: "epiphany".into(),
            health_contract: "health.v1".into(),
            provider_state: "active".into(),
            reason_code: IDUNN_PROVIDER_ACTIVE_REASON.into(),
            provider_observed_at_unix_millis: 100,
            admitted_at_unix_millis: 101,
            evaluated_at_unix_millis: 102,
            trust_binding_id: "root/epiphany".into(),
            trust_binding_sha256: format!("sha256-{}", "a".repeat(64)),
            signed_health_sha256: format!("sha256-{}", "b".repeat(64)),
            authenticated_admission_sha256: format!("sha256-{}", "c".repeat(64)),
            provider_signer_identity_id: "provider-signing-key".into(),
            provider_incarnation_id: "provider/boot/1".into(),
            provider_sequence: 1,
            release_id: Some("release-1".into()),
            release_witness_sha256: Some(format!("sha256-{}", "d".repeat(64))),
            source_commit: Some("e".repeat(40)),
            deployment_id: Some("deployment-1".into()),
            idunn_runtime_id: "idunn-yggdrasil".into(),
            idunn_signer_identity_id: "idunn-signing-key".into(),
            projection_incarnation_id: "idunn/boot/1".into(),
            projection_sequence: 1,
            signature_algorithm: "ed25519".into(),
            signature: vec![6; 64],
            private_state_exposed: false,
            expires_at_unix_millis: 200,
        }
    }

    #[test]
    fn contracts_accept_exact_root_and_lineage_shapes() -> Result<()> {
        let anchor = anchor();
        let projection = projection();
        let health = signed_health();
        anchor.validate()?;
        projection.validate()?;
        health.validate()?;
        let encoded = rmp_serde::to_vec(&health)?;
        assert_eq!(encoded.first().copied(), Some(0xdc));
        assert_eq!(&encoded[1..3], &[0, 17]);
        assert_eq!(
            rmp_serde::from_slice::<IdunnSignedDaemonHealthRecord>(&encoded)?,
            health
        );
        assert_eq!(
            rmp_serde::from_slice::<GameCultServiceTrustAnchorRecord>(&rmp_serde::to_vec(
                &anchor
            )?)?,
            anchor
        );
        assert_eq!(
            rmp_serde::from_slice::<IdunnAuthenticatedProviderHealthProjectionRecord>(
                &rmp_serde::to_vec(&projection)?
            )?,
            projection
        );
        assert_eq!(authenticated_provider_health_reason_code("missing"), None);
        Ok(())
    }

    #[test]
    fn contracts_refuse_substitution_and_manufactured_states() {
        let mut value = anchor();
        value.binding_authority = "idunn".into();
        assert!(value.validate().is_err());
        let mut value = anchor();
        value.signer_identity_id = "caller-selected".into();
        assert!(value.validate().is_err());
        let mut value = projection();
        value.reason_code = "release_drift".into();
        assert!(value.validate().is_err());
        let mut value = projection();
        value.provider_state = "missing".into();
        assert!(value.validate().is_err());
        let mut value = projection();
        value.deployment_id = None;
        assert!(value.validate().is_err());
        let mut value = projection();
        value.signature.clear();
        assert!(value.validate().is_err());
        let mut value = projection();
        value.signed_health_sha256 = format!("sha256-{}", "A".repeat(64));
        assert!(value.validate().is_err());
        let mut value = signed_health();
        value.publisher_sequence = 0;
        assert!(value.validate().is_err());
        let mut value = signed_health();
        value.release_witness_sha256 = None;
        assert!(value.validate().is_err());
        let mut value = signed_health();
        value.private_state_exposed = true;
        assert!(value.validate().is_err());
    }
}
