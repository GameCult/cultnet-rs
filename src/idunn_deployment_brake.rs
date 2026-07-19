use anyhow::{Result, bail};
use cultcache_rs::DatabaseEntry;

use crate::{
    IdunnDeploymentBrakeOperatorIdentity, IdunnDeploymentBrakeReleasePurpose,
    ServiceIdentitySignature, ServiceIdentityTrustAnchor, verify_service_identity_signature,
};

pub const IDUNN_DEPLOYMENT_BRAKE_SCHEMA: &str = "idunn.deployment_brake.v1";
pub const IDUNN_DEPLOYMENT_BRAKE_TYPE: &str = "idunn.deployment_brake";
pub const IDUNN_DEPLOYMENT_BRAKE_ID: &str = "idunn/deployment-brake";
pub const IDUNN_DEPLOYMENT_BRAKE_AUTHORITY: &str = "idunn.deployment-brake";
pub const IDUNN_DEPLOYMENT_BRAKE_SCOPE: &str = "deployment";
pub const IDUNN_DEPLOYMENT_RELEASE_PURPOSE: &str = "idunn.deployment-release.v1";
pub const IDUNN_DEPLOYMENT_RELEASE_MAX_LIFETIME_MILLIS: u64 = 15 * 60 * 1_000;

/// Canonical deployment-facing brake projection consumed by Idunn. A released
/// status is not permission by itself: the authorization fields bind one
/// release and one deployment attempt for a short, explicit interval.
#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(type = "idunn.deployment_brake", schema = "idunn.deployment_brake.v1")]
pub struct IdunnDeploymentBrakeRecord {
    #[cultcache(key = 0)]
    pub schema_version: String,
    #[cultcache(key = 1)]
    pub brake_id: String,
    #[cultcache(key = 2)]
    pub authority: String,
    #[cultcache(key = 3)]
    pub runtime_id: String,
    #[cultcache(key = 4)]
    pub status: String,
    #[cultcache(key = 5)]
    pub scope: String,
    #[cultcache(key = 6)]
    pub reason: String,
    #[cultcache(key = 7)]
    pub observed_at_unix_millis: u64,
    #[cultcache(key = 8)]
    pub expires_at_unix_millis: Option<u64>,
    #[cultcache(key = 9)]
    pub authorization_id: Option<String>,
    #[cultcache(key = 10)]
    pub authorization_purpose: Option<String>,
    #[cultcache(key = 11)]
    pub authorized_release_id: Option<String>,
    #[cultcache(key = 12)]
    pub authorized_deployment_id: Option<String>,
    #[cultcache(key = 13)]
    pub authorized_by: Option<String>,
    #[cultcache(key = 14)]
    pub authorization_issued_at_unix_millis: Option<u64>,
    #[cultcache(key = 15)]
    pub authorization_expires_at_unix_millis: Option<u64>,
    #[cultcache(key = 16)]
    pub signature_algorithm: Option<String>,
    #[cultcache(key = 17)]
    pub signature: Option<Vec<u8>>,
    #[cultcache(key = 18)]
    pub private_state_exposed: bool,
    /// Human/operator principal responsible for the latest transition. This is
    /// distinct from `authorized_by`, which is the cryptographic identity id.
    #[cultcache(key = 19)]
    pub updated_by: String,
}

impl IdunnDeploymentBrakeRecord {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != IDUNN_DEPLOYMENT_BRAKE_SCHEMA {
            bail!("deployment brake schema is unsupported");
        }
        identifier(&self.brake_id, "brake id")?;
        identifier(&self.authority, "authority")?;
        identifier(&self.runtime_id, "runtime id")?;
        identifier(&self.reason, "reason")?;
        identifier(&self.scope, "scope")?;
        identifier(&self.updated_by, "updating operator")?;
        if !matches!(self.status.as_str(), "engaged" | "released")
            || self.observed_at_unix_millis == 0
            || self
                .expires_at_unix_millis
                .is_some_and(|v| v <= self.observed_at_unix_millis)
            || self.private_state_exposed
        {
            bail!("deployment brake shape, lifetime, or privacy is invalid");
        }

        let authorization = [
            self.authorization_id.as_ref(),
            self.authorization_purpose.as_ref(),
            self.authorized_release_id.as_ref(),
            self.authorized_deployment_id.as_ref(),
            self.authorized_by.as_ref(),
            self.signature_algorithm.as_ref(),
        ];
        let has_authorization = authorization.iter().any(|v| v.is_some())
            || self.authorization_issued_at_unix_millis.is_some()
            || self.authorization_expires_at_unix_millis.is_some()
            || self.signature.is_some();
        if self.status == "engaged" {
            if has_authorization {
                bail!("engaged deployment brake must not carry release authorization");
            }
            return Ok(());
        }
        if authorization.iter().any(|v| v.is_none())
            || self.authorization_issued_at_unix_millis.is_none()
            || self.authorization_expires_at_unix_millis.is_none()
            || self.signature.is_none()
        {
            bail!("released deployment brake authorization is incomplete");
        }
        for (value, label) in [
            (&self.authorization_id, "authorization id"),
            (&self.authorized_release_id, "authorized release id"),
            (&self.authorized_deployment_id, "authorized deployment id"),
            (&self.authorized_by, "authorizer"),
        ] {
            identifier(value.as_deref().unwrap(), label)?;
        }
        let issued = self.authorization_issued_at_unix_millis.unwrap();
        let expires = self.authorization_expires_at_unix_millis.unwrap();
        if self.authorization_purpose.as_deref() != Some(IDUNN_DEPLOYMENT_RELEASE_PURPOSE)
            || self.signature_algorithm.as_deref() != Some("ed25519")
            || self.signature.as_ref().is_none_or(|v| v.len() != 64)
            || issued < self.observed_at_unix_millis
            || expires <= issued
            || expires - issued > IDUNN_DEPLOYMENT_RELEASE_MAX_LIFETIME_MILLIS
            || self
                .expires_at_unix_millis
                .is_some_and(|brake_expiry| expires > brake_expiry)
        {
            bail!("deployment release authorization purpose, signature, or lifetime is invalid");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum IdunnDeploymentBrakeObservation<'a> {
    Missing,
    Corrupt,
    Present(&'a IdunnDeploymentBrakeRecord),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdunnDeploymentBrakeDenial {
    Missing,
    Corrupt,
    Foreign,
    WrongRuntime,
    WrongScope,
    Engaged,
    Expired,
    ReleaseMismatch,
    DeploymentMismatch,
    InvalidSignature,
}

fn classify_idunn_deployment_brake(
    observation: IdunnDeploymentBrakeObservation<'_>,
    runtime_id: &str,
    release_id: &str,
    deployment_id: &str,
    now_unix_millis: u64,
) -> std::result::Result<(), IdunnDeploymentBrakeDenial> {
    let record = match observation {
        IdunnDeploymentBrakeObservation::Missing => {
            return Err(IdunnDeploymentBrakeDenial::Missing);
        }
        IdunnDeploymentBrakeObservation::Corrupt => {
            return Err(IdunnDeploymentBrakeDenial::Corrupt);
        }
        IdunnDeploymentBrakeObservation::Present(record) => record,
    };
    if record.validate().is_err() {
        return Err(IdunnDeploymentBrakeDenial::Corrupt);
    }
    if record.brake_id != IDUNN_DEPLOYMENT_BRAKE_ID
        || record.authority != IDUNN_DEPLOYMENT_BRAKE_AUTHORITY
    {
        return Err(IdunnDeploymentBrakeDenial::Foreign);
    }
    if record.runtime_id != runtime_id {
        return Err(IdunnDeploymentBrakeDenial::WrongRuntime);
    }
    if !matches!(record.scope.as_str(), "all" | IDUNN_DEPLOYMENT_BRAKE_SCOPE) {
        return Err(IdunnDeploymentBrakeDenial::WrongScope);
    }
    if record.status == "engaged" {
        return Err(IdunnDeploymentBrakeDenial::Engaged);
    }
    if record
        .expires_at_unix_millis
        .is_some_and(|v| now_unix_millis >= v)
        || record
            .authorization_expires_at_unix_millis
            .is_none_or(|v| now_unix_millis >= v)
        || record
            .authorization_issued_at_unix_millis
            .is_none_or(|v| now_unix_millis < v)
    {
        return Err(IdunnDeploymentBrakeDenial::Expired);
    }
    if record.authorized_release_id.as_deref() != Some(release_id) {
        return Err(IdunnDeploymentBrakeDenial::ReleaseMismatch);
    }
    if record.authorized_deployment_id.as_deref() != Some(deployment_id) {
        return Err(IdunnDeploymentBrakeDenial::DeploymentMismatch);
    }
    Ok(())
}

pub fn evaluate_idunn_deployment_brake(
    observation: IdunnDeploymentBrakeObservation<'_>,
    operator_anchor: &ServiceIdentityTrustAnchor,
    runtime_id: &str,
    release_id: &str,
    deployment_id: &str,
    now_unix_millis: u64,
) -> std::result::Result<(), IdunnDeploymentBrakeDenial> {
    classify_idunn_deployment_brake(
        observation,
        runtime_id,
        release_id,
        deployment_id,
        now_unix_millis,
    )?;
    let IdunnDeploymentBrakeObservation::Present(record) = observation else {
        unreachable!("successful classification always has a present record")
    };
    verify_idunn_deployment_brake_authorization(record, operator_anchor)
        .map_err(|_| IdunnDeploymentBrakeDenial::InvalidSignature)
}

/// Verify the release grant using the dedicated operator public anchor. The
/// signed payload is the complete positional record with the signature field
/// empty, so authority, runtime, target IDs, and both time bounds are covered.
pub fn verify_idunn_deployment_brake_authorization(
    record: &IdunnDeploymentBrakeRecord,
    anchor: &ServiceIdentityTrustAnchor,
) -> Result<()> {
    record.validate()?;
    if record.status != "released" {
        bail!("engaged deployment brake has no release authorization to verify");
    }
    let identity_id = record
        .authorized_by
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("deployment brake authorizer is absent"))?;
    let signature = record
        .signature
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("deployment brake signature is absent"))?;
    let mut unsigned = record.clone();
    unsigned.signature = None;
    verify_service_identity_signature::<
        IdunnDeploymentBrakeOperatorIdentity,
        IdunnDeploymentBrakeReleasePurpose,
    >(
        anchor,
        &rmp_serde::to_vec(&unsigned)?,
        &ServiceIdentitySignature {
            identity_id: identity_id.clone(),
            signature: signature.clone(),
        },
    )
}

fn identifier(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        bail!("{label} is empty, oversized, or contains control characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enroll_service_identity_at;

    fn released() -> IdunnDeploymentBrakeRecord {
        IdunnDeploymentBrakeRecord {
            schema_version: IDUNN_DEPLOYMENT_BRAKE_SCHEMA.into(),
            brake_id: IDUNN_DEPLOYMENT_BRAKE_ID.into(),
            authority: IDUNN_DEPLOYMENT_BRAKE_AUTHORITY.into(),
            runtime_id: "yggdrasil".into(),
            status: "released".into(),
            scope: "deployment".into(),
            reason: "operator authorized one attempt".into(),
            observed_at_unix_millis: 100,
            expires_at_unix_millis: Some(1000),
            authorization_id: Some("auth/r4".into()),
            authorization_purpose: Some(IDUNN_DEPLOYMENT_RELEASE_PURPOSE.into()),
            authorized_release_id: Some("release-4".into()),
            authorized_deployment_id: Some("deployment-4".into()),
            authorized_by: Some("operator/metacrat".into()),
            authorization_issued_at_unix_millis: Some(100),
            authorization_expires_at_unix_millis: Some(900),
            signature_algorithm: Some("ed25519".into()),
            signature: Some(vec![7; 64]),
            private_state_exposed: false,
            updated_by: "operator/metacrat".into(),
        }
    }

    #[test]
    fn only_exact_bounded_release_is_permitted() {
        let value = released();
        assert_eq!(
            classify_idunn_deployment_brake(
                IdunnDeploymentBrakeObservation::Present(&value),
                "yggdrasil",
                "release-4",
                "deployment-4",
                500
            ),
            Ok(())
        );
        assert_eq!(
            classify_idunn_deployment_brake(
                IdunnDeploymentBrakeObservation::Missing,
                "yggdrasil",
                "release-4",
                "deployment-4",
                500
            ),
            Err(IdunnDeploymentBrakeDenial::Missing)
        );
        assert_eq!(
            classify_idunn_deployment_brake(
                IdunnDeploymentBrakeObservation::Corrupt,
                "yggdrasil",
                "release-4",
                "deployment-4",
                500
            ),
            Err(IdunnDeploymentBrakeDenial::Corrupt)
        );
        assert_eq!(
            classify_idunn_deployment_brake(
                IdunnDeploymentBrakeObservation::Present(&value),
                "yggdrasil",
                "other",
                "deployment-4",
                500
            ),
            Err(IdunnDeploymentBrakeDenial::ReleaseMismatch)
        );
        assert_eq!(
            classify_idunn_deployment_brake(
                IdunnDeploymentBrakeObservation::Present(&value),
                "yggdrasil",
                "release-4",
                "other",
                500
            ),
            Err(IdunnDeploymentBrakeDenial::DeploymentMismatch)
        );
        assert_eq!(
            classify_idunn_deployment_brake(
                IdunnDeploymentBrakeObservation::Present(&value),
                "yggdrasil",
                "release-4",
                "deployment-4",
                900
            ),
            Err(IdunnDeploymentBrakeDenial::Expired)
        );
    }

    #[test]
    fn hostile_authority_scope_and_shape_substitutions_fail_closed() {
        let mut value = released();
        value.authority = "idunn".into();
        assert_eq!(
            classify_idunn_deployment_brake(
                IdunnDeploymentBrakeObservation::Present(&value),
                "yggdrasil",
                "release-4",
                "deployment-4",
                500
            ),
            Err(IdunnDeploymentBrakeDenial::Foreign)
        );
        let mut value = released();
        value.runtime_id = "nightwing".into();
        assert_eq!(
            classify_idunn_deployment_brake(
                IdunnDeploymentBrakeObservation::Present(&value),
                "yggdrasil",
                "release-4",
                "deployment-4",
                500
            ),
            Err(IdunnDeploymentBrakeDenial::WrongRuntime)
        );
        let mut value = released();
        value.scope = "persona.public_speech".into();
        assert_eq!(
            classify_idunn_deployment_brake(
                IdunnDeploymentBrakeObservation::Present(&value),
                "yggdrasil",
                "release-4",
                "deployment-4",
                500
            ),
            Err(IdunnDeploymentBrakeDenial::WrongScope)
        );
        let mut value = released();
        value.signature = Some(vec![0; 63]);
        assert_eq!(
            classify_idunn_deployment_brake(
                IdunnDeploymentBrakeObservation::Present(&value),
                "yggdrasil",
                "release-4",
                "deployment-4",
                500
            ),
            Err(IdunnDeploymentBrakeDenial::Corrupt)
        );
        let mut value = released();
        value.authorization_expires_at_unix_millis =
            Some(100 + IDUNN_DEPLOYMENT_RELEASE_MAX_LIFETIME_MILLIS + 1);
        assert!(value.validate().is_err());
    }

    #[test]
    fn engaged_record_cannot_smuggle_authorization() {
        let mut value = released();
        value.status = "engaged".into();
        assert!(value.validate().is_err());
        value.authorization_id = None;
        value.authorization_purpose = None;
        value.authorized_release_id = None;
        value.authorized_deployment_id = None;
        value.authorized_by = None;
        value.authorization_issued_at_unix_millis = None;
        value.authorization_expires_at_unix_millis = None;
        value.signature_algorithm = None;
        value.signature = None;
        value.validate().unwrap();
        assert_eq!(
            classify_idunn_deployment_brake(
                IdunnDeploymentBrakeObservation::Present(&value),
                "yggdrasil",
                "release-4",
                "deployment-4",
                500
            ),
            Err(IdunnDeploymentBrakeDenial::Engaged)
        );
    }

    #[test]
    fn evaluation_requires_the_dedicated_operator_signature() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let signer = enroll_service_identity_at::<IdunnDeploymentBrakeOperatorIdentity>(
            &temp.path().join("operator.cc"),
        )?;
        let anchor = signer.trust_anchor()?;
        let mut value = released();
        value.authorized_by = Some(anchor.identity_id.clone());
        value.signature = None;
        let proof = signer.sign::<IdunnDeploymentBrakeReleasePurpose>(&rmp_serde::to_vec(&value)?);
        value.signature = Some(proof.signature);
        assert_eq!(
            evaluate_idunn_deployment_brake(
                IdunnDeploymentBrakeObservation::Present(&value),
                &anchor,
                "yggdrasil",
                "release-4",
                "deployment-4",
                500,
            ),
            Ok(())
        );
        value.reason = "tampered after authorization".into();
        assert_eq!(
            evaluate_idunn_deployment_brake(
                IdunnDeploymentBrakeObservation::Present(&value),
                &anchor,
                "yggdrasil",
                "release-4",
                "deployment-4",
                500,
            ),
            Err(IdunnDeploymentBrakeDenial::InvalidSignature)
        );
        Ok(())
    }
}
