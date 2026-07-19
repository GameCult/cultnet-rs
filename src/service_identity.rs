use anyhow::{Context, Result, anyhow, bail};
use cultcache_rs::{CacheBackingStore, CultCacheEnvelope, SingleFileMessagePackBackingStore};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::marker::PhantomData;
use std::path::Path;

pub const WINDOWS_SERVICE_IDENTITY_ASSURANCE: &str = "os_user_installation_bound_best_effort";
pub const LINUX_SERVICE_IDENTITY_ASSURANCE: &str = "os_installation_file_bound_cloneable_baseline";

/// Fixes every authority-bearing name at the call site. A service cannot open
/// another service's identity by supplying a convenient runtime string.
pub trait ServiceIdentityProfile: Send + Sync + 'static {
    const PRIVATE_TYPE: &'static str;
    const PRIVATE_SCHEMA: &'static str;
    const PRIVATE_KEY: &'static str;
    const TRUST_ANCHOR_TYPE: &'static str;
    const TRUST_ANCHOR_SCHEMA: &'static str;
    const TRUST_ANCHOR_KEY: &'static str;
    const ID_DOMAIN: &'static [u8];
    const SIGNATURE_DOMAIN: &'static [u8];
    const PROTECTOR_CONTEXT: &'static str;
}

/// A purpose is a type, not caller-provided prose. Protocol implementations
/// define one zero-sized type per signed statement kind.
pub trait ServiceSignaturePurpose<P: ServiceIdentityProfile>: Send + Sync + 'static {
    const PURPOSE: &'static [u8];
}

pub enum IdunnServiceIdentity {}

/// Root-operated identity dedicated to deployment-brake release grants. The
/// Idunn daemon receives only this profile's public trust anchor; opening the
/// private store is a provisioning operation, never daemon startup work.
pub enum IdunnDeploymentBrakeOperatorIdentity {}

pub struct IdunnDeploymentBrakeReleasePurpose;

impl ServiceSignaturePurpose<IdunnDeploymentBrakeOperatorIdentity>
    for IdunnDeploymentBrakeReleasePurpose
{
    const PURPOSE: &'static [u8] = b"idunn.deployment-release.v1";
}

impl ServiceIdentityProfile for IdunnDeploymentBrakeOperatorIdentity {
    const PRIVATE_TYPE: &'static str = "idunn.deployment_brake_operator.private.v1";
    const PRIVATE_SCHEMA: &'static str = "idunn.deployment_brake_operator.private.v1";
    const PRIVATE_KEY: &'static str = "idunn-deployment-brake-operator";
    const TRUST_ANCHOR_TYPE: &'static str = "idunn.deployment_brake_operator.trust_anchor.v1";
    const TRUST_ANCHOR_SCHEMA: &'static str = "idunn.deployment_brake_operator.trust_anchor.v1";
    const TRUST_ANCHOR_KEY: &'static str = "idunn-deployment-brake-operator-public";
    const ID_DOMAIN: &'static [u8] = b"idunn.deployment-brake-operator.id.v1\0";
    const SIGNATURE_DOMAIN: &'static [u8] = b"idunn.deployment-brake-operator.signature.v1\0";
    const PROTECTOR_CONTEXT: &'static str = "idunn-deployment-brake-operator-v1";
}

/// Dedicated provider-owned identity for generic daemon-health statements.
/// It is intentionally independent of any one provider runtime or repository.
pub enum GameCultProviderHealthIdentity {}

/// The only generic health statement purpose accepted from provider-health
/// identities by Idunn admission.
pub struct IdunnSignedDaemonHealthPurpose;

impl ServiceSignaturePurpose<GameCultProviderHealthIdentity> for IdunnSignedDaemonHealthPurpose {
    const PURPOSE: &'static [u8] = b"idunn.signed_daemon_health.v1";
}

impl ServiceIdentityProfile for GameCultProviderHealthIdentity {
    const PRIVATE_TYPE: &'static str = "gamecult.provider_health_identity.private.v1";
    const PRIVATE_SCHEMA: &'static str = "gamecult.provider_health_identity.private.v1";
    const PRIVATE_KEY: &'static str = "gamecult-provider-health-identity";
    const TRUST_ANCHOR_TYPE: &'static str = "gamecult.provider_health_identity.trust_anchor.v1";
    const TRUST_ANCHOR_SCHEMA: &'static str = "gamecult.provider_health_identity.trust_anchor.v1";
    const TRUST_ANCHOR_KEY: &'static str = "gamecult-provider-health-identity-public";
    const ID_DOMAIN: &'static [u8] = b"gamecult.provider-health.identity.v1\0";
    const SIGNATURE_DOMAIN: &'static [u8] = b"gamecult.provider-health.signature.v1\0";
    const PROTECTOR_CONTEXT: &'static str = "gamecult-provider-health-identity-v1";
}

/// The only signing purpose accepted for Idunn's public projection of a
/// provider-authenticated health admission. Keeping this profile here makes
/// purpose selection a compile-time protocol choice rather than caller text.
pub struct IdunnAuthenticatedProviderHealthProjectionPurpose;

impl ServiceSignaturePurpose<IdunnServiceIdentity>
    for IdunnAuthenticatedProviderHealthProjectionPurpose
{
    const PURPOSE: &'static [u8] = b"idunn.authenticated-provider-health-projection.v1";
}

impl ServiceIdentityProfile for IdunnServiceIdentity {
    const PRIVATE_TYPE: &'static str = "idunn.service_identity.private.v1";
    const PRIVATE_SCHEMA: &'static str = "idunn.service_identity.private.v1";
    const PRIVATE_KEY: &'static str = "idunn-service-identity";
    const TRUST_ANCHOR_TYPE: &'static str = "idunn.service_identity.trust_anchor.v1";
    const TRUST_ANCHOR_SCHEMA: &'static str = "idunn.service_identity.trust_anchor.v1";
    const TRUST_ANCHOR_KEY: &'static str = "idunn-service-identity-public";
    const ID_DOMAIN: &'static [u8] = b"idunn.service-identity.id.v1\0";
    const SIGNATURE_DOMAIN: &'static [u8] = b"idunn.service-identity.signature.v1\0";
    const PROTECTOR_CONTEXT: &'static str = "idunn-service-identity-v1";
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceIdentityPrivateEntry {
    pub schema_version: String,
    pub identity_id: String,
    pub public_key: Vec<u8>,
    pub protected_private_seed: Vec<u8>,
    pub protector_kind: String,
    pub protector_binding: String,
    pub protector_version: String,
    pub assurance: String,
    pub created_at: String,
    pub enrollment_nonce: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceIdentityTrustAnchor {
    pub schema_version: String,
    pub identity_id: String,
    pub public_key: Vec<u8>,
    pub assurance: String,
    pub identity_created_at: String,
    pub source_identity_record_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceIdentitySignature {
    pub identity_id: String,
    pub signature: Vec<u8>,
}

/// The only value holding unprotected key material. It exposes signing, never
/// seed export or access to the underlying signing key.
pub struct ServiceIdentitySigner<P: ServiceIdentityProfile> {
    entry: ServiceIdentityPrivateEntry,
    signing_key: SigningKey,
    profile: PhantomData<P>,
}

impl<P: ServiceIdentityProfile> ServiceIdentitySigner<P> {
    pub fn entry(&self) -> &ServiceIdentityPrivateEntry {
        &self.entry
    }

    pub fn trust_anchor(&self) -> Result<ServiceIdentityTrustAnchor> {
        Ok(ServiceIdentityTrustAnchor {
            schema_version: P::TRUST_ANCHOR_SCHEMA.into(),
            identity_id: self.entry.identity_id.clone(),
            public_key: self.entry.public_key.clone(),
            assurance: self.entry.assurance.clone(),
            identity_created_at: self.entry.created_at.clone(),
            source_identity_record_sha256: format!(
                "sha256-{}",
                hex(&Sha256::digest(rmp_serde::to_vec(&self.entry)?))
            ),
        })
    }

    pub fn sign<S: ServiceSignaturePurpose<P>>(&self, payload: &[u8]) -> ServiceIdentitySignature {
        ServiceIdentitySignature {
            identity_id: self.entry.identity_id.clone(),
            signature: self
                .signing_key
                .sign(&signing_message::<P, S>(payload))
                .to_bytes()
                .to_vec(),
        }
    }
}

pub fn enroll_service_identity_at<P: ServiceIdentityProfile>(
    path: &Path,
) -> Result<ServiceIdentitySigner<P>> {
    if path.exists() {
        bail!(
            "service identity store {} already exists; enrollment is immutable",
            path.display()
        );
    }
    prepare_parent(path)?;
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    let public_key = signing_key.verifying_key().to_bytes();
    let binding = platform_binding::<P>()?;
    let entry = ServiceIdentityPrivateEntry {
        schema_version: P::PRIVATE_SCHEMA.into(),
        identity_id: identity_id::<P>(&public_key),
        public_key: public_key.to_vec(),
        protected_private_seed: protect_seed::<P>(&seed, &binding)?,
        protector_kind: platform_protector_kind().into(),
        protector_binding: binding,
        protector_version: "v1".into(),
        assurance: platform_assurance().into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        enrollment_nonce: nonce.to_vec(),
    };
    validate_private::<P>(&entry)?;
    let envelope = private_envelope::<P>(&entry)?;
    atomic_create_private_store(path, &envelope)?;
    harden_store_permissions(path)?;
    open_service_identity_at::<P>(path)
}

pub fn open_service_identity_at<P: ServiceIdentityProfile>(
    path: &Path,
) -> Result<ServiceIdentitySigner<P>> {
    if !path.is_file() {
        bail!("service identity store {} does not exist", path.display());
    }
    let entries = SingleFileMessagePackBackingStore::new(path).pull_all()?;
    if entries.len() != 1 {
        bail!("service identity store must contain exactly one immutable envelope");
    }
    let envelope = &entries[0];
    if envelope.r#type != P::PRIVATE_TYPE
        || envelope.key != P::PRIVATE_KEY
        || envelope.schema_id.as_deref() != Some(P::PRIVATE_SCHEMA)
    {
        bail!("service identity store belongs to a different profile or schema");
    }
    let entry: ServiceIdentityPrivateEntry = rmp_serde::from_slice(&envelope.payload)
        .context("service identity private payload is malformed MessagePack")?;
    validate_private::<P>(&entry)?;
    if entry.protector_kind != platform_protector_kind() || entry.assurance != platform_assurance()
    {
        bail!("service identity protector does not belong to this platform implementation");
    }
    let binding = platform_binding::<P>()?;
    if entry.protector_binding != binding {
        bail!("service identity protector binding does not match this OS installation or profile");
    }
    let seed: [u8; 32] = unprotect_seed::<P>(&entry.protected_private_seed, &binding)?
        .try_into()
        .map_err(|_| anyhow!("unprotected service identity seed has invalid length"))?;
    let signing_key = SigningKey::from_bytes(&seed);
    if signing_key.verifying_key().to_bytes().as_slice() != entry.public_key.as_slice() {
        bail!("service identity private seed does not match enrolled public key");
    }
    Ok(ServiceIdentitySigner {
        entry,
        signing_key,
        profile: PhantomData,
    })
}

pub fn export_service_identity_trust_anchor<P: ServiceIdentityProfile>(
    signer: &ServiceIdentitySigner<P>,
    path: &Path,
) -> Result<ServiceIdentityTrustAnchor> {
    let anchor = signer.trust_anchor()?;
    prepare_parent(path)?;
    let envelope = CultCacheEnvelope {
        key: P::TRUST_ANCHOR_KEY.into(),
        r#type: P::TRUST_ANCHOR_TYPE.into(),
        payload: rmp_serde::to_vec(&anchor)?,
        stored_at: anchor.identity_created_at.clone(),
        schema_id: Some(P::TRUST_ANCHOR_SCHEMA.into()),
    };
    let mut backing = SingleFileMessagePackBackingStore::new(path);
    match backing.pull_all()?.as_slice() {
        [] => backing.push(&envelope)?,
        [current] if current == &envelope => {}
        _ => bail!("service identity trust anchor output already contains different state"),
    }
    Ok(anchor)
}

pub fn verify_service_identity_signature<P, S>(
    anchor: &ServiceIdentityTrustAnchor,
    payload: &[u8],
    proof: &ServiceIdentitySignature,
) -> Result<()>
where
    P: ServiceIdentityProfile,
    S: ServiceSignaturePurpose<P>,
{
    validate_anchor::<P>(anchor)?;
    if proof.identity_id != anchor.identity_id {
        bail!("service identity signature names a different identity");
    }
    let key: [u8; 32] = anchor
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("service identity public key has invalid length"))?;
    let signature = Signature::from_slice(&proof.signature)
        .map_err(|_| anyhow!("service identity signature has invalid length"))?;
    VerifyingKey::from_bytes(&key)?
        .verify(&signing_message::<P, S>(payload), &signature)
        .map_err(|_| anyhow!("service identity signature verification failed"))
}

/// Verify against a public key already admitted by an owning trust store.
/// The profile derives the identity, so callers cannot substitute a convenient
/// identity string while retaining the same signature bytes.
pub fn verify_service_identity_signature_with_public_key<P, S>(
    public_key: &[u8],
    payload: &[u8],
    proof: &ServiceIdentitySignature,
) -> Result<()>
where
    P: ServiceIdentityProfile,
    S: ServiceSignaturePurpose<P>,
{
    if proof.identity_id != derive_service_identity_id::<P>(public_key)? {
        bail!("service identity signature names a different identity");
    }
    let key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| anyhow!("service identity public key has invalid length"))?;
    let signature = Signature::from_slice(&proof.signature)
        .map_err(|_| anyhow!("service identity signature has invalid length"))?;
    VerifyingKey::from_bytes(&key)?
        .verify(&signing_message::<P, S>(payload), &signature)
        .map_err(|_| anyhow!("service identity signature verification failed"))
}

fn validate_private<P: ServiceIdentityProfile>(entry: &ServiceIdentityPrivateEntry) -> Result<()> {
    if entry.schema_version != P::PRIVATE_SCHEMA
        || entry.public_key.len() != 32
        || entry.enrollment_nonce.len() != 32
        || entry.protected_private_seed.is_empty()
        || entry.protector_version != "v1"
    {
        bail!("service identity private entry violates its profile schema");
    }
    chrono::DateTime::parse_from_rfc3339(&entry.created_at)
        .map_err(|_| anyhow!("service identity created_at is not RFC3339"))?;
    if identity_id::<P>(&entry.public_key) != entry.identity_id {
        bail!("service identity id does not match public key");
    }
    Ok(())
}

fn validate_anchor<P: ServiceIdentityProfile>(anchor: &ServiceIdentityTrustAnchor) -> Result<()> {
    if anchor.schema_version != P::TRUST_ANCHOR_SCHEMA
        || anchor.public_key.len() != 32
        || derive_service_identity_id::<P>(&anchor.public_key)? != anchor.identity_id
    {
        bail!("service identity trust anchor violates its profile schema");
    }
    Ok(())
}

/// Derives the profile-bound identity id from an exact Ed25519 public key.
/// Consumers use this instead of accepting a caller-supplied identity string.
pub fn derive_service_identity_id<P: ServiceIdentityProfile>(public_key: &[u8]) -> Result<String> {
    if public_key.len() != 32 {
        bail!("service identity public key has invalid length");
    }
    Ok(hex(&Sha256::digest([P::ID_DOMAIN, public_key].concat())))
}

fn identity_id<P: ServiceIdentityProfile>(key: &[u8]) -> String {
    derive_service_identity_id::<P>(key).expect("internal service identity key is Ed25519")
}

fn signing_message<P: ServiceIdentityProfile, S: ServiceSignaturePurpose<P>>(
    payload: &[u8],
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(P::SIGNATURE_DOMAIN.len() + S::PURPOSE.len() + payload.len() + 16);
    out.extend_from_slice(P::SIGNATURE_DOMAIN);
    out.extend_from_slice(&(S::PURPOSE.len() as u64).to_be_bytes());
    out.extend_from_slice(S::PURPOSE);
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn private_envelope<P: ServiceIdentityProfile>(
    entry: &ServiceIdentityPrivateEntry,
) -> Result<CultCacheEnvelope> {
    Ok(CultCacheEnvelope {
        key: P::PRIVATE_KEY.into(),
        r#type: P::PRIVATE_TYPE.into(),
        payload: rmp_serde::to_vec(entry)?,
        stored_at: entry.created_at.clone(),
        schema_id: Some(P::PRIVATE_SCHEMA.into()),
    })
}

fn prepare_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("service identity path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Enrollment is a one-shot authority transition. `create_new` makes two
/// simultaneous enrollments unable to overwrite one another, while the encoded
/// envelope vector remains a supported CultCache single-file representation.
fn atomic_create_private_store(path: &Path, envelope: &CultCacheEnvelope) -> Result<()> {
    let bytes = rmp_serde::to_vec(&vec![envelope.clone()])
        .context("failed to encode immutable service identity store")?;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .with_context(|| {
            format!(
                "service identity store {} already exists or cannot be created; enrollment is immutable",
                path.display()
            )
        })?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error).context("failed to persist immutable service identity store");
    }
    Ok(())
}
fn harden_store_permissions(_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(windows)]
fn platform_protector_kind() -> &'static str {
    "windows_dpapi_current_user"
}
#[cfg(target_os = "linux")]
fn platform_protector_kind() -> &'static str {
    "linux_file_mode_machine_id_binding"
}
#[cfg(windows)]
fn platform_assurance() -> &'static str {
    WINDOWS_SERVICE_IDENTITY_ASSURANCE
}
#[cfg(target_os = "linux")]
fn platform_assurance() -> &'static str {
    LINUX_SERVICE_IDENTITY_ASSURANCE
}

#[cfg(windows)]
fn platform_binding<P: ServiceIdentityProfile>() -> Result<String> {
    Ok(format!("dpapi-current-user:{}", P::PROTECTOR_CONTEXT))
}
#[cfg(target_os = "linux")]
fn platform_binding<P: ServiceIdentityProfile>() -> Result<String> {
    let raw = std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .context("Linux machine-id is unavailable")?;
    let id = raw.trim();
    if id.is_empty() {
        bail!("Linux machine-id is empty");
    }
    Ok(format!(
        "{}:machine-id-sha256:{}",
        P::PROTECTOR_CONTEXT,
        hex(&Sha256::digest(id.as_bytes()))
    ))
}

#[cfg(windows)]
fn protect_seed<P: ServiceIdentityProfile>(seed: &[u8; 32], binding: &str) -> Result<Vec<u8>> {
    dpapi::<P>(seed, binding, true)
}
#[cfg(windows)]
fn unprotect_seed<P: ServiceIdentityProfile>(seed: &[u8], binding: &str) -> Result<Vec<u8>> {
    dpapi::<P>(seed, binding, false)
}
#[cfg(windows)]
fn dpapi<P: ServiceIdentityProfile>(input: &[u8], binding: &str, protect: bool) -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    let mut input = input.to_vec();
    let mut entropy = Sha256::digest(
        [
            b"gamecult-service-identity-dpapi-v1\0".as_slice(),
            P::PROTECTOR_CONTEXT.as_bytes(),
            binding.as_bytes(),
        ]
        .concat(),
    )
    .to_vec();
    let ib = CRYPT_INTEGER_BLOB {
        cbData: input.len() as u32,
        pbData: input.as_mut_ptr(),
    };
    let eb = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &ib,
                std::ptr::null(),
                &eb,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &ib,
                std::ptr::null_mut(),
                &eb,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .context("DPAPI service identity operation failed");
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn protect_seed<P: ServiceIdentityProfile>(seed: &[u8; 32], binding: &str) -> Result<Vec<u8>> {
    xor_linux::<P>(seed, binding)
}
#[cfg(target_os = "linux")]
fn unprotect_seed<P: ServiceIdentityProfile>(seed: &[u8], binding: &str) -> Result<Vec<u8>> {
    if seed.len() != 32 {
        bail!("protected Linux service seed has invalid length");
    }
    xor_linux::<P>(seed, binding)
}
#[cfg(target_os = "linux")]
fn xor_linux<P: ServiceIdentityProfile>(seed: &[u8], binding: &str) -> Result<Vec<u8>> {
    let mask = Sha256::digest(
        [
            b"gamecult-linux-service-seed-v1\0".as_slice(),
            P::PROTECTOR_CONTEXT.as_bytes(),
            binding.as_bytes(),
        ]
        .concat(),
    );
    Ok(seed.iter().zip(mask).map(|(a, b)| a ^ b).collect())
}

fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    enum OtherPurpose {}
    impl ServiceSignaturePurpose<IdunnServiceIdentity> for OtherPurpose {
        const PURPOSE: &'static [u8] = b"idunn.other.v1";
    }

    #[test]
    fn immutable_enrollment_reopens_and_is_purpose_and_payload_bound() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("idunn.ccmp");
        let signer = enroll_service_identity_at::<IdunnServiceIdentity>(&path)?;
        let proof = signer.sign::<IdunnAuthenticatedProviderHealthProjectionPurpose>(b"healthy");
        let anchor = signer.trust_anchor()?;
        verify_service_identity_signature::<
            IdunnServiceIdentity,
            IdunnAuthenticatedProviderHealthProjectionPurpose,
        >(&anchor, b"healthy", &proof)?;
        assert!(
            verify_service_identity_signature::<
                IdunnServiceIdentity,
                IdunnAuthenticatedProviderHealthProjectionPurpose,
            >(&anchor, b"unhealthy", &proof)
            .is_err()
        );
        assert!(
            verify_service_identity_signature::<IdunnServiceIdentity, OtherPurpose>(
                &anchor, b"healthy", &proof
            )
            .is_err()
        );
        assert!(enroll_service_identity_at::<IdunnServiceIdentity>(&path).is_err());
        assert_eq!(
            derive_service_identity_id::<IdunnServiceIdentity>(&anchor.public_key)?,
            anchor.identity_id
        );
        assert!(derive_service_identity_id::<IdunnServiceIdentity>(&[0; 31]).is_err());
        assert_eq!(
            open_service_identity_at::<IdunnServiceIdentity>(&path)?.entry(),
            signer.entry()
        );
        Ok(())
    }

    #[test]
    fn malformed_or_profile_substituted_state_fails_closed_without_replacement() -> Result<()> {
        enum Alien {}
        impl ServiceIdentityProfile for Alien {
            const PRIVATE_TYPE: &'static str = "alien.private.v1";
            const PRIVATE_SCHEMA: &'static str = "alien.private.v1";
            const PRIVATE_KEY: &'static str = "alien";
            const TRUST_ANCHOR_TYPE: &'static str = "alien.anchor.v1";
            const TRUST_ANCHOR_SCHEMA: &'static str = "alien.anchor.v1";
            const TRUST_ANCHOR_KEY: &'static str = "alien-public";
            const ID_DOMAIN: &'static [u8] = b"alien.id\0";
            const SIGNATURE_DOMAIN: &'static [u8] = b"alien.sig\0";
            const PROTECTOR_CONTEXT: &'static str = "alien-v1";
        }
        let temp = tempfile::tempdir()?;
        let malformed = temp.path().join("bad.ccmp");
        std::fs::write(&malformed, b"rot")?;
        let before = std::fs::read(&malformed)?;
        assert!(open_service_identity_at::<IdunnServiceIdentity>(&malformed).is_err());
        assert!(enroll_service_identity_at::<IdunnServiceIdentity>(&malformed).is_err());
        assert_eq!(before, std::fs::read(&malformed)?);
        let good = temp.path().join("good.ccmp");
        enroll_service_identity_at::<IdunnServiceIdentity>(&good)?;
        assert!(open_service_identity_at::<Alien>(&good).is_err());
        Ok(())
    }

    #[test]
    fn exported_anchor_is_public_only_immutable_and_rejects_identity_substitution() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let signer =
            enroll_service_identity_at::<IdunnServiceIdentity>(&temp.path().join("private.ccmp"))?;
        let output = temp.path().join("public.ccmp");
        let anchor = export_service_identity_trust_anchor(&signer, &output)?;
        let bytes = std::fs::read(&output)?;
        assert!(
            !bytes
                .windows(signer.entry().protected_private_seed.len())
                .any(|w| w == signer.entry().protected_private_seed)
        );
        export_service_identity_trust_anchor(&signer, &output)?;
        assert_eq!(bytes, std::fs::read(&output)?);
        let other =
            enroll_service_identity_at::<IdunnServiceIdentity>(&temp.path().join("other.ccmp"))?;
        let proof = other.sign::<IdunnAuthenticatedProviderHealthProjectionPurpose>(b"healthy");
        assert!(
            verify_service_identity_signature::<
                IdunnServiceIdentity,
                IdunnAuthenticatedProviderHealthProjectionPurpose,
            >(&anchor, b"healthy", &proof)
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn provider_health_profile_is_domain_separated_and_purpose_bound() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let signer = enroll_service_identity_at::<GameCultProviderHealthIdentity>(
            &temp.path().join("provider-health.cc"),
        )?;
        let proof = signer.sign::<IdunnSignedDaemonHealthPurpose>(b"signed-health-record");
        let anchor = signer.trust_anchor()?;
        verify_service_identity_signature::<
            GameCultProviderHealthIdentity,
            IdunnSignedDaemonHealthPurpose,
        >(&anchor, b"signed-health-record", &proof)?;
        verify_service_identity_signature_with_public_key::<
            GameCultProviderHealthIdentity,
            IdunnSignedDaemonHealthPurpose,
        >(&anchor.public_key, b"signed-health-record", &proof)?;
        assert_eq!(
            anchor.schema_version,
            "gamecult.provider_health_identity.trust_anchor.v1"
        );
        assert_ne!(
            derive_service_identity_id::<GameCultProviderHealthIdentity>(&anchor.public_key)?,
            derive_service_identity_id::<IdunnServiceIdentity>(&anchor.public_key)?
        );
        Ok(())
    }
}
