use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use aes_gcm::Nonce;
use aes_gcm::aead::Aead;
use aes_gcm::aead::Payload;
use anyhow::Result;
use anyhow::anyhow;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::DateTime;
use chrono::TimeZone;
use chrono::Utc;
use hmac::Hmac;
use hmac::Mac;
use rand::RngCore;
use sha2::Digest;
use sha2::Sha256;

const NONCE_LENGTH: usize = 12;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CultNetClientSecurityOptions {
    pub connection_key: String,
    encryption_key: [u8; 32],
}

impl CultNetClientSecurityOptions {
    pub fn new(connection_key: impl Into<String>) -> Result<Self> {
        let connection_key = connection_key.into();
        if connection_key.trim().is_empty() {
            return Err(anyhow!("Connection key must be provided"));
        }
        let encryption_key = sha256(connection_key.as_bytes());
        Ok(Self {
            connection_key,
            encryption_key,
        })
    }

    pub fn development() -> Self {
        Self::new("gamecult-dev-connection-key").expect("development key is valid")
    }

    pub fn encryption_key(&self) -> [u8; 32] {
        self.encryption_key
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CultNetServerSecurityOptions {
    client: CultNetClientSecurityOptions,
    pub session_signing_secret: String,
    session_signing_key: [u8; 32],
    pub is_development: bool,
}

impl CultNetServerSecurityOptions {
    pub fn new(
        connection_key: impl Into<String>,
        session_signing_secret: impl Into<String>,
        is_development: bool,
    ) -> Result<Self> {
        let session_signing_secret = session_signing_secret.into();
        if session_signing_secret.trim().is_empty() {
            return Err(anyhow!("Session signing secret must be provided"));
        }
        Ok(Self {
            client: CultNetClientSecurityOptions::new(connection_key)?,
            session_signing_key: sha256(session_signing_secret.as_bytes()),
            session_signing_secret,
            is_development,
        })
    }

    pub fn development() -> Self {
        Self::new(
            "gamecult-dev-connection-key",
            "gamecult-dev-session-signing-secret",
            true,
        )
        .expect("development security config is valid")
    }

    pub fn to_client_options(&self) -> CultNetClientSecurityOptions {
        self.client.clone()
    }

    pub fn encryption_key(&self) -> [u8; 32] {
        self.client.encryption_key()
    }

    pub fn session_signing_key(&self) -> [u8; 32] {
        self.session_signing_key
    }
}

pub trait CultNetEncryptionOptions {
    fn encryption_key(&self) -> [u8; 32];
}

impl CultNetEncryptionOptions for CultNetClientSecurityOptions {
    fn encryption_key(&self) -> [u8; 32] {
        self.encryption_key()
    }
}

impl CultNetEncryptionOptions for CultNetServerSecurityOptions {
    fn encryption_key(&self) -> [u8; 32] {
        self.encryption_key()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedCultNetSessionToken {
    pub user_id: String,
    pub expires_at_utc: DateTime<Utc>,
}

pub struct CultNetSecret;

impl CultNetSecret {
    pub fn new_nonce() -> [u8; NONCE_LENGTH] {
        let mut nonce = [0_u8; NONCE_LENGTH];
        rand::rng().fill_bytes(&mut nonce);
        nonce
    }

    pub fn encrypt_string(
        input: Option<&str>,
        nonce: &[u8],
        options: &impl CultNetEncryptionOptions,
    ) -> Result<Option<Vec<u8>>> {
        let Some(input) = input.filter(|value| !value.is_empty()) else {
            return Ok(None);
        };
        Ok(Some(Self::encrypt_bytes(input.as_bytes(), nonce, options)?))
    }

    pub fn decrypt_string(
        encrypted: Option<&[u8]>,
        nonce: Option<&[u8]>,
        options: &impl CultNetEncryptionOptions,
    ) -> Result<Option<String>> {
        let (Some(encrypted), Some(nonce)) = (encrypted, nonce) else {
            return Ok(None);
        };
        let bytes = Self::decrypt_bytes(encrypted, nonce, options)?;
        Ok(Some(String::from_utf8(bytes)?))
    }

    pub fn encrypt_bytes(
        input: &[u8],
        nonce: &[u8],
        options: &impl CultNetEncryptionOptions,
    ) -> Result<Vec<u8>> {
        let nonce = validate_nonce(nonce)?;
        let cipher = Aes256Gcm::new_from_slice(&options.encryption_key())?;
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: input,
                    aad: &[],
                },
            )
            .map_err(|_| anyhow!("AES-GCM encryption failed"))?;
        Ok(encrypted)
    }

    pub fn decrypt_bytes(
        encrypted: &[u8],
        nonce: &[u8],
        options: &impl CultNetEncryptionOptions,
    ) -> Result<Vec<u8>> {
        let nonce = validate_nonce(nonce)?;
        let cipher = Aes256Gcm::new_from_slice(&options.encryption_key())?;
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: encrypted,
                    aad: &[],
                },
            )
            .map_err(|_| anyhow!("AES-GCM decryption failed"))
    }

    pub fn create_session_token(
        user_id: &str,
        expires_at_utc: DateTime<Utc>,
        options: &CultNetServerSecurityOptions,
    ) -> Result<String> {
        let payload = format!("{}|{}", user_id, expires_at_utc.timestamp());
        let signature = hmac_sha256(&options.session_signing_key(), payload.as_bytes())?;
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload.as_bytes()),
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    pub fn try_validate_session_token(
        token: Option<&str>,
        options: &CultNetServerSecurityOptions,
    ) -> Result<Option<ValidatedCultNetSessionToken>> {
        let Some(token) = token.filter(|value| !value.trim().is_empty()) else {
            return Ok(None);
        };
        let Some((payload_part, signature_part)) = token.split_once('.') else {
            return Ok(None);
        };
        let payload = URL_SAFE_NO_PAD.decode(payload_part)?;
        let signature = URL_SAFE_NO_PAD.decode(signature_part)?;
        let expected = hmac_sha256(&options.session_signing_key(), &payload)?;
        if !constant_time_eq(&signature, &expected) {
            return Ok(None);
        }
        let payload = String::from_utf8(payload)?;
        let Some((user_id, expires_at)) = payload.split_once('|') else {
            return Ok(None);
        };
        let expires_at_seconds: i64 = expires_at.parse()?;
        let Some(expires_at_utc) = Utc.timestamp_opt(expires_at_seconds, 0).single() else {
            return Ok(None);
        };
        if expires_at_utc <= Utc::now() {
            return Ok(None);
        }
        Ok(Some(ValidatedCultNetSessionToken {
            user_id: user_id.to_string(),
            expires_at_utc,
        }))
    }

    pub fn to_base64_url(input: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(input)
    }

    pub fn from_base64_url(input: &str) -> Result<Vec<u8>> {
        Ok(URL_SAFE_NO_PAD.decode(input)?)
    }
}

fn validate_nonce(nonce: &[u8]) -> Result<&[u8]> {
    if nonce.len() != NONCE_LENGTH {
        return Err(anyhow!("Invalid nonce"));
    }
    Ok(nonce)
}

fn sha256(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

fn hmac_sha256(key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)?;
    mac.update(input);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}
