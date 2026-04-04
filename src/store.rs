use aes_gcm::{Aes256Gcm, Key};
use anyhow::{anyhow, Context, Result};
use tracing::debug;

use crate::backend::{self, RawSecret, SecretBackend};
use crate::types::*;

pub struct CredStore {
    backend: Box<dyn SecretBackend>,
    master_key: Option<Key<Aes256Gcm>>,
}

impl CredStore {
    /// Create a new CredStore with auto-detected backend.
    pub fn new(master_key: Key<Aes256Gcm>) -> Result<Self> {
        let backend = backend::create_backend()?;
        Ok(Self {
            backend,
            master_key: Some(master_key),
        })
    }

    /// Create with a specific backend (for testing or explicit selection).
    pub fn with_backend(master_key: Key<Aes256Gcm>, backend: Box<dyn SecretBackend>) -> Self {
        Self {
            backend,
            master_key: Some(master_key),
        }
    }

    fn require_key(&self) -> Result<&Key<Aes256Gcm>> {
        self.master_key.as_ref()
            .ok_or_else(|| anyhow!("no encryption key -- is the YubiKey plugged in?"))
    }

    /// List all secrets, decrypting each one.
    pub async fn list_all(&self) -> Result<Vec<Secret>> {
        let master_key = self.require_key()?;
        let raw_secrets = self.backend.list_all().await?;
        let mut secrets = Vec::new();

        for raw in raw_secrets {
            match decrypt_raw_secret(&raw, master_key) {
                Ok(secret) => secrets.push(secret),
                Err(e) => {
                    debug!("skipping undecryptable secret {}/{}: {}", raw.service, raw.key, e);
                }
            }
        }

        Ok(secrets)
    }

    /// Store a secret, encrypting it first.
    pub async fn store(&self, secret: &Secret) -> Result<u64> {
        let master_key = self.require_key()?;
        let ciphertext = encrypt_secret_value(&secret.value, master_key)?;
        self.backend.store(&secret.service, &secret.key, &ciphertext).await
    }

    /// Get a single secret by service and key.
    pub async fn get(&self, service: &str, key: &str) -> Result<Secret> {
        let master_key = self.require_key()?;
        let raw = self.backend.get(service, key).await?;
        decrypt_raw_secret(&raw, master_key)
    }

    /// Delete a secret by service and key.
    pub async fn delete(&self, service: &str, key: &str) -> Result<()> {
        self.backend.delete(service, key).await
    }
}

/// Encrypt a SecretValue to hex-encoded ciphertext.
fn encrypt_secret_value(value: &SecretValue, key: &Key<Aes256Gcm>) -> Result<String> {
    let json = serde_json::to_string(value).context("failed to serialize secret")?;
    let encrypted = crate::crypto::encrypt(key, json.as_bytes())?;
    Ok(hex::encode(encrypted))
}

/// Decrypt a RawSecret's ciphertext into a full Secret.
fn decrypt_raw_secret(raw: &RawSecret, key: &Key<Aes256Gcm>) -> Result<Secret> {
    let encrypted_bytes = hex::decode(&raw.ciphertext)
        .context("invalid hex ciphertext")?;
    let decrypted = crate::crypto::decrypt(key, &encrypted_bytes)
        .context("decryption failed")?;
    let value: SecretValue = serde_json::from_slice(&decrypted)
        .context("failed to deserialize secret value")?;

    Ok(Secret {
        service: raw.service.clone(),
        key: raw.key.clone(),
        value,
        engram_id: Some(raw.id),
        created_at: raw.created_at.as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc)),
    })
}
