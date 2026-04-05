use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroize;

/// Nonce size for AES-256-GCM (96 bits / 12 bytes).
const NONCE_SIZE: usize = 12;

/// Salt size for Argon2id key derivation (16 bytes).
#[allow(dead_code)]
const SALT_SIZE: usize = 16;

/// Explicit Argon2id parameters per OWASP/RFC 9106 recommendations.
/// Pinned to prevent silent changes if the argon2 crate updates defaults.
/// m_cost = 19456 KiB (~19 MiB), t_cost = 2 iterations, p_cost = 1 thread.
fn argon2_kdf() -> Argon2<'static> {
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .expect("Argon2 params are valid (compile-time constant)");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Stronger Argon2id parameters for human passphrases.
/// m_cost = 65536 KiB (64 MiB), t_cost = 4 iterations, p_cost = 1 thread.
/// Significantly harder to brute-force than the YubiKey KDF profile,
/// since passphrases have much lower entropy than HMAC-SHA1 output.
fn passphrase_argon2_kdf() -> Argon2<'static> {
    let params = Params::new(64 * 1024, 4, 1, Some(32))
        .expect("Argon2 params are valid (compile-time constant)");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Derive a 256-bit AES key from a YubiKey HMAC-SHA1 response.
///
/// The YubiKey returns 20 bytes (HMAC-SHA1). We stretch it to 32 bytes
/// using HKDF-style derivation via Argon2id with a fixed context salt.
/// This also hardens against brute-force if the HMAC output leaks.
pub fn derive_key_from_yubikey_response(hmac_response: &[u8]) -> Result<Key<Aes256Gcm>> {
    // Fixed salt for YubiKey key derivation -- this is not secret,
    // it just provides domain separation.
    let salt = b"cred-yubikey-v1\0";

    let mut key_bytes = [0u8; 32];
    argon2_kdf()
        .hash_password_into(hmac_response, salt, &mut key_bytes)
        .map_err(|e| anyhow!("key derivation failed: {}", e))?;

    let key = *Key::<Aes256Gcm>::from_slice(&key_bytes);
    key_bytes.zeroize();
    Ok(key)
}

/// Derive a 256-bit AES key from a recovery passphrase.
/// Uses a random salt that must be stored alongside the ciphertext.
#[allow(dead_code)]
pub fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Result<Key<Aes256Gcm>> {
    let mut key_bytes = [0u8; 32];
    passphrase_argon2_kdf()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| anyhow!("passphrase key derivation failed: {}", e))?;

    let key = *Key::<Aes256Gcm>::from_slice(&key_bytes);
    key_bytes.zeroize();
    Ok(key)
}

/// Encrypt plaintext with AES-256-GCM.
/// Returns: nonce (12 bytes) || ciphertext+tag
pub fn encrypt(key: &Key<Aes256Gcm>, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("encryption failed: {}", e))?;

    // Prepend nonce to ciphertext
    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt AES-256-GCM ciphertext.
/// Input format: nonce (12 bytes) || ciphertext+tag
pub fn decrypt(key: &Key<Aes256Gcm>, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_SIZE + 16 {
        // 16 bytes minimum for GCM tag
        return Err(anyhow!("ciphertext too short"));
    }

    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
    let ciphertext = &data[NONCE_SIZE..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("decryption failed (wrong key or corrupted data): {}", e))
}

/// Encrypt the HMAC secret for the recovery file.
/// Format: salt (16 bytes) || nonce (12 bytes) || ciphertext+tag
#[allow(dead_code)]
pub fn encrypt_recovery(passphrase: &str, hmac_secret: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key_from_passphrase(passphrase, &salt)?;
    let encrypted = encrypt(&key, hmac_secret)?;

    let mut output = Vec::with_capacity(SALT_SIZE + encrypted.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

/// Decrypt the HMAC secret from a recovery file.
/// Input format: salt (16 bytes) || nonce (12 bytes) || ciphertext+tag
#[allow(dead_code)]
pub fn decrypt_recovery(passphrase: &str, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < SALT_SIZE + NONCE_SIZE + 16 {
        return Err(anyhow!("recovery file too short or corrupted"));
    }

    let salt = &data[..SALT_SIZE];
    let encrypted = &data[SALT_SIZE..];

    let key = derive_key_from_passphrase(passphrase, salt)?;
    decrypt(&key, encrypted)
}

/// Bundle the HMAC secret and challenge into a single recovery payload,
/// then encrypt with the passphrase.
/// Format: magic("CRv2", 4) || challenge_len(2 LE) || challenge || hmac_secret
/// The entire bundle is then encrypted via encrypt_recovery().
#[allow(dead_code)]
pub fn encrypt_recovery_v2(passphrase: &str, hmac_secret: &[u8], challenge: &[u8]) -> Result<Vec<u8>> {
    if challenge.len() > u16::MAX as usize {
        return Err(anyhow!("challenge too large"));
    }
    let mut bundle = Vec::with_capacity(6 + challenge.len() + hmac_secret.len());
    bundle.extend_from_slice(b"CRv2"); // 4-byte magic header
    bundle.extend_from_slice(&(challenge.len() as u16).to_le_bytes());
    bundle.extend_from_slice(challenge);
    bundle.extend_from_slice(hmac_secret);
    encrypt_recovery(passphrase, &bundle)
}

/// Decrypt a recovery file. Handles both v1 (HMAC secret only) and v2 (challenge + HMAC secret).
/// Returns (hmac_secret, Option<challenge>).
#[allow(dead_code)]
pub fn decrypt_recovery_v2(passphrase: &str, data: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let decrypted = decrypt_recovery(passphrase, data)?;

    if decrypted.len() > 6 && &decrypted[..4] == b"CRv2" {
        let challenge_len = u16::from_le_bytes([decrypted[4], decrypted[5]]) as usize;
        if decrypted.len() < 6 + challenge_len {
            return Err(anyhow!("recovery bundle truncated"));
        }
        let challenge = decrypted[6..6 + challenge_len].to_vec();
        let hmac_secret = decrypted[6 + challenge_len..].to_vec();
        Ok((hmac_secret, Some(challenge)))
    } else {
        // v1 format: raw HMAC secret, no challenge
        Ok((decrypted, None))
    }
}

/// Generate a random 20-byte HMAC-SHA1 secret for YubiKey programming.
#[allow(dead_code)]
pub fn generate_hmac_secret() -> [u8; 20] {
    let mut secret = [0u8; 20];
    OsRng.fill_bytes(&mut secret);
    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let hmac_response = b"01234567890123456789"; // 20 bytes
        let key = derive_key_from_yubikey_response(hmac_response).unwrap();
        let plaintext = b"my-secret-password";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = derive_key_from_yubikey_response(b"aaaaaaaaaaaaaaaaaaaa").unwrap();
        let key2 = derive_key_from_yubikey_response(b"bbbbbbbbbbbbbbbbbbbb").unwrap();

        let encrypted = encrypt(&key1, b"secret").unwrap();
        assert!(decrypt(&key2, &encrypted).is_err());
    }

    #[test]
    fn test_recovery_roundtrip() {
        let secret = generate_hmac_secret();
        let passphrase = "correct horse battery staple";

        let encrypted = encrypt_recovery(passphrase, &secret).unwrap();
        let decrypted = decrypt_recovery(passphrase, &encrypted).unwrap();

        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_recovery_wrong_passphrase() {
        let secret = generate_hmac_secret();
        let encrypted = encrypt_recovery("right", &secret).unwrap();
        assert!(decrypt_recovery("wrong", &encrypted).is_err());
    }

    #[test]
    fn test_recovery_v2_roundtrip() {
        let secret = generate_hmac_secret();
        let challenge = [0xABu8; 32];
        let passphrase = "correct horse battery staple";

        let encrypted = encrypt_recovery_v2(passphrase, &secret, &challenge).unwrap();
        let (recovered_secret, recovered_challenge) = decrypt_recovery_v2(passphrase, &encrypted).unwrap();

        assert_eq!(recovered_secret, secret);
        assert_eq!(recovered_challenge.unwrap(), challenge);
    }

    #[test]
    fn test_recovery_v2_reads_v1() {
        let secret = generate_hmac_secret();
        let passphrase = "correct horse battery staple";

        // v1 format
        let encrypted = encrypt_recovery(passphrase, &secret).unwrap();
        let (recovered_secret, recovered_challenge) = decrypt_recovery_v2(passphrase, &encrypted).unwrap();

        assert_eq!(recovered_secret, secret);
        assert!(recovered_challenge.is_none());
    }
}
