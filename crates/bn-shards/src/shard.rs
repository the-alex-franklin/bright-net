// bn-shards/src/shard.rs
//
// Shamir's Secret Sharing for the root signing key + genesis block hash.
//
// Flow:
//   split_secret(secret, threshold, total)
//     → Vec<RawShard>           (distribute one per device)
//
//   encrypt_shard(raw, pin)
//     → EncryptedShard          (store on device; pin derived from composite local factors)
//
//   decrypt_shard(encrypted, pin)
//     → RawShard
//
//   reconstruct_secret(shards, threshold)
//     → secret bytes            (only possible with ≥ threshold shards)
//
// The Shamir library (`sharks`) works over GF(256) — each shard is a Vec<u8>.
// We layer ChaCha20-Poly1305 encryption on top so a stolen device file can't
// be used without also knowing the PIN (and ideally biometric + TPM factor).

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use sharks::{Share, Sharks};
use zeroize::Zeroizing;

use crate::error::ShardError;

// ── Types ─────────────────────────────────────────────────────────────────────

/// A raw (unencrypted) Shamir share.
/// Never write this to disk — always encrypt first.
pub struct RawShard {
    /// Shamir share bytes (includes the x-coordinate implicitly).
    pub bytes: Zeroizing<Vec<u8>>,
    /// Which shard this is (1-indexed, for display only).
    pub index: u8,
    /// Total shards in the set.
    pub total: u8,
    /// Minimum shards required to reconstruct.
    pub threshold: u8,
}

/// An encrypted shard — safe to write to disk or transmit to a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedShard {
    /// Argon2id salt used when deriving the encryption key from the PIN.
    pub salt: String, // base64-encoded
    /// ChaCha20-Poly1305 nonce.
    pub nonce: String, // hex-encoded [u8; 12]
    /// Ciphertext (Shamir share bytes + AEAD auth tag).
    pub ciphertext: String, // hex-encoded
    pub index: u8,
    pub total: u8,
    pub threshold: u8,
}

// ── Split ─────────────────────────────────────────────────────────────────────

/// Split `secret` into `total` Shamir shares where any `threshold` of them
/// can reconstruct the original.
///
/// Typical call: `split_secret(&root_key_bytes, 3, 5)`
pub fn split_secret(
    secret: &[u8],
    threshold: u8,
    total: u8,
) -> Result<Vec<RawShard>, ShardError> {
    if secret.len() > 65535 {
        return Err(ShardError::SecretTooLarge(secret.len()));
    }

    let sharks = Sharks(threshold);
    // `dealer` is an iterator that yields shares indefinitely.
    // We collect exactly `total` of them.
    let dealer = sharks.dealer(secret);
    let shares: Vec<Share> = dealer.take(total as usize).collect();

    shares
        .into_iter()
        .enumerate()
        .map(|(i, share)| {
            Ok(RawShard {
                bytes: Zeroizing::new(Vec::from(&share)),
                index: i as u8 + 1,
                total,
                threshold,
            })
        })
        .collect()
}

// ── Reconstruct ───────────────────────────────────────────────────────────────

/// Reconstruct the original secret from `threshold` or more raw shards.
pub fn reconstruct_secret(
    shards: &[RawShard],
    threshold: u8,
) -> Result<Zeroizing<Vec<u8>>, ShardError> {
    if shards.len() < threshold as usize {
        return Err(ShardError::InsufficientShards {
            threshold,
            available: shards.len(),
        });
    }

    let sharks = Sharks(threshold);

    // Convert our RawShard bytes back into the Share type the library expects.
    let shares: Vec<Share> = shards
        .iter()
        .map(|s| Share::try_from(s.bytes.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ShardError::InvalidShard(e.to_string()))?;

    let secret = sharks
        .recover(&shares)
        .map_err(|e| ShardError::InvalidShard(e.to_string()))?;

    Ok(Zeroizing::new(secret))
}

// ── Encrypt / Decrypt ─────────────────────────────────────────────────────────

/// Encrypt a raw shard with a PIN (and optionally a device-bound factor
/// concatenated with the PIN before passing in here).
///
/// In production, `pin` would be derived from: Argon2id(PIN || device_id || biometric_hash).
/// For now, it's just a raw passphrase — the device-binding is a TODO for the daemon layer.
pub fn encrypt_shard(shard: &RawShard, pin: &[u8]) -> Result<EncryptedShard, ShardError> {
    // Derive a 32-byte ChaCha20 key from the PIN using Argon2id.
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash_str = argon2
        .hash_password(pin, &salt)
        .map_err(|e| ShardError::Encryption(e.to_string()))?
        .to_string();

    // Extract just the raw output hash bytes (last 32 bytes of the PHC string).
    // Argon2id output is 32 bytes by default.
    let key_bytes = derive_key_from_hash(&hash_str)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, shard.bytes.as_slice())
        .map_err(|e| ShardError::Encryption(e.to_string()))?;

    Ok(EncryptedShard {
        salt: salt.to_string(),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
        index: shard.index,
        total: shard.total,
        threshold: shard.threshold,
    })
}

/// Decrypt an encrypted shard using the same PIN it was encrypted with.
pub fn decrypt_shard(shard: &EncryptedShard, pin: &[u8]) -> Result<RawShard, ShardError> {
    // Re-derive the same key — Argon2id is deterministic given the same salt.
    let salt = argon2::password_hash::SaltString::from_b64(&shard.salt)
        .map_err(|_| ShardError::Decryption)?;
    let argon2 = Argon2::default();
    let hash_str = argon2
        .hash_password(pin, &salt)
        .map_err(|_| ShardError::Decryption)?
        .to_string();

    let key_bytes = derive_key_from_hash(&hash_str)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce_bytes = hex::decode(&shard.nonce).map_err(|_| ShardError::Decryption)?;
    let nonce_arr: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| ShardError::Decryption)?;
    let nonce = Nonce::from(nonce_arr);

    let ciphertext = hex::decode(&shard.ciphertext).map_err(|_| ShardError::Decryption)?;
    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_slice())
        .map_err(|_| ShardError::Decryption)?;

    Ok(RawShard {
        bytes: Zeroizing::new(plaintext),
        index: shard.index,
        total: shard.total,
        threshold: shard.threshold,
    })
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Extract 32 usable key bytes from an Argon2 PHC-format hash string.
/// Argon2id default output is 32 bytes, base64-encoded in the hash field.
fn derive_key_from_hash(phc_string: &str) -> Result<[u8; 32], ShardError> {
    // PHC format: $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>
    // The hash field is the last `$`-delimited segment.
    let hash_b64 = phc_string
        .rsplit('$')
        .next()
        .ok_or_else(|| ShardError::Encryption("malformed argon2 hash".into()))?;

    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    let hash_bytes = STANDARD_NO_PAD
        .decode(hash_b64)
        .map_err(|e| ShardError::Encryption(format!("base64 decode failed: {e}")))?;

    hash_bytes
        .try_into()
        .map_err(|_| ShardError::Encryption("argon2 output not 32 bytes".into()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"this-is-a-32-byte-root-signingke"; // 32 bytes
    const TEST_PIN: &[u8] = b"correct-horse-battery-staple";

    #[test]
    fn split_and_reconstruct_exact_threshold() {
        let shards = split_secret(TEST_SECRET, 3, 5).unwrap();
        assert_eq!(shards.len(), 5);

        // Use exactly 3 shards.
        let subset: Vec<_> = shards.into_iter().take(3).collect();
        let recovered = reconstruct_secret(&subset, 3).unwrap();
        assert_eq!(recovered.as_slice(), TEST_SECRET);
    }

    #[test]
    fn reconstruct_with_all_shards() {
        let shards = split_secret(TEST_SECRET, 3, 5).unwrap();
        let recovered = reconstruct_secret(&shards, 3).unwrap();
        assert_eq!(recovered.as_slice(), TEST_SECRET);
    }

    #[test]
    fn insufficient_shards_returns_error() {
        let shards = split_secret(TEST_SECRET, 3, 5).unwrap();
        let subset: Vec<_> = shards.into_iter().take(2).collect();
        let result = reconstruct_secret(&subset, 3);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let shards = split_secret(TEST_SECRET, 3, 5).unwrap();
        let encrypted = encrypt_shard(&shards[0], TEST_PIN).unwrap();
        let decrypted = decrypt_shard(&encrypted, TEST_PIN).unwrap();
        assert_eq!(decrypted.bytes.as_slice(), shards[0].bytes.as_slice());
    }

    #[test]
    fn wrong_pin_fails_decryption() {
        let shards = split_secret(TEST_SECRET, 3, 5).unwrap();
        let encrypted = encrypt_shard(&shards[0], TEST_PIN).unwrap();
        let result = decrypt_shard(&encrypted, b"wrong-pin");
        assert!(result.is_err());
    }

    #[test]
    fn full_flow_split_encrypt_decrypt_reconstruct() {
        let shards = split_secret(TEST_SECRET, 3, 5).unwrap();

        // Encrypt all 5.
        let encrypted: Vec<_> = shards
            .iter()
            .map(|s| encrypt_shard(s, TEST_PIN).unwrap())
            .collect();

        // Decrypt 3 of them.
        let decrypted: Vec<_> = encrypted
            .iter()
            .take(3)
            .map(|e| decrypt_shard(e, TEST_PIN).unwrap())
            .collect();

        // Reconstruct.
        let recovered = reconstruct_secret(&decrypted, 3).unwrap();
        assert_eq!(recovered.as_slice(), TEST_SECRET);
    }
}
