// bn-core/src/crypto.rs
// Thin wrappers around the raw cryptographic primitives.
// Keeps the rest of the codebase from having to import ed25519-dalek directly.

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::BnError;

// ── Key types ────────────────────────────────────────────────────────────────

/// A signing (private) key.
/// `SigningKey` implements `ZeroizeOnDrop`, so its secret bytes are
/// automatically wiped from memory when this value is dropped.
/// We don't wrap it in `Zeroizing<>` because that requires `T: Zeroize`
/// (a different, stricter trait), which `SigningKey` doesn't implement.
pub struct AvatarSigningKey(pub(crate) SigningKey);

/// A verifying (public) key. Safe to share with the world.
#[derive(Clone)]
pub struct AvatarVerifyingKey(pub(crate) VerifyingKey);

impl AvatarSigningKey {
    /// Generate a fresh Ed25519 keypair from the OS entropy source.
    pub fn generate() -> (AvatarSigningKey, AvatarVerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (
            AvatarSigningKey(signing_key),
            AvatarVerifyingKey(verifying_key),
        )
    }

    /// Produce an Ed25519 signature over arbitrary bytes.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }

    /// Export the raw 32-byte private key wrapped in Zeroizing so the
    /// caller's copy is also wiped on drop — handle with care.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// Reconstruct from raw bytes (e.g. after shard reassembly).
    /// `SigningKey::from_bytes` in ed25519-dalek v2 is infallible.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        AvatarSigningKey(SigningKey::from_bytes(bytes))
    }
}

impl AvatarVerifyingKey {
    /// Verify that `signature_bytes` is a valid Ed25519 signature over
    /// `message` produced by the private half of this public key.
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8; 64]) -> Result<(), BnError> {
        let sig = Signature::from_bytes(signature_bytes);
        self.0.verify(message, &sig).map_err(Into::into)
    }

    /// Raw 32-byte public key — safe to transmit in handshakes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, BnError> {
        VerifyingKey::from_bytes(bytes)
            .map(AvatarVerifyingKey)
            .map_err(|_| BnError::Key("invalid verifying key bytes".into()))
    }
}

// ── Hashing helpers ──────────────────────────────────────────────────────────

/// SHA-256 over arbitrary bytes → 32-byte digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// ── Symmetric encryption ─────────────────────────────────────────────────────

/// Encrypt arbitrary bytes with a 32-byte key.
/// Output: 12-byte random nonce prepended to ciphertext+tag.
pub fn seal_bytes(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, crate::error::BnError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| crate::error::BnError::Serialization(format!("seal failed: {e}")))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt bytes produced by `seal_bytes`. Returns zeroized plaintext.
pub fn open_bytes(sealed: &[u8], key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, crate::error::BnError> {
    if sealed.len() < 12 {
        return Err(crate::error::BnError::Key("sealed data too short".into()));
    }
    let (nonce_bytes, ct) = sealed.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map(Zeroizing::new)
        .map_err(|_| crate::error::BnError::Key("decryption failed — wrong key or corrupted data".into()))
}
