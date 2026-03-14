// bn-core/src/crypto.rs
// Thin wrappers around the raw cryptographic primitives.
// Keeps the rest of the codebase from having to import ed25519-dalek directly.

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
