use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::BnError;

/// A signing (private) key. Zeroed from memory on drop.
pub struct AvatarSigningKey(pub(crate) SigningKey);

/// A verifying (public) key. Safe to share.
#[derive(Clone)]
pub struct AvatarVerifyingKey(pub(crate) VerifyingKey);

impl AvatarSigningKey {
    pub fn generate() -> (AvatarSigningKey, AvatarVerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (AvatarSigningKey(signing_key), AvatarVerifyingKey(verifying_key))
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        AvatarSigningKey(SigningKey::from_bytes(bytes))
    }
}

impl AvatarVerifyingKey {
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8; 64]) -> Result<(), BnError> {
        let sig = Signature::from_bytes(signature_bytes);
        self.0.verify(message, &sig).map_err(Into::into)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, BnError> {
        VerifyingKey::from_bytes(bytes)
            .map(AvatarVerifyingKey)
            .map_err(|_| BnError::Key("invalid verifying key bytes".into()))
    }
}

/// SHA-256 over arbitrary bytes → 32-byte digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
