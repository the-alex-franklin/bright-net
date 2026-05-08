use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{sha256, AvatarSigningKey, AvatarVerifyingKey},
    error::BnError,
};

/// What kind of event this block records.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BlockKind {
    /// The very first block. Creates the avatar identity.
    Genesis,
    /// A completed handshake with another avatar.
    Handshake {
        peer_pubkey: String,    // hex-encoded
        peer_chain_tip: String, // hex-encoded
    },
    /// A custom payload — for application-layer extensibility.
    Custom {
        payload_hash: String, // hex-encoded SHA-256 of the actual payload
    },
}

// ── Genesis block ─────────────────────────────────────────────────────────────

/// The anchor block. Created once per avatar, never again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisBlock {
    pub pubkey: String,           // hex-encoded [u8; 32]
    pub created_at: DateTime<Utc>,
    pub label: Option<String>,
    pub signature: String,        // hex-encoded [u8; 64]
}

impl GenesisBlock {
    pub fn new(
        signing_key: &AvatarSigningKey,
        verifying_key: &AvatarVerifyingKey,
        label: Option<String>,
    ) -> Self {
        let pubkey = hex::encode(verifying_key.to_bytes());
        let created_at = Utc::now();
        let message = Self::signing_bytes(&pubkey, &created_at);
        let signature = hex::encode(signing_key.sign(&message));
        GenesisBlock { pubkey, created_at, label, signature }
    }

    pub fn verify(&self) -> Result<(), BnError> {
        let pubkey_bytes = hex::decode(&self.pubkey)
            .map_err(|_| BnError::Key("invalid pubkey hex".into()))?;
        let pubkey_arr: [u8; 32] = pubkey_bytes
            .try_into()
            .map_err(|_| BnError::Key("pubkey wrong length".into()))?;
        let verifying_key = AvatarVerifyingKey::from_bytes(&pubkey_arr)?;

        let sig_bytes = hex::decode(&self.signature)
            .map_err(|_| BnError::InvalidSignature)?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| BnError::InvalidSignature)?;

        let message = Self::signing_bytes(&self.pubkey, &self.created_at);
        verifying_key.verify(&message, &sig_arr)
    }

    pub fn hash(&self) -> Result<[u8; 32], BnError> {
        let json = serde_json::to_vec(self)?;
        Ok(sha256(&json))
    }

    fn signing_bytes(pubkey: &str, created_at: &DateTime<Utc>) -> Vec<u8> {
        format!("genesis:{}:{}", pubkey, created_at.to_rfc3339()).into_bytes()
    }
}

// ── Chain block ───────────────────────────────────────────────────────────────

/// Every block after the genesis. Forms the linked chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainBlock {
    pub prev_hash: String,  // hex-encoded [u8; 32]
    pub index: u64,
    pub kind: BlockKind,
    pub pubkey: String,     // hex-encoded [u8; 32]
    pub timestamp: DateTime<Utc>,
    pub signature: String,  // hex-encoded [u8; 64]
}

impl ChainBlock {
    pub fn new(
        signing_key: &AvatarSigningKey,
        verifying_key: &AvatarVerifyingKey,
        prev_hash: [u8; 32],
        index: u64,
        kind: BlockKind,
    ) -> Result<Self, BnError> {
        let pubkey = hex::encode(verifying_key.to_bytes());
        let prev_hash_hex = hex::encode(prev_hash);
        let timestamp = Utc::now();

        let kind_json = serde_json::to_string(&kind)?;
        let message = Self::signing_bytes(&prev_hash_hex, index, &kind_json, &pubkey, &timestamp);
        let signature = hex::encode(signing_key.sign(&message));

        Ok(ChainBlock { prev_hash: prev_hash_hex, index, kind, pubkey, timestamp, signature })
    }

    pub fn verify(&self, expected_pubkey: &AvatarVerifyingKey) -> Result<(), BnError> {
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|_| BnError::InvalidSignature)?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| BnError::InvalidSignature)?;

        let kind_json = serde_json::to_string(&self.kind)?;
        let message = Self::signing_bytes(
            &self.prev_hash, self.index, &kind_json, &self.pubkey, &self.timestamp,
        );
        expected_pubkey.verify(&message, &sig_arr)
    }

    pub fn hash(&self) -> Result<[u8; 32], BnError> {
        let json = serde_json::to_vec(self)?;
        Ok(sha256(&json))
    }

    fn signing_bytes(
        prev_hash: &str,
        index: u64,
        kind_json: &str,
        pubkey: &str,
        timestamp: &DateTime<Utc>,
    ) -> Vec<u8> {
        format!("block:{}:{}:{}:{}:{}", prev_hash, index, kind_json, pubkey, timestamp.to_rfc3339())
            .into_bytes()
    }
}
