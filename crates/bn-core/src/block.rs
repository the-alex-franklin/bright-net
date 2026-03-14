// bn-core/src/block.rs
// Block data structures for the avatar chain.
//
// Two block kinds:
//   GenesisBlock — created once when an avatar is first initialised.
//                  Its hash becomes the immutable anchor for the entire chain.
//   ChainBlock   — every subsequent event: handshakes, key rotations, etc.
//
// Serde's `#[derive(Serialize, Deserialize)]` is like TypeScript's
// `satisfies` + a codec, but generated at compile time with zero overhead.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{sha256, AvatarSigningKey, AvatarVerifyingKey},
    error::BnError,
};

// ── Block kind tag ────────────────────────────────────────────────────────────

/// What kind of event this block records.
/// In Rust, enums are algebraic types — each variant can carry different data.
/// Think of it like a TypeScript discriminated union:
///   type BlockKind = { kind: "genesis" } | { kind: "handshake"; peer: string } | ...
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BlockKind {
    /// The very first block. Creates the avatar identity.
    Genesis,
    /// A completed blockchain handshake with another avatar.
    Handshake {
        /// Public key of the peer we connected to.
        peer_pubkey: String, // hex-encoded
        /// Their chain tip hash at the time of the handshake.
        peer_chain_tip: String, // hex-encoded
    },
    /// The root signing key has been rotated (e.g. after device loss).
    KeyRotation {
        /// The new public key replacing the old one.
        new_pubkey: String, // hex-encoded
    },
    /// A custom payload — for application-layer extensibility.
    Custom {
        payload_hash: String, // hex-encoded SHA-256 of the actual payload
    },
}

// ── Genesis block ─────────────────────────────────────────────────────────────

/// The anchor block. Created once per avatar, never again.
/// Its hash is what gets sharded via Shamir's and stored across devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisBlock {
    /// The avatar's initial public key.
    pub pubkey: String, // hex-encoded [u8; 32]
    /// When the avatar was created.
    pub created_at: DateTime<Utc>,
    /// Optional human-readable label (for local UX only, never transmitted).
    pub label: Option<String>,
    /// Ed25519 signature over the canonical bytes of this block's fields.
    pub signature: String, // hex-encoded [u8; 64]
}

impl GenesisBlock {
    /// Create and sign a new genesis block.
    pub fn new(
        signing_key: &AvatarSigningKey,
        verifying_key: &AvatarVerifyingKey,
        label: Option<String>,
    ) -> Self {
        let pubkey = hex::encode(verifying_key.to_bytes());
        let created_at = Utc::now();

        // The bytes we sign: pubkey ++ timestamp (as RFC3339 string).
        // Deterministic serialization is critical — the verifier must
        // produce the exact same byte sequence.
        let message = Self::signing_bytes(&pubkey, &created_at);
        let signature = hex::encode(signing_key.sign(&message));

        GenesisBlock {
            pubkey,
            created_at,
            label,
            signature,
        }
    }

    /// Verify the block's own signature.
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

    /// Hash of this block — becomes the `prev_hash` of block #1.
    pub fn hash(&self) -> Result<[u8; 32], BnError> {
        let json = serde_json::to_vec(self)?;
        Ok(sha256(&json))
    }

    fn signing_bytes(pubkey: &str, created_at: &DateTime<Utc>) -> Vec<u8> {
        // Canonical form: "genesis:{pubkey}:{iso8601_timestamp}"
        format!("genesis:{}:{}", pubkey, created_at.to_rfc3339()).into_bytes()
    }
}

// ── Chain block ───────────────────────────────────────────────────────────────

/// Every block after the genesis. Forms the linked chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainBlock {
    /// SHA-256 of the previous block (genesis or chain). This is what
    /// makes tampering detectable — changing any block invalidates all
    /// subsequent hashes, just like a Git commit graph.
    pub prev_hash: String, // hex-encoded [u8; 32]
    /// Sequence number (0-indexed from genesis, so block #1 has index 0).
    pub index: u64,
    /// What happened in this block.
    pub kind: BlockKind,
    /// Current public key at the time of this block.
    pub pubkey: String, // hex-encoded [u8; 32]
    /// An ephemeral one-time-use public key for this session's key exchange.
    /// Burned after use — enables forward secrecy.
    pub ephemeral_pubkey: String, // hex-encoded [u8; 32]
    /// Block creation timestamp.
    pub timestamp: DateTime<Utc>,
    /// Ed25519 signature over the canonical bytes of this block's fields.
    pub signature: String, // hex-encoded [u8; 64]
}

impl ChainBlock {
    /// Create and sign a new chain block.
    pub fn new(
        signing_key: &AvatarSigningKey,
        verifying_key: &AvatarVerifyingKey,
        prev_hash: [u8; 32],
        index: u64,
        kind: BlockKind,
    ) -> Result<Self, BnError> {
        // Generate a fresh ephemeral keypair for this block's session.
        let (ephemeral_signing, ephemeral_verifying) = AvatarSigningKey::generate();
        let _ = ephemeral_signing; // Immediately drop the ephemeral private key.

        let pubkey = hex::encode(verifying_key.to_bytes());
        let ephemeral_pubkey = hex::encode(ephemeral_verifying.to_bytes());
        let prev_hash_hex = hex::encode(prev_hash);
        let timestamp = Utc::now();

        let kind_json = serde_json::to_string(&kind)?;
        let message = Self::signing_bytes(
            &prev_hash_hex,
            index,
            &kind_json,
            &pubkey,
            &ephemeral_pubkey,
            &timestamp,
        );
        let signature = hex::encode(signing_key.sign(&message));

        Ok(ChainBlock {
            prev_hash: prev_hash_hex,
            index,
            kind,
            pubkey,
            ephemeral_pubkey,
            timestamp,
            signature,
        })
    }

    /// Verify the block's own signature.
    pub fn verify(&self, expected_pubkey: &AvatarVerifyingKey) -> Result<(), BnError> {
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|_| BnError::InvalidSignature)?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| BnError::InvalidSignature)?;

        let kind_json = serde_json::to_string(&self.kind)?;
        let message = Self::signing_bytes(
            &self.prev_hash,
            self.index,
            &kind_json,
            &self.pubkey,
            &self.ephemeral_pubkey,
            &self.timestamp,
        );
        expected_pubkey.verify(&message, &sig_arr)
    }

    /// Hash of this block — becomes the `prev_hash` of the next block.
    pub fn hash(&self) -> Result<[u8; 32], BnError> {
        let json = serde_json::to_vec(self)?;
        Ok(sha256(&json))
    }

    fn signing_bytes(
        prev_hash: &str,
        index: u64,
        kind_json: &str,
        pubkey: &str,
        ephemeral_pubkey: &str,
        timestamp: &DateTime<Utc>,
    ) -> Vec<u8> {
        // Canonical form: pipe-delimited fields, deterministic ordering.
        format!(
            "block:{}:{}:{}:{}:{}:{}",
            prev_hash,
            index,
            kind_json,
            pubkey,
            ephemeral_pubkey,
            timestamp.to_rfc3339()
        )
        .into_bytes()
    }
}
