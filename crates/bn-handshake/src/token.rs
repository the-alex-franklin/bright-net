// bn-handshake/src/token.rs
//
// HandshakeToken — a freshly signed proof-of-possession.
//
// Unlike transmitting an existing chain block (which could be replayed if the
// timestamp is old), a HandshakeToken is created on-demand for each handshake:
//   - Fresh timestamp  → proves the signer is active right now
//   - Random nonce     → makes the token unique even within the same second
//   - chain_tip_hash   → cryptographically links the token to the avatar chain
//   - Signed with the avatar's current key → proves key control
//
// Analogy for TS devs: this is like a short-lived signed JWT, except the
// signature covers a deterministic canonical string (not a base64url header).

use chrono::{DateTime, Utc};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use bn_core::{chain::AvatarChain, crypto::AvatarVerifyingKey};

use crate::error::HandshakeError;

/// Maximum permitted clock skew between the token's timestamp and local time.
const MAX_CLOCK_SKEW_SECS: i64 = 30;

// ── HandshakeToken ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeToken {
    /// Hex-encoded verifying (public) key of the token's creator.
    pub pubkey: String,
    /// Hex-encoded SHA-256 hash of the creator's current chain tip.
    /// Could be their genesis block hash or their latest chain block hash.
    pub chain_tip_hash: String,
    /// Number of chain blocks after genesis (0 for a brand-new avatar).
    pub chain_height: u64,
    /// 16 random bytes, hex-encoded — makes every token globally unique.
    pub nonce: String,
    /// When this token was created.
    pub timestamp: DateTime<Utc>,
    /// Ed25519 signature over the canonical bytes of all fields above.
    pub signature: String,
}

impl HandshakeToken {
    /// Create a fresh token for `chain`. Signs using `chain.sign()` so the
    /// signing key never leaves the AvatarChain struct.
    pub fn create(chain: &AvatarChain) -> Result<Self, HandshakeError> {
        let pubkey = hex::encode(chain.verifying_key.to_bytes());
        let chain_tip_hash = hex::encode(chain.tip_hash()?);
        let chain_height = chain.height();

        let mut nonce_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        let timestamp = Utc::now();
        let message =
            Self::signing_bytes(&pubkey, &chain_tip_hash, chain_height, &nonce, &timestamp);
        let signature = hex::encode(chain.sign(&message));

        Ok(HandshakeToken {
            pubkey,
            chain_tip_hash,
            chain_height,
            nonce,
            timestamp,
            signature,
        })
    }

    /// Verify the token's signature and timestamp freshness.
    /// This is called by the *receiver* of the token.
    pub fn verify(&self) -> Result<(), HandshakeError> {
        // 1. Timestamp freshness — prevents replaying old tokens.
        let now = Utc::now();
        let skew = (self.timestamp - now).num_seconds().abs();
        if skew > MAX_CLOCK_SKEW_SECS {
            return Err(HandshakeError::StaleToken(skew));
        }

        // 2. Parse the public key.
        let pubkey_bytes = hex::decode(&self.pubkey)
            .map_err(|_| HandshakeError::InvalidToken("bad pubkey hex".into()))?;
        let pubkey_arr: [u8; 32] = pubkey_bytes
            .try_into()
            .map_err(|_| HandshakeError::InvalidToken("pubkey wrong length".into()))?;
        let vk = AvatarVerifyingKey::from_bytes(&pubkey_arr)
            .map_err(|_| HandshakeError::InvalidToken("invalid pubkey".into()))?;

        // 3. Parse the signature.
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|_| HandshakeError::InvalidToken("bad signature hex".into()))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| HandshakeError::InvalidSignature)?;

        // 4. Verify the signature over the canonical message.
        let message = Self::signing_bytes(
            &self.pubkey,
            &self.chain_tip_hash,
            self.chain_height,
            &self.nonce,
            &self.timestamp,
        );
        vk.verify(&message, &sig_arr)
            .map_err(|_| HandshakeError::InvalidSignature)?;

        Ok(())
    }

    /// Deserialise the public key into a usable type.
    pub fn verifying_key(&self) -> Result<AvatarVerifyingKey, HandshakeError> {
        let bytes = hex::decode(&self.pubkey)
            .map_err(|_| HandshakeError::InvalidToken("bad pubkey hex".into()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| HandshakeError::InvalidToken("pubkey wrong length".into()))?;
        AvatarVerifyingKey::from_bytes(&arr)
            .map_err(|_| HandshakeError::InvalidToken("invalid pubkey".into()))
    }

    /// Deserialise the chain tip hash into raw bytes for recording a handshake block.
    pub fn chain_tip_hash_bytes(&self) -> Result<[u8; 32], HandshakeError> {
        let bytes = hex::decode(&self.chain_tip_hash)
            .map_err(|_| HandshakeError::InvalidToken("bad tip hash hex".into()))?;
        bytes
            .try_into()
            .map_err(|_| HandshakeError::InvalidToken("tip hash wrong length".into()))
    }

    // Deterministic canonical form:
    // "handshake-token:{pubkey}:{chain_tip_hash}:{chain_height}:{nonce}:{iso8601}"
    fn signing_bytes(
        pubkey: &str,
        chain_tip_hash: &str,
        chain_height: u64,
        nonce: &str,
        timestamp: &DateTime<Utc>,
    ) -> Vec<u8> {
        format!(
            "handshake-token:{}:{}:{}:{}:{}",
            pubkey,
            chain_tip_hash,
            chain_height,
            nonce,
            timestamp.to_rfc3339()
        )
        .into_bytes()
    }
}
