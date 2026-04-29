// bn-core/src/chain.rs
// The AvatarChain — the full linked structure of an avatar's history.
//
// Analogy for TS devs: this is like an immutable array with a validated
// append operation. You can only push a new block if it correctly links
// to the current tip and carries a valid signature.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    block::{BlockKind, ChainBlock, GenesisBlock},
    crypto::{AvatarSigningKey, AvatarVerifyingKey},
    error::BnError,
};

// Serializable representation of a chain — no private key.
// The signing key lives in shards and is passed in at load time.
#[derive(Serialize, Deserialize)]
struct ChainFile {
    genesis: GenesisBlock,
    blocks: Vec<ChainBlock>,
}

// ── Key resolution ────────────────────────────────────────────────────────────

// Walk a chain's blocks to find the currently-active verifying key.
// Starts at genesis.pubkey and advances through any KeyRotation blocks.
// Called by validate_full (to replay key history) and load (to find the
// current key after a chain with rotations is read from disk).
fn resolve_verifying_key(
    genesis: &GenesisBlock,
    blocks: &[ChainBlock],
) -> Result<AvatarVerifyingKey, BnError> {
    let mut pubkey_hex = genesis.pubkey.as_str();

    for block in blocks {
        if let BlockKind::KeyRotation { ref new_pubkey } = block.kind {
            pubkey_hex = new_pubkey.as_str();
        }
    }

    let bytes = hex::decode(pubkey_hex)
        .map_err(|_| BnError::Key("invalid pubkey hex resolving active key".into()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| BnError::Key("pubkey wrong length resolving active key".into()))?;
    AvatarVerifyingKey::from_bytes(&arr)
}

// ── Maximum allowed clock skew when validating timestamps ────────────────────
// During a handshake, a peer's block timestamp must be within this window
// of our local clock. Prevents replay attacks with old chain tips.
const MAX_CLOCK_SKEW_SECS: i64 = 30;

// ── AvatarChain ──────────────────────────────────────────────────────────────

/// The complete chain for a single avatar identity.
/// Owns the signing key and maintains the ordered list of blocks.
pub struct AvatarChain {
    /// The first block — immutable anchor of the identity.
    pub genesis: GenesisBlock,
    /// All subsequent blocks in order. Empty for a brand-new avatar.
    pub blocks: Vec<ChainBlock>,
    /// The active signing key. Kept in memory; persisted only as a shard.
    signing_key: AvatarSigningKey,
    /// The active verifying (public) key.
    pub verifying_key: AvatarVerifyingKey,
}

impl AvatarChain {
    /// Initialise a brand-new avatar. Generates a keypair, creates the
    /// genesis block, and returns the chain ready for use.
    pub fn new(label: Option<String>) -> Result<Self, BnError> {
        let (signing_key, verifying_key) = AvatarSigningKey::generate();
        let genesis = GenesisBlock::new(&signing_key, &verifying_key, label);

        // Immediately verify our own genesis to catch any internal bugs.
        genesis.verify()?;

        Ok(AvatarChain {
            genesis,
            blocks: Vec::new(),
            signing_key,
            verifying_key,
        })
    }

    /// The hash of the most recent block (could be genesis or a chain block).
    /// This is what gets transmitted during a handshake as the "chain tip".
    pub fn tip_hash(&self) -> Result<[u8; 32], BnError> {
        match self.blocks.last() {
            Some(block) => block.hash(),
            None => self.genesis.hash(),
        }
    }

    /// How many chain blocks exist after the genesis.
    pub fn height(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// Append a new block to the chain.
    /// Validates linkage and timestamp before accepting.
    pub fn append(&mut self, kind: BlockKind) -> Result<&ChainBlock, BnError> {
        let prev_hash = self.tip_hash()?;
        let index = self.height();

        let block = ChainBlock::new(
            &self.signing_key,
            &self.verifying_key,
            prev_hash,
            index,
            kind,
        )?;

        // Immediately validate what we just produced.
        self.validate_block(&block)?;
        self.blocks.push(block);

        // `unwrap` is safe here — we just pushed.
        Ok(self.blocks.last().unwrap())
    }

    /// Validate a single candidate block against the current chain state.
    /// Used both for our own appends and when receiving a peer's blocks.
    pub fn validate_block(&self, block: &ChainBlock) -> Result<(), BnError> {
        // 1. Signature check.
        block.verify(&self.verifying_key)?;

        // 2. Index must be exactly height (no gaps, no rewrites).
        let expected_index = self.height();
        if block.index != expected_index {
            return Err(BnError::ChainIntegrity(format!(
                "expected index {expected_index}, got {}",
                block.index
            )));
        }

        // 3. prev_hash must match our current tip.
        let expected_prev = hex::encode(self.tip_hash()?);
        if block.prev_hash != expected_prev {
            return Err(BnError::ChainIntegrity(
                "prev_hash does not match current tip".into(),
            ));
        }

        // 4. Timestamp must be after the previous block's timestamp,
        //    and not unreasonably far in the future (replay / clock-skew).
        let block_time = block.timestamp;
        let now = Utc::now();

        if block_time > now + chrono::Duration::seconds(MAX_CLOCK_SKEW_SECS) {
            return Err(BnError::Timestamp(format!(
                "block timestamp {} is too far in the future",
                block_time
            )));
        }

        if let Some(prev_block) = self.blocks.last() {
            if block_time <= prev_block.timestamp {
                return Err(BnError::Timestamp(
                    "block timestamp must be after previous block".into(),
                ));
            }
        } else if block_time < self.genesis.created_at {
            return Err(BnError::Timestamp(
                "block timestamp must be after genesis".into(),
            ));
        }

        Ok(())
    }

    /// Validate the entire chain from genesis to tip.
    /// O(n) — call this on load, not on every append.
    pub fn validate_full(&self) -> Result<(), BnError> {
        self.genesis.verify()?;

        let mut expected_prev = self.genesis.hash()?;
        let mut prev_timestamp: Option<DateTime<Utc>> = Some(self.genesis.created_at);

        // Replay key history: start at genesis key, advance through rotations.
        let mut active_key = resolve_verifying_key(&self.genesis, &[])?;

        for (i, block) in self.blocks.iter().enumerate() {
            // Signature — verified against the key active at this point in history.
            block.verify(&active_key)?;

            // Index continuity.
            if block.index != i as u64 {
                return Err(BnError::ChainIntegrity(format!(
                    "block at position {i} has index {}",
                    block.index
                )));
            }

            // Hash linkage.
            if block.prev_hash != hex::encode(expected_prev) {
                return Err(BnError::ChainIntegrity(format!(
                    "hash chain broken at block {i}"
                )));
            }

            // Timestamp ordering.
            if let Some(prev_ts) = prev_timestamp {
                if block.timestamp <= prev_ts {
                    return Err(BnError::Timestamp(format!(
                        "timestamp not monotonically increasing at block {i}"
                    )));
                }
            }

            // Advance the active key if this block is a rotation.
            // The rotation block itself is signed by the OLD key (verified above);
            // everything after it is signed by the new key.
            if let BlockKind::KeyRotation { ref new_pubkey } = block.kind {
                let bytes = hex::decode(new_pubkey)
                    .map_err(|_| BnError::Key(format!("invalid new_pubkey hex at block {i}")))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| BnError::Key(format!("new_pubkey wrong length at block {i}")))?;
                active_key = AvatarVerifyingKey::from_bytes(&arr)?;
            }

            expected_prev = block.hash()?;
            prev_timestamp = Some(block.timestamp);
        }

        Ok(())
    }

    // ── Persistence ──────────────────────────────────────────────────────────

    /// A stable identifier for this avatar derived from its genesis block hash.
    /// Used as the directory name under ~/.bright-net/avatars/<id>/.
    pub fn id(&self) -> Result<String, BnError> {
        Ok(hex::encode(self.genesis.hash()?))
    }

    /// Write the chain to disk. The signing key is never included in the file —
    /// it lives in shards and is supplied at load time.
    /// Creates parent directories if they don't exist.
    pub fn save(&self, path: &Path) -> Result<(), BnError> {
        let file = ChainFile {
            genesis: self.genesis.clone(),
            blocks: self.blocks.clone(),
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(&file)?)?;
        Ok(())
    }

    /// Load a chain from disk. The signing key must be supplied separately
    /// (reconstructed from shards). Runs validate_full before returning.
    pub fn load(path: &Path, signing_key: AvatarSigningKey) -> Result<Self, BnError> {
        let json = std::fs::read_to_string(path)?;
        let file: ChainFile = serde_json::from_str(&json)?;

        // Derive the current verifying key by replaying any key rotations.
        let verifying_key = resolve_verifying_key(&file.genesis, &file.blocks)?;

        let chain = AvatarChain {
            genesis: file.genesis,
            blocks: file.blocks,
            signing_key,
            verifying_key,
        };
        chain.validate_full()?;
        Ok(chain)
    }

    // ── Key rotation ─────────────────────────────────────────────────────────

    /// Rotate the avatar's signing key. Appends a KeyRotation block signed
    /// with the OLD key, then swaps to the new keypair.
    ///
    /// After this call, all future blocks are signed with the new key.
    /// The old key is dropped (and zeroed by ed25519-dalek's ZeroizeOnDrop).
    /// Callers must re-shard and redistribute after rotating.
    pub fn rotate_key(&mut self) -> Result<(), BnError> {
        let (new_signing_key, new_verifying_key) = AvatarSigningKey::generate();
        let new_pubkey_hex = hex::encode(new_verifying_key.to_bytes());

        // Sign the rotation block with the current (old) key via append.
        // self.verifying_key is still the old key here, so validate_block passes.
        self.append(BlockKind::KeyRotation {
            new_pubkey: new_pubkey_hex,
        })?;

        // Swap. The old signing key is dropped and zeroed here.
        self.signing_key = new_signing_key;
        self.verifying_key = new_verifying_key;

        Ok(())
    }

    // ── Signing ──────────────────────────────────────────────────────────────

    /// Sign arbitrary bytes with this avatar's current signing key.
    /// Exposed so higher-level protocol crates (e.g. bn-handshake) can create
    /// fresh signed proofs without the signing key ever leaving this struct.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message)
    }

    /// Export the current signing key bytes for secure storage.
    /// Caller is responsible for encrypting before writing to disk.
    /// Wrapped in Zeroizing so the caller's copy is wiped on drop.
    pub(crate) fn signing_key_bytes(&self) -> zeroize::Zeroizing<[u8; 32]> {
        self.signing_key.to_bytes()
    }

    // ── Handshake helpers ────────────────────────────────────────────────────

    /// Record a successful outbound handshake with a peer.
    pub fn record_handshake(
        &mut self,
        peer_pubkey: &AvatarVerifyingKey,
        peer_tip: [u8; 32],
    ) -> Result<&ChainBlock, BnError> {
        self.append(BlockKind::Handshake {
            peer_pubkey: hex::encode(peer_pubkey.to_bytes()),
            peer_chain_tip: hex::encode(peer_tip),
        })
    }

    /// Validate a peer's chain tip during a handshake.
    ///
    /// We don't have their full chain — only their tip block and pubkey.
    /// We check signature + timestamp to decide whether to proceed.
    pub fn validate_peer_tip(
        peer_block: &ChainBlock,
        peer_pubkey: &AvatarVerifyingKey,
    ) -> Result<(), BnError> {
        // Signature must be valid.
        peer_block.verify(peer_pubkey)?;

        // Timestamp must be within clock-skew window of now.
        let now = Utc::now();
        let skew = (peer_block.timestamp - now).num_seconds().abs();
        if skew > MAX_CLOCK_SKEW_SECS {
            return Err(BnError::Timestamp(format!(
                "peer tip timestamp skew of {skew}s exceeds maximum of {MAX_CLOCK_SKEW_SECS}s"
            )));
        }

        Ok(())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockKind;

    // In Rust, `#[test]` marks a function as a test. `cargo test` discovers
    // and runs them automatically — no test runner configuration needed.

    #[test]
    fn genesis_block_selfverifies() {
        let chain = AvatarChain::new(Some("test-avatar".into())).unwrap();
        chain.genesis.verify().unwrap();
    }

    #[test]
    fn append_and_validate() {
        let mut chain = AvatarChain::new(None).unwrap();

        // Record a fake handshake.
        let (_, peer_verifying) = AvatarSigningKey::generate();
        let fake_tip = [0u8; 32];
        chain.record_handshake(&peer_verifying, fake_tip).unwrap();

        assert_eq!(chain.height(), 1);
        chain.validate_full().unwrap();
    }

    #[test]
    fn multiple_blocks_chain_correctly() {
        let mut chain = AvatarChain::new(Some("multi-block".into())).unwrap();

        for i in 0..5 {
            chain
                .append(BlockKind::Custom {
                    payload_hash: hex::encode([i as u8; 32]),
                })
                .unwrap();
        }

        assert_eq!(chain.height(), 5);
        chain.validate_full().unwrap();
    }

    #[test]
    fn save_and_load_roundtrip() {
        let mut chain = AvatarChain::new(Some("persist-test".into())).unwrap();
        chain
            .append(BlockKind::Custom {
                payload_hash: hex::encode([42u8; 32]),
            })
            .unwrap();

        let dir = std::env::temp_dir().join("bn-core-test-save");
        let path = dir.join("chain.json");
        chain.save(&path).unwrap();

        // Extract the signing key bytes before moving the chain.
        let key_bytes = chain.signing_key.to_bytes();
        let signing_key = crate::crypto::AvatarSigningKey::from_bytes(&key_bytes);

        let loaded = AvatarChain::load(&path, signing_key).unwrap();
        assert_eq!(loaded.height(), chain.height());
        assert_eq!(
            hex::encode(loaded.tip_hash().unwrap()),
            hex::encode(chain.tip_hash().unwrap())
        );
        loaded.validate_full().unwrap();

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn key_rotation_validates_full_chain() {
        let mut chain = AvatarChain::new(Some("rotation-test".into())).unwrap();

        chain.append(BlockKind::Custom { payload_hash: hex::encode([1u8; 32]) }).unwrap();
        chain.rotate_key().unwrap();
        chain.append(BlockKind::Custom { payload_hash: hex::encode([2u8; 32]) }).unwrap();

        // height: 1 custom + 1 rotation + 1 custom = 3
        assert_eq!(chain.height(), 3);
        chain.validate_full().unwrap();
    }

    #[test]
    fn multiple_rotations_validate() {
        let mut chain = AvatarChain::new(None).unwrap();
        chain.rotate_key().unwrap();
        chain.rotate_key().unwrap();
        chain.append(BlockKind::Custom { payload_hash: hex::encode([9u8; 32]) }).unwrap();
        chain.validate_full().unwrap();
    }

    #[test]
    fn save_load_roundtrip_after_rotation() {
        let mut chain = AvatarChain::new(Some("rotation-persist".into())).unwrap();
        chain.append(BlockKind::Custom { payload_hash: hex::encode([1u8; 32]) }).unwrap();
        chain.rotate_key().unwrap();
        chain.append(BlockKind::Custom { payload_hash: hex::encode([2u8; 32]) }).unwrap();

        let dir = std::env::temp_dir().join("bn-core-test-rotation");
        let path = dir.join("chain.json");
        chain.save(&path).unwrap();

        let key_bytes = chain.signing_key.to_bytes();
        let signing_key = crate::crypto::AvatarSigningKey::from_bytes(&key_bytes);

        let loaded = AvatarChain::load(&path, signing_key).unwrap();
        assert_eq!(loaded.height(), chain.height());
        assert_eq!(
            hex::encode(loaded.tip_hash().unwrap()),
            hex::encode(chain.tip_hash().unwrap()),
        );
        loaded.validate_full().unwrap();

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tampered_prev_hash_fails_validation() {
        let mut chain = AvatarChain::new(None).unwrap();
        chain
            .append(BlockKind::Custom {
                payload_hash: hex::encode([1u8; 32]),
            })
            .unwrap();

        // Tamper with the prev_hash of the second block.
        chain.blocks[0].prev_hash = hex::encode([0xff_u8; 32]);

        let result = chain.validate_full();
        assert!(result.is_err(), "tampered chain should fail validation");
    }
}
