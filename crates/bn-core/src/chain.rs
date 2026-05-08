use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    block::{BlockKind, ChainBlock, GenesisBlock},
    crypto::{AvatarSigningKey, AvatarVerifyingKey},
    error::BnError,
};

#[derive(Serialize, Deserialize)]
struct ChainFile {
    genesis: GenesisBlock,
    blocks: Vec<ChainBlock>,
}

const MAX_CLOCK_SKEW_SECS: i64 = 30;

/// The complete chain for a single avatar identity.
/// Owns the signing key and maintains the ordered list of blocks.
pub struct AvatarChain {
    pub genesis: GenesisBlock,
    pub blocks: Vec<ChainBlock>,
    signing_key: AvatarSigningKey,
    pub verifying_key: AvatarVerifyingKey,
}

impl AvatarChain {
    /// Create a brand-new avatar identity.
    pub fn new(label: Option<String>) -> Result<Self, BnError> {
        let (signing_key, verifying_key) = AvatarSigningKey::generate();
        let genesis = GenesisBlock::new(&signing_key, &verifying_key, label);
        genesis.verify()?;
        Ok(AvatarChain { genesis, blocks: Vec::new(), signing_key, verifying_key })
    }

    /// Hash of the most recent block (genesis if no blocks yet).
    pub fn tip_hash(&self) -> Result<[u8; 32], BnError> {
        match self.blocks.last() {
            Some(block) => block.hash(),
            None => self.genesis.hash(),
        }
    }

    /// Number of blocks after genesis.
    pub fn height(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// Stable identifier derived from the genesis block hash.
    pub fn id(&self) -> Result<String, BnError> {
        Ok(hex::encode(self.genesis.hash()?))
    }

    /// Append a new block to the chain.
    pub fn append(&mut self, kind: BlockKind) -> Result<&ChainBlock, BnError> {
        let prev_hash = self.tip_hash()?;
        let index = self.height();
        let block = ChainBlock::new(&self.signing_key, &self.verifying_key, prev_hash, index, kind)?;
        self.validate_block(&block)?;
        self.blocks.push(block);
        Ok(self.blocks.last().unwrap())
    }

    /// Validate a single candidate block against the current chain state.
    pub fn validate_block(&self, block: &ChainBlock) -> Result<(), BnError> {
        block.verify(&self.verifying_key)?;

        let expected_index = self.height();
        if block.index != expected_index {
            return Err(BnError::ChainIntegrity(format!(
                "expected index {expected_index}, got {}",
                block.index
            )));
        }

        let expected_prev = hex::encode(self.tip_hash()?);
        if block.prev_hash != expected_prev {
            return Err(BnError::ChainIntegrity("prev_hash does not match current tip".into()));
        }

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
                return Err(BnError::Timestamp("block timestamp must be after previous block".into()));
            }
        } else if block_time < self.genesis.created_at {
            return Err(BnError::Timestamp("block timestamp must be after genesis".into()));
        }

        Ok(())
    }

    /// Validate the entire chain from genesis to tip. O(n).
    pub fn validate_full(&self) -> Result<(), BnError> {
        self.genesis.verify()?;

        let mut expected_prev = self.genesis.hash()?;
        let mut prev_timestamp: Option<DateTime<Utc>> = Some(self.genesis.created_at);

        for (i, block) in self.blocks.iter().enumerate() {
            block.verify(&self.verifying_key)?;

            if block.index != i as u64 {
                return Err(BnError::ChainIntegrity(format!(
                    "block at position {i} has index {}",
                    block.index
                )));
            }

            if block.prev_hash != hex::encode(expected_prev) {
                return Err(BnError::ChainIntegrity(format!("hash chain broken at block {i}")));
            }

            if let Some(prev_ts) = prev_timestamp {
                if block.timestamp <= prev_ts {
                    return Err(BnError::Timestamp(format!(
                        "timestamp not monotonically increasing at block {i}"
                    )));
                }
            }

            expected_prev = block.hash()?;
            prev_timestamp = Some(block.timestamp);
        }

        Ok(())
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    /// Write the chain to disk. The signing key is never included in the file.
    pub fn save(&self, path: &Path) -> Result<(), BnError> {
        let file = ChainFile { genesis: self.genesis.clone(), blocks: self.blocks.clone() };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(&file)?)?;
        Ok(())
    }

    /// Load a chain from disk. The signing key must be supplied separately.
    pub fn load(path: &Path, signing_key: AvatarSigningKey) -> Result<Self, BnError> {
        let json = std::fs::read_to_string(path)?;
        let file: ChainFile = serde_json::from_str(&json)?;

        let pubkey_bytes = hex::decode(&file.genesis.pubkey)
            .map_err(|_| BnError::Key("invalid pubkey hex in genesis".into()))?;
        let pubkey_arr: [u8; 32] = pubkey_bytes
            .try_into()
            .map_err(|_| BnError::Key("pubkey wrong length".into()))?;
        let verifying_key = AvatarVerifyingKey::from_bytes(&pubkey_arr)?;

        let chain = AvatarChain { genesis: file.genesis, blocks: file.blocks, signing_key, verifying_key };
        chain.validate_full()?;
        Ok(chain)
    }

    // ── Signing ───────────────────────────────────────────────────────────────

    /// Sign arbitrary bytes with this avatar's current signing key.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message)
    }

    /// Export the signing key bytes for secure storage.
    pub fn signing_key_bytes(&self) -> zeroize::Zeroizing<[u8; 32]> {
        self.signing_key.to_bytes()
    }

    // ── Handshake helpers ─────────────────────────────────────────────────────

    /// Record a successful handshake with a peer.
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
    pub fn validate_peer_tip(
        peer_block: &ChainBlock,
        peer_pubkey: &AvatarVerifyingKey,
    ) -> Result<(), BnError> {
        peer_block.verify(peer_pubkey)?;

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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockKind;

    #[test]
    fn genesis_block_selfverifies() {
        let chain = AvatarChain::new(Some("test-avatar".into())).unwrap();
        chain.genesis.verify().unwrap();
    }

    #[test]
    fn append_and_validate() {
        let mut chain = AvatarChain::new(None).unwrap();
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
            chain.append(BlockKind::Custom { payload_hash: hex::encode([i as u8; 32]) }).unwrap();
        }
        assert_eq!(chain.height(), 5);
        chain.validate_full().unwrap();
    }

    #[test]
    fn save_and_load_roundtrip() {
        let mut chain = AvatarChain::new(Some("persist-test".into())).unwrap();
        chain.append(BlockKind::Custom { payload_hash: hex::encode([42u8; 32]) }).unwrap();

        let dir = std::env::temp_dir().join("bn-core-test-save");
        let path = dir.join("chain.json");
        chain.save(&path).unwrap();

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
    fn tampered_prev_hash_fails_validation() {
        let mut chain = AvatarChain::new(None).unwrap();
        chain.append(BlockKind::Custom { payload_hash: hex::encode([1u8; 32]) }).unwrap();
        chain.blocks[0].prev_hash = hex::encode([0xff_u8; 32]);
        assert!(chain.validate_full().is_err(), "tampered chain should fail validation");
    }
}
