// bn-core/src/chain.rs
// The AvatarChain — the full linked structure of an avatar's history.
//
// Analogy for TS devs: this is like an immutable array with a validated
// append operation. You can only push a new block if it correctly links
// to the current tip and carries a valid signature.

use chrono::{DateTime, Utc};

use crate::{
    block::{BlockKind, ChainBlock, GenesisBlock},
    crypto::{AvatarSigningKey, AvatarVerifyingKey},
    error::BnError,
};

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
        // Verify genesis block signature.
        self.genesis.verify()?;

        let mut expected_prev = self.genesis.hash()?;
        let mut prev_timestamp: Option<DateTime<Utc>> = Some(self.genesis.created_at);

        for (i, block) in self.blocks.iter().enumerate() {
            // Signature.
            block.verify(&self.verifying_key)?;

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

            expected_prev = block.hash()?;
            prev_timestamp = Some(block.timestamp);
        }

        Ok(())
    }

    // ── Signing ──────────────────────────────────────────────────────────────

    /// Sign arbitrary bytes with this avatar's current signing key.
    /// Exposed so higher-level protocol crates (e.g. bn-handshake) can create
    /// fresh signed proofs without the signing key ever leaving this struct.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message)
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
