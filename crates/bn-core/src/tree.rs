// bn-core/src/tree.rs
//
// AvatarTree — a root identity anchor with any number of avatar branches.
//
// Structure (flat star, not a deep tree):
//
//   Root Genesis Block  ←  sharded signing key
//       ├── Branch: "work"      (full AvatarChain, own keypair, own genesis)
//       ├── Branch: "personal"  (full AvatarChain, own keypair, own genesis)
//       └── Branch: "gaming"    (full AvatarChain, own keypair, own genesis)
//
// The root doesn't grow its own chain of blocks — it's an anchor and
// certifying authority only. Each branch is an independent AvatarChain.
//
// The root signing key is what gets sharded via bn-shards. Branch signing
// keys are stored encrypted on disk, keyed by a hash derived from the root
// key, so the daemon only needs the root key to unlock everything.
//
// External peers see exactly one branch at a time. The root and all sibling
// branches are invisible to them.

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    block::GenesisBlock,
    chain::AvatarChain,
    crypto::{open_bytes, seal_bytes, sha256, AvatarSigningKey, AvatarVerifyingKey},
    error::BnError,
};

// ── BranchCertification ───────────────────────────────────────────────────────

/// Signed proof that a branch belongs to this root.
/// Private to the user — never transmitted during handshakes.
/// The root signing key signs this; verification requires the root verifying key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchCertification {
    /// Hash of the root genesis block — the permanent identity anchor.
    pub root_genesis_hash: String, // hex
    /// Hash of this branch's genesis block — uniquely identifies the branch.
    pub branch_genesis_hash: String, // hex
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Ed25519 signature by the root key over the canonical bytes of all fields above.
    pub signature: String, // hex
}

impl BranchCertification {
    pub(crate) fn create(
        root_signing_key: &AvatarSigningKey,
        root_genesis_hash: [u8; 32],
        branch_genesis_hash: [u8; 32],
        label: Option<String>,
    ) -> Self {
        let root_genesis_hash = hex::encode(root_genesis_hash);
        let branch_genesis_hash = hex::encode(branch_genesis_hash);
        let created_at = Utc::now();

        let message = Self::signing_bytes(
            &root_genesis_hash,
            &branch_genesis_hash,
            label.as_deref(),
            &created_at,
        );
        let signature = hex::encode(root_signing_key.sign(&message));

        BranchCertification {
            root_genesis_hash,
            branch_genesis_hash,
            label,
            created_at,
            signature,
        }
    }

    /// Verify this certification against the root's verifying key.
    pub fn verify(&self, root_verifying_key: &AvatarVerifyingKey) -> Result<(), BnError> {
        let sig_bytes = hex::decode(&self.signature).map_err(|_| BnError::InvalidSignature)?;
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| BnError::InvalidSignature)?;
        let message = Self::signing_bytes(
            &self.root_genesis_hash,
            &self.branch_genesis_hash,
            self.label.as_deref(),
            &self.created_at,
        );
        root_verifying_key.verify(&message, &sig_arr)
    }

    fn signing_bytes(
        root_genesis_hash: &str,
        branch_genesis_hash: &str,
        label: Option<&str>,
        created_at: &DateTime<Utc>,
    ) -> Vec<u8> {
        format!(
            "branch-cert:{}:{}:{}:{}",
            root_genesis_hash,
            branch_genesis_hash,
            label.unwrap_or(""),
            created_at.to_rfc3339(),
        )
        .into_bytes()
    }
}

// ── AvatarBranch ──────────────────────────────────────────────────────────────

pub struct AvatarBranch {
    pub chain: AvatarChain,
    pub cert: BranchCertification,
}

// ── AvatarTree ────────────────────────────────────────────────────────────────

pub struct AvatarTree {
    /// The root identity anchor. Its hash is sharded across devices.
    pub root_genesis: GenesisBlock,
    /// The root signing key. Reconstructed from shards at daemon start, zeroed on drop.
    root_signing_key: AvatarSigningKey,
    /// The root verifying (public) key.
    pub root_verifying_key: AvatarVerifyingKey,
    /// All avatar branches keyed by branch ID (hex of branch genesis hash).
    branches: HashMap<String, AvatarBranch>,
}

// Derive a 32-byte encryption key for a branch's signing key.
// Input is the root signing key + branch ID — so only the root key can
// produce the correct decryption key for any given branch.
fn branch_enc_key(root_signing_key: &AvatarSigningKey, branch_id: &str) -> [u8; 32] {
    let root_bytes = root_signing_key.to_bytes();
    let mut data = b"branch-key-enc:".to_vec();
    data.extend_from_slice(&*root_bytes);
    data.push(b':');
    data.extend_from_slice(branch_id.as_bytes());
    sha256(&data)
}

impl AvatarTree {
    // ── Construction ─────────────────────────────────────────────────────────

    /// Create a new root identity. All avatar branches will stem from this genesis.
    pub fn new(label: Option<String>) -> Result<Self, BnError> {
        let (root_signing_key, root_verifying_key) = AvatarSigningKey::generate();
        let root_genesis = GenesisBlock::new(&root_signing_key, &root_verifying_key, label);
        root_genesis.verify()?;

        Ok(AvatarTree {
            root_genesis,
            root_signing_key,
            root_verifying_key,
            branches: HashMap::new(),
        })
    }

    /// The stable identifier for this root, derived from its genesis block hash.
    pub fn root_id(&self) -> Result<String, BnError> {
        Ok(hex::encode(self.root_genesis.hash()?))
    }

    /// Export root signing key bytes for sharding. Wrapped in Zeroizing.
    pub fn root_signing_key_bytes(&self) -> Zeroizing<[u8; 32]> {
        self.root_signing_key.to_bytes()
    }

    // ── Branch management ─────────────────────────────────────────────────────

    /// Create a new avatar branch and add it to the tree.
    /// Returns the branch ID (hex of branch genesis hash).
    pub fn new_branch(&mut self, label: Option<String>) -> Result<String, BnError> {
        let chain = AvatarChain::new(label.clone())?;
        let branch_id = chain.id()?;

        let cert = BranchCertification::create(
            &self.root_signing_key,
            self.root_genesis.hash()?,
            chain.genesis.hash()?,
            label,
        );
        cert.verify(&self.root_verifying_key)?;

        self.branches.insert(branch_id.clone(), AvatarBranch { chain, cert });
        Ok(branch_id)
    }

    pub fn branch(&self, id: &str) -> Option<&AvatarBranch> {
        self.branches.get(id)
    }

    pub fn branch_mut(&mut self, id: &str) -> Option<&mut AvatarBranch> {
        self.branches.get_mut(id)
    }

    pub fn branch_ids(&self) -> Vec<&str> {
        self.branches.keys().map(String::as_str).collect()
    }

    pub fn branch_count(&self) -> usize {
        self.branches.len()
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    /// Save the tree to disk.
    ///
    /// Directory layout under `base`:
    /// ```text
    /// base/
    ///   root/genesis.json
    ///   branches/<branch-id>/chain.json
    ///   branches/<branch-id>/cert.json
    ///   branches/<branch-id>/key.enc   ← signing key, encrypted with root-derived key
    /// ```
    pub fn save(&self, base: &Path) -> Result<(), BnError> {
        let root_dir = base.join("root");
        std::fs::create_dir_all(&root_dir)?;
        std::fs::write(
            root_dir.join("genesis.json"),
            serde_json::to_string_pretty(&self.root_genesis)?,
        )?;

        for (branch_id, branch) in &self.branches {
            let branch_dir = base.join("branches").join(branch_id);
            std::fs::create_dir_all(&branch_dir)?;

            branch.chain.save(&branch_dir.join("chain.json"))?;

            std::fs::write(
                branch_dir.join("cert.json"),
                serde_json::to_string_pretty(&branch.cert)?,
            )?;

            let enc_key = branch_enc_key(&self.root_signing_key, branch_id);
            let key_bytes = branch.chain.signing_key_bytes();
            let sealed = seal_bytes(&*key_bytes, &enc_key)?;
            std::fs::write(branch_dir.join("key.enc"), &sealed)?;
        }

        Ok(())
    }

    /// Load a tree from disk.
    /// The root signing key must be supplied (reconstructed from shards by the caller).
    pub fn load(base: &Path, root_signing_key: AvatarSigningKey) -> Result<Self, BnError> {
        let root_genesis: GenesisBlock = serde_json::from_str(
            &std::fs::read_to_string(base.join("root").join("genesis.json"))?,
        )?;
        root_genesis.verify()?;

        let root_pubkey_bytes = hex::decode(&root_genesis.pubkey)
            .map_err(|_| BnError::Key("invalid root pubkey hex".into()))?;
        let root_pubkey_arr: [u8; 32] = root_pubkey_bytes
            .try_into()
            .map_err(|_| BnError::Key("root pubkey wrong length".into()))?;
        let root_verifying_key = AvatarVerifyingKey::from_bytes(&root_pubkey_arr)?;

        let mut branches = HashMap::new();
        let branches_dir = base.join("branches");

        if branches_dir.exists() {
            for entry in std::fs::read_dir(&branches_dir)? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let branch_id = entry.file_name().to_string_lossy().into_owned();
                let branch_dir = entry.path();

                // Decrypt branch signing key using root-derived enc key.
                let enc_key = branch_enc_key(&root_signing_key, &branch_id);
                let sealed = std::fs::read(branch_dir.join("key.enc"))?;
                let key_plain = open_bytes(&sealed, &enc_key)?;
                let key_arr: [u8; 32] = key_plain.as_slice()
                    .try_into()
                    .map_err(|_| BnError::Key("branch key wrong length".into()))?;
                let branch_signing_key = AvatarSigningKey::from_bytes(&key_arr);

                let chain =
                    AvatarChain::load(&branch_dir.join("chain.json"), branch_signing_key)?;

                let cert: BranchCertification = serde_json::from_str(
                    &std::fs::read_to_string(branch_dir.join("cert.json"))?,
                )?;
                cert.verify(&root_verifying_key)?;

                branches.insert(branch_id, AvatarBranch { chain, cert });
            }
        }

        Ok(AvatarTree {
            root_genesis,
            root_signing_key,
            root_verifying_key,
            branches,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockKind;

    #[test]
    fn new_tree_and_branches() {
        let mut tree = AvatarTree::new(Some("root".into())).unwrap();
        let work_id = tree.new_branch(Some("work".into())).unwrap();
        let personal_id = tree.new_branch(Some("personal".into())).unwrap();

        assert_eq!(tree.branch_count(), 2);
        assert!(tree.branch(&work_id).is_some());
        assert!(tree.branch(&personal_id).is_some());
    }

    #[test]
    fn branch_cert_verifies_against_root() {
        let mut tree = AvatarTree::new(None).unwrap();
        let id = tree.new_branch(Some("gaming".into())).unwrap();
        let branch = tree.branch(&id).unwrap();
        branch.cert.verify(&tree.root_verifying_key).unwrap();
    }

    #[test]
    fn branch_cert_fails_with_wrong_root_key() {
        let mut tree = AvatarTree::new(None).unwrap();
        let id = tree.new_branch(None).unwrap();
        let branch = tree.branch(&id).unwrap();

        let (_, wrong_key) = AvatarSigningKey::generate();
        let result = branch.cert.verify(&wrong_key);
        assert!(result.is_err(), "cert should not verify against a different root key");
    }

    #[test]
    fn branches_are_independent_chains() {
        let mut tree = AvatarTree::new(None).unwrap();
        let a = tree.new_branch(Some("a".into())).unwrap();
        let b = tree.new_branch(Some("b".into())).unwrap();

        tree.branch_mut(&a).unwrap().chain
            .append(BlockKind::Custom { payload_hash: hex::encode([1u8; 32]) })
            .unwrap();

        assert_eq!(tree.branch(&a).unwrap().chain.height(), 1);
        assert_eq!(tree.branch(&b).unwrap().chain.height(), 0);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let mut tree = AvatarTree::new(Some("root".into())).unwrap();
        let work_id = tree.new_branch(Some("work".into())).unwrap();
        tree.branch_mut(&work_id).unwrap().chain
            .append(BlockKind::Custom { payload_hash: hex::encode([7u8; 32]) })
            .unwrap();
        tree.new_branch(Some("personal".into())).unwrap();

        let dir = std::env::temp_dir().join("bn-tree-test");
        tree.save(&dir).unwrap();

        let root_key_bytes = tree.root_signing_key.to_bytes();
        let root_key = AvatarSigningKey::from_bytes(&root_key_bytes);

        let loaded = AvatarTree::load(&dir, root_key).unwrap();

        assert_eq!(loaded.branch_count(), 2);
        assert_eq!(
            loaded.branch(&work_id).unwrap().chain.height(),
            tree.branch(&work_id).unwrap().chain.height(),
        );
        loaded.branch(&work_id).unwrap().chain.validate_full().unwrap();
        loaded.branch(&work_id).unwrap().cert.verify(&loaded.root_verifying_key).unwrap();

        std::fs::remove_dir_all(&dir).ok();
    }
}
