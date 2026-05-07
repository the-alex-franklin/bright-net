use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bn_core::crypto::AvatarSigningKey;

pub fn default_base_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".bright-net")
}

pub fn key_path(base: &Path) -> PathBuf {
    base.join("root.key")
}

pub fn save_key(bytes: &[u8; 32], path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes.as_ref())?;
    Ok(())
}

pub fn load_key(path: &Path) -> Result<AvatarSigningKey> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading key file: {}", path.display()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("root.key has wrong length (expected 32 bytes)"))?;
    Ok(AvatarSigningKey::from_bytes(&arr))
}
