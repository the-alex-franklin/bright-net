// bn-shards/src/error.rs

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShardError {
    #[error("not enough shards to reconstruct secret: need {threshold}, got {available}")]
    InsufficientShards { threshold: u8, available: usize },

    #[error("shard encryption failed: {0}")]
    Encryption(String),

    #[error("shard decryption failed — wrong PIN or corrupted shard")]
    Decryption,

    #[error("secret too large: {0} bytes (max 65535)")]
    SecretTooLarge(usize),

    #[error("invalid shard data: {0}")]
    InvalidShard(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<serde_json::Error> for ShardError {
    fn from(e: serde_json::Error) -> Self {
        ShardError::Serialization(e.to_string())
    }
}
