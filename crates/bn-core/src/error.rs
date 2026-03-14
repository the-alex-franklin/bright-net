// bn-core/src/error.rs
// Centralised error type for the entire bn-core crate.
// `thiserror::Error` generates Display + std::error::Error impls automatically —
// similar to extending Error in TypeScript but with exhaustive pattern matching.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BnError {
    #[error("invalid signature")]
    InvalidSignature,

    #[error("chain integrity violation: {0}")]
    ChainIntegrity(String),

    #[error("timestamp error: {0}")]
    Timestamp(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("key error: {0}")]
    Key(String),
}

// Rust's `?` operator auto-converts foreign error types into BnError
// if we implement From<ForeignError> for BnError.
impl From<serde_json::Error> for BnError {
    fn from(e: serde_json::Error) -> Self {
        BnError::Serialization(e.to_string())
    }
}

impl From<ed25519_dalek::SignatureError> for BnError {
    fn from(_: ed25519_dalek::SignatureError) -> Self {
        BnError::InvalidSignature
    }
}
