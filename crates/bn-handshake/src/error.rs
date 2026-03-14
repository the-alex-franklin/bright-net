// bn-handshake/src/error.rs

use thiserror::Error;
use bn_core::error::BnError;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("invalid signature")]
    InvalidSignature,

    /// Token timestamp is outside the acceptable clock-skew window.
    #[error("stale token: clock skew of {0}s exceeds maximum")]
    StaleToken(i64),

    #[error("invalid token: {0}")]
    InvalidToken(String),

    /// The response's offer_hash doesn't match the actual offer.
    /// Prevents a valid response from being replayed against a different session.
    #[error("offer/response mismatch: response does not bind to this offer")]
    OfferMismatch,

    #[error("rate limited: too many failed verification attempts for this peer")]
    RateLimited,

    /// Errors propagated from the bn-core chain layer.
    #[error("chain error: {0}")]
    Chain(#[from] BnError),

    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<serde_json::Error> for HandshakeError {
    fn from(e: serde_json::Error) -> Self {
        HandshakeError::Serialization(e.to_string())
    }
}
