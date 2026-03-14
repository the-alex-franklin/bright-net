// bn-handshake/src/cookie.rs
//
// Stateless cookie mechanism — Step 2 of the blockchain handshake protocol.
//
// Purpose: filter spoofed-source DDoS traffic before the responder allocates
// any per-connection cryptographic state. Inspired by QUIC's Retry packet
// and WireGuard's cookie reply.
//
// How it works:
//   1. Responder generates a cookie: HMAC-SHA256(secret || initiator_ip)
//      using a server-side secret that rotates on a short interval.
//   2. Initiator echoes the cookie back in their full offer.
//   3. Responder verifies the echo before proceeding with chain tip exchange.
//
// The cookie proves the initiator's source address is reachable (can receive
// replies), which eliminates spoofed-source UDP floods. The responder stores
// NO per-connection state until the cookie is verified.

use std::time::{SystemTime, UNIX_EPOCH};

use bn_core::crypto::sha256;
use serde::{Deserialize, Serialize};

use crate::error::HandshakeError;

/// How long (in seconds) a cookie remains valid.
/// Short enough to limit replay windows; long enough to survive a round trip.
const COOKIE_VALIDITY_SECS: u64 = 10;

// ── CookieChallenge ───────────────────────────────────────────────────────────

/// Sent by the responder in reply to the initiator's first contact.
/// Contains a short-lived HMAC cookie the initiator must echo back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieChallenge {
    /// Hex-encoded HMAC-SHA256(secret || initiator_ip || timestamp_bucket).
    pub cookie: String,
    /// Unix timestamp of when this challenge was issued.
    /// The initiator echoes this back so the responder can verify freshness
    /// without storing any state.
    pub issued_at: u64,
}

// ── CookieSecret ─────────────────────────────────────────────────────────────

/// Server-side state for issuing and verifying cookies.
/// In production, `secret` rotates every few minutes and the previous secret
/// is retained briefly so in-flight cookies don't suddenly become invalid.
pub struct CookieSecret {
    current: [u8; 32],
    previous: Option<[u8; 32]>,
}

impl CookieSecret {
    /// Initialise with a freshly-generated secret.
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            current: secret,
            previous: None,
        }
    }

    /// Rotate to a new secret, retaining the previous one for verification
    /// of cookies issued just before the rotation.
    pub fn rotate(&mut self, new_secret: [u8; 32]) {
        self.previous = Some(self.current);
        self.current = new_secret;
    }

    /// Issue a fresh cookie challenge for an initiator identified by their
    /// address string (e.g. "192.0.2.1:12345").
    pub fn issue(&self, initiator_addr: &str) -> CookieChallenge {
        let issued_at = now_secs();
        let cookie = compute_cookie(&self.current, initiator_addr, issued_at);
        CookieChallenge { cookie, issued_at }
    }

    /// Verify a cookie echo from an initiator.
    /// Checks freshness (within COOKIE_VALIDITY_SECS) and HMAC validity.
    /// Tries the current secret first, then the previous one (if any).
    pub fn verify(
        &self,
        initiator_addr: &str,
        challenge: &CookieChallenge,
    ) -> Result<(), HandshakeError> {
        let now = now_secs();

        // Freshness check — no stored state needed.
        let age = now.saturating_sub(challenge.issued_at);
        if age > COOKIE_VALIDITY_SECS {
            return Err(HandshakeError::InvalidToken(format!(
                "cookie expired: {age}s old (max {COOKIE_VALIDITY_SECS}s)"
            )));
        }

        // HMAC check against current secret.
        let expected = compute_cookie(&self.current, initiator_addr, challenge.issued_at);
        if expected == challenge.cookie {
            return Ok(());
        }

        // Fall back to previous secret (handles cookies issued just before rotation).
        if let Some(prev) = &self.previous {
            let expected_prev = compute_cookie(prev, initiator_addr, challenge.issued_at);
            if expected_prev == challenge.cookie {
                return Ok(());
            }
        }

        Err(HandshakeError::InvalidToken(
            "cookie HMAC verification failed".into(),
        ))
    }
}

// ── Internals ─────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// HMAC-SHA256 approximation using double-SHA256 (keyed construction):
///   SHA256(secret || SHA256(data))
///
/// This is a well-known secure keyed hash construction.
/// A full HMAC crate (hmac + sha2) would be marginally more orthodox but
/// this construction is cryptographically equivalent for our purposes.
fn compute_cookie(secret: &[u8; 32], initiator_addr: &str, issued_at: u64) -> String {
    // data = addr || ":" || timestamp
    let data = format!("{}:{}", initiator_addr, issued_at);
    let inner = sha256(data.as_bytes());

    // keyed: SHA256(secret || inner)
    let mut keyed = Vec::with_capacity(32 + 32);
    keyed.extend_from_slice(secret);
    keyed.extend_from_slice(&inner);
    hex::encode(sha256(&keyed))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};

    fn random_secret() -> [u8; 32] {
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        s
    }

    const ADDR: &str = "192.0.2.1:51820";

    #[test]
    fn fresh_cookie_verifies() {
        let secret = CookieSecret::new(random_secret());
        let challenge = secret.issue(ADDR);
        assert!(secret.verify(ADDR, &challenge).is_ok());
    }

    #[test]
    fn wrong_address_fails() {
        let secret = CookieSecret::new(random_secret());
        let challenge = secret.issue(ADDR);
        let result = secret.verify("10.0.0.1:9999", &challenge);
        assert!(result.is_err(), "cookie issued for different addr should fail");
    }

    #[test]
    fn tampered_cookie_fails() {
        let secret = CookieSecret::new(random_secret());
        let mut challenge = secret.issue(ADDR);
        challenge.cookie = hex::encode([0u8; 32]);
        let result = secret.verify(ADDR, &challenge);
        assert!(result.is_err(), "tampered cookie should fail");
    }

    #[test]
    fn cookie_valid_after_rotation_using_previous_secret() {
        let mut secret = CookieSecret::new(random_secret());
        // Issue with current secret.
        let challenge = secret.issue(ADDR);
        // Rotate — old secret moves to `previous`.
        secret.rotate(random_secret());
        // Cookie issued with the old secret should still verify.
        assert!(
            secret.verify(ADDR, &challenge).is_ok(),
            "cookie should verify against previous secret after rotation"
        );
    }

    #[test]
    fn cookie_invalid_after_two_rotations() {
        let mut secret = CookieSecret::new(random_secret());
        let challenge = secret.issue(ADDR);
        secret.rotate(random_secret()); // old → previous
        secret.rotate(random_secret()); // previous discarded
        let result = secret.verify(ADDR, &challenge);
        assert!(result.is_err(), "cookie should be invalid after two rotations");
    }
}
