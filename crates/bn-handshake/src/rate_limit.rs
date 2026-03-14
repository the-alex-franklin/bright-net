// bn-handshake/src/rate_limit.rs
//
// Per-peer rate limiter for failed handshake verification attempts.
//
// This implements the "negative feedback loop" described in the white paper
// (§3.1): repeated failed verifications cause exponentially increasing backoff.
// Successful verifications clear the failure state for that peer.
//
// In the protocol, only *failed* verifications trigger penalties — legitimate
// traffic is never penalised regardless of volume.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};

use crate::error::HandshakeError;

// ── Configuration ─────────────────────────────────────────────────────────────

/// Tunable parameters for the rate limiter.
/// `Default` provides production-sensible values.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Number of failed verifications within the window before backoff kicks in.
    pub max_failures: u32,
    /// Length of the sliding failure-count window in seconds.
    pub window_secs: u64,
    /// Initial backoff duration in seconds (doubles on each subsequent trigger).
    pub base_backoff_secs: u64,
    /// Maximum backoff duration in seconds (caps the exponential growth).
    pub max_backoff_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_failures: 5,
            window_secs: 60,
            base_backoff_secs: 10,
            max_backoff_secs: 300, // 5 minutes
        }
    }
}

// ── Per-peer state ────────────────────────────────────────────────────────────

struct PeerState {
    /// Failure count within the current window.
    failures: u32,
    /// When the current window started.
    window_start: DateTime<Utc>,
    /// If set, no handshakes from this peer are accepted until this time.
    backoff_until: Option<DateTime<Utc>>,
    /// How many times backoff has been triggered (drives exponential growth).
    backoff_count: u32,
}

impl PeerState {
    fn new(now: DateTime<Utc>) -> Self {
        Self {
            failures: 0,
            window_start: now,
            backoff_until: None,
            backoff_count: 0,
        }
    }
}

// ── RateLimiter ───────────────────────────────────────────────────────────────

pub struct RateLimiter {
    /// State keyed by peer pubkey (hex string).
    peers: HashMap<String, PeerState>,
    config: RateLimitConfig,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            peers: HashMap::new(),
            config,
        }
    }

    /// Check whether a peer is currently in backoff.
    /// Call this *before* processing an inbound offer or response.
    pub fn check(&self, peer_pubkey: &str) -> Result<(), HandshakeError> {
        if let Some(state) = self.peers.get(peer_pubkey) {
            if let Some(backoff_until) = state.backoff_until {
                if Utc::now() < backoff_until {
                    return Err(HandshakeError::RateLimited);
                }
            }
        }
        Ok(())
    }

    /// Record a failed verification attempt for a peer.
    /// Triggers exponential backoff once failures exceed `max_failures`.
    pub fn record_failure(&mut self, peer_pubkey: &str) {
        let now = Utc::now();
        let config = &self.config;

        let state = self
            .peers
            .entry(peer_pubkey.to_string())
            .or_insert_with(|| PeerState::new(now));

        // Reset the window counter if the window has expired.
        let elapsed = (now - state.window_start).num_seconds().unsigned_abs();
        if elapsed >= config.window_secs {
            state.failures = 0;
            state.window_start = now;
        }

        state.failures += 1;

        // If we've hit the threshold, apply exponential backoff.
        if state.failures >= config.max_failures {
            state.backoff_count += 1;
            // backoff = base * 2^(count-1), capped at max.
            let multiplier = 2u64.saturating_pow(state.backoff_count.saturating_sub(1));
            let backoff_secs = (config.base_backoff_secs * multiplier).min(config.max_backoff_secs);
            state.backoff_until = Some(now + Duration::seconds(backoff_secs as i64));
            // Reset the window so the next burst starts fresh.
            state.failures = 0;
            state.window_start = now;
        }
    }

    /// Record a successful verification — clears all failure state for this peer.
    pub fn record_success(&mut self, peer_pubkey: &str) {
        if let Some(state) = self.peers.get_mut(peer_pubkey) {
            state.failures = 0;
            state.backoff_count = 0;
            state.backoff_until = None;
        }
    }

    /// How many peers currently have active backoff (useful for monitoring).
    pub fn active_backoff_count(&self) -> usize {
        let now = Utc::now();
        self.peers
            .values()
            .filter(|s| s.backoff_until.map_or(false, |t| t > now))
            .count()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

    #[test]
    fn no_failures_allows_connections() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        assert!(limiter.check(PEER).is_ok());
    }

    #[test]
    fn rate_limited_after_threshold_failures() {
        let mut limiter = RateLimiter::new(RateLimitConfig::default());

        for _ in 0..5 {
            limiter.record_failure(PEER);
        }

        assert!(
            matches!(limiter.check(PEER), Err(HandshakeError::RateLimited)),
            "peer should be rate-limited after 5 failures"
        );
    }

    #[test]
    fn success_clears_failure_state() {
        let mut limiter = RateLimiter::new(RateLimitConfig::default());

        for _ in 0..5 {
            limiter.record_failure(PEER);
        }
        assert!(limiter.check(PEER).is_err());

        limiter.record_success(PEER);
        assert!(
            limiter.check(PEER).is_ok(),
            "peer should be allowed after success clears state"
        );
    }

    #[test]
    fn unknown_peer_is_always_allowed() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        assert!(limiter.check("unknown-peer-pubkey").is_ok());
    }

    #[test]
    fn active_backoff_count_tracks_correctly() {
        let mut limiter = RateLimiter::new(RateLimitConfig::default());

        for _ in 0..5 {
            limiter.record_failure(PEER);
        }
        assert_eq!(limiter.active_backoff_count(), 1);

        limiter.record_success(PEER);
        assert_eq!(limiter.active_backoff_count(), 0);
    }
}
