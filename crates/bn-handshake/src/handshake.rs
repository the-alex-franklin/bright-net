// bn-handshake/src/handshake.rs
//
// The blockchain handshake protocol — two avatar chains authenticate each other.
//
// Protocol flow (maps to white paper §2.2):
//
//   Initiator                          Responder
//   ─────────                          ─────────
//   HandshakeOffer::create(chain) ───► HandshakeResponse::create(chain, offer)
//                                        - validate offer token (sig + timestamp)
//                                        - create response token bound to offer
//   response.verify(offer)  ◄─────────
//     - validate response token
//     - confirm offer_hash matches
//
//   Both call chain.record_handshake() to append a block.
//
// IP-spoofed DDoS filtering is handled at the transport layer by QUIC's built-in
// Retry mechanism (RFC 9000 §8.1), which proves source-address reachability
// before any application state is allocated. There is no need for a redundant
// application-layer cookie.
//
// For in-memory / testing use, `perform_handshake(alice, bob)` does all of this
// in one call. In production (over a network), each party runs their own half.

use bn_core::{chain::AvatarChain, crypto::sha256};
use serde::{Deserialize, Serialize};

use crate::{error::HandshakeError, token::HandshakeToken};

// ── HandshakeOffer ────────────────────────────────────────────────────────────

/// Sent by the initiating party to start a handshake.
/// By the time this is sent, QUIC's Retry has already proven the source IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeOffer {
    pub token: HandshakeToken,
}

impl HandshakeOffer {
    /// Create an offer from the initiator's chain.
    /// Does NOT mutate the chain — block is only appended after both sides verify.
    pub fn create(chain: &AvatarChain) -> Result<Self, HandshakeError> {
        let token = HandshakeToken::create(chain)?;
        Ok(HandshakeOffer { token })
    }
}

// ── HandshakeResponse ─────────────────────────────────────────────────────────

/// Sent by the responding party in reply to a HandshakeOffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub token: HandshakeToken,
    /// SHA-256 of the JSON-serialized HandshakeOffer token.
    /// Binds this response to the specific offer — prevents replay against
    /// a different session even if the token itself is still fresh.
    pub offer_hash: String,
}

impl HandshakeResponse {
    /// Validate the incoming offer token, then create a response.
    /// Does NOT mutate the responder's chain — block appended after both verify.
    pub fn create(chain: &AvatarChain, offer: &HandshakeOffer) -> Result<Self, HandshakeError> {
        // Verify the offer token — proves chain continuity and key control.
        offer.token.verify()?;

        let token = HandshakeToken::create(chain)?;

        // Bind the response to this specific offer.
        let offer_json = serde_json::to_vec(&offer.token)?;
        let offer_hash = hex::encode(sha256(&offer_json));

        Ok(HandshakeResponse { token, offer_hash })
    }

    /// Validate this response against the offer that produced it.
    /// Called by the initiator after receiving the response.
    pub fn verify(&self, offer: &HandshakeOffer) -> Result<(), HandshakeError> {
        // Verify the response token (signature + timestamp).
        self.token.verify()?;

        // Confirm the response is bound to our specific offer.
        let offer_json = serde_json::to_vec(&offer.token)?;
        let expected_offer_hash = hex::encode(sha256(&offer_json));
        if self.offer_hash != expected_offer_hash {
            return Err(HandshakeError::OfferMismatch);
        }

        Ok(())
    }
}

// ── perform_handshake ─────────────────────────────────────────────────────────

/// Execute a complete handshake between two in-memory avatar chains.
/// Both chains are mutated: a `Handshake` block is appended to each on success.
/// An error from either party aborts the handshake — neither chain is mutated.
///
/// In production (over QUIC), QUIC's Retry has already filtered spoofed-source
/// traffic before this function is reached.
pub fn perform_handshake(
    initiator: &mut AvatarChain,
    responder: &mut AvatarChain,
) -> Result<(), HandshakeError> {
    // Step 1: initiator produces an offer.
    let offer = HandshakeOffer::create(initiator)?;

    // Step 2: responder validates the offer and produces a response.
    let response = HandshakeResponse::create(responder, &offer)?;

    // Step 3: initiator validates the response.
    response.verify(&offer)?;

    // Step 4: both parties append a Handshake block to their own chain.
    let responder_key = response.token.verifying_key()?;
    let responder_tip = response.token.chain_tip_hash_bytes()?;
    initiator.record_handshake(&responder_key, responder_tip)?;

    let initiator_key = offer.token.verifying_key()?;
    let initiator_tip = offer.token.chain_tip_hash_bytes()?;
    responder.record_handshake(&initiator_key, initiator_tip)?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bn_core::chain::AvatarChain;

    fn make_chain(label: &str) -> AvatarChain {
        AvatarChain::new(Some(label.into())).unwrap()
    }

    #[test]
    fn successful_handshake_appends_blocks_to_both_chains() {
        let mut alice = make_chain("alice");
        let mut bob = make_chain("bob");

        perform_handshake(&mut alice, &mut bob).unwrap();

        assert_eq!(alice.height(), 1);
        assert_eq!(bob.height(), 1);
        alice.validate_full().unwrap();
        bob.validate_full().unwrap();
    }

    #[test]
    fn multiple_handshakes_chain_correctly() {
        let mut alice = make_chain("alice");
        let mut bob = make_chain("bob");
        let mut carol = make_chain("carol");

        perform_handshake(&mut alice, &mut bob).unwrap();
        perform_handshake(&mut alice, &mut carol).unwrap();
        perform_handshake(&mut bob, &mut carol).unwrap();

        assert_eq!(alice.height(), 2);
        assert_eq!(bob.height(), 2);
        assert_eq!(carol.height(), 2);

        alice.validate_full().unwrap();
        bob.validate_full().unwrap();
        carol.validate_full().unwrap();
    }

    #[test]
    fn tampered_offer_pubkey_fails_verification() {
        let alice = make_chain("alice");
        let mut offer = HandshakeOffer::create(&alice).unwrap();

        let mut pubkey_bytes = hex::decode(&offer.token.pubkey).unwrap();
        pubkey_bytes[0] ^= 0xff;
        offer.token.pubkey = hex::encode(pubkey_bytes);

        let bob = make_chain("bob");
        let result = HandshakeResponse::create(&bob, &offer);
        assert!(result.is_err(), "tampered pubkey should fail offer verification");
    }

    #[test]
    fn tampered_response_offer_hash_fails_verification() {
        let alice = make_chain("alice");
        let bob = make_chain("bob");

        let offer = HandshakeOffer::create(&alice).unwrap();
        let mut response = HandshakeResponse::create(&bob, &offer).unwrap();

        response.offer_hash = hex::encode([0u8; 32]);

        let result = response.verify(&offer);
        assert!(
            matches!(result, Err(HandshakeError::OfferMismatch)),
            "corrupted offer_hash should return OfferMismatch"
        );
    }
}

