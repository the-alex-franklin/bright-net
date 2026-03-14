// bn-handshake/src/handshake.rs
//
// The blockchain handshake protocol — two avatar chains authenticate each other.
//
// Protocol flow (maps to white paper §2.2):
//
//   Initiator                          Responder
//   ─────────                          ─────────
//   [initial contact] ───────────────► CookieChallenge::issue()
//   challenge.verify() ◄───────────── CookieChallenge
//   HandshakeOffer::create() ────────►
//   (cookie echo included)             HandshakeResponse::create()
//                                        - verify cookie echo
//                                        - validate offer token (sig + timestamp)
//                                        - create response token bound to offer
//   response.verify(offer) ◄──────────
//     - validate response token
//     - confirm offer_hash matches
//
//   Both call chain.record_handshake() to append a block.
//
// For in-memory / testing use, `perform_handshake(alice, bob, secret)` does all
// of this in one call. In production (over a network), each party runs their own
// half with real network I/O between steps.

use bn_core::{chain::AvatarChain, crypto::sha256};
use serde::{Deserialize, Serialize};

use crate::{
    cookie::{CookieChallenge, CookieSecret},
    error::HandshakeError,
    token::HandshakeToken,
};

// ── HandshakeOffer ────────────────────────────────────────────────────────────

/// Sent by the initiating party after receiving and verifying the cookie challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeOffer {
    pub token: HandshakeToken,
    /// The cookie challenge echoed back to the responder.
    /// Proves the initiator received the challenge (source IP is reachable).
    pub cookie_echo: CookieChallenge,
}

impl HandshakeOffer {
    /// Create an offer from the initiator's chain, echoing the cookie challenge
    /// received from the responder.
    pub fn create(chain: &AvatarChain, cookie_echo: CookieChallenge) -> Result<Self, HandshakeError> {
        let token = HandshakeToken::create(chain)?;
        Ok(HandshakeOffer { token, cookie_echo })
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
    /// Validate the incoming offer (cookie + token), then create a response.
    /// Does NOT mutate the responder's chain — block appended after both verify.
    pub fn create(
        chain: &AvatarChain,
        offer: &HandshakeOffer,
        cookie_secret: &CookieSecret,
        initiator_addr: &str,
    ) -> Result<Self, HandshakeError> {
        // Step 1: verify the cookie echo — proves source IP is reachable.
        cookie_secret.verify(initiator_addr, &offer.cookie_echo)?;

        // Step 2: verify the offer token — proves chain continuity and key control.
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
/// `initiator_addr` simulates the network address of the initiator (used for
/// cookie binding). In production this comes from the UDP socket.
pub fn perform_handshake(
    initiator: &mut AvatarChain,
    responder: &mut AvatarChain,
    cookie_secret: &CookieSecret,
    initiator_addr: &str,
) -> Result<(), HandshakeError> {
    // Step 1: responder issues a cookie challenge (stateless, no stored state).
    let challenge = cookie_secret.issue(initiator_addr);

    // Step 2: initiator verifies the challenge came from the right responder
    // (signature check), then echoes it back in the offer.
    // In production the initiator would verify the responder's identity here
    // via TLS; for in-memory tests we skip that layer.
    let offer = HandshakeOffer::create(initiator, challenge)?;

    // Step 3: responder verifies cookie echo + offer token, produces response.
    let response = HandshakeResponse::create(responder, &offer, cookie_secret, initiator_addr)?;

    // Step 4: initiator verifies the response.
    response.verify(&offer)?;

    // Step 5: both parties append a Handshake block to their own chain.
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
    use rand::{rngs::OsRng, RngCore};

    use super::*;
    use bn_core::chain::AvatarChain;

    fn make_chain(label: &str) -> AvatarChain {
        AvatarChain::new(Some(label.into())).unwrap()
    }

    fn make_secret() -> CookieSecret {
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        CookieSecret::new(s)
    }

    const ADDR: &str = "192.0.2.1:51820";

    #[test]
    fn successful_handshake_appends_blocks_to_both_chains() {
        let mut alice = make_chain("alice");
        let mut bob = make_chain("bob");
        let secret = make_secret();

        perform_handshake(&mut alice, &mut bob, &secret, ADDR).unwrap();

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
        let secret = make_secret();

        perform_handshake(&mut alice, &mut bob, &secret, ADDR).unwrap();
        perform_handshake(&mut alice, &mut carol, &secret, ADDR).unwrap();
        perform_handshake(&mut bob, &mut carol, &secret, ADDR).unwrap();

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
        let bob = make_chain("bob");
        let secret = make_secret();

        let challenge = secret.issue(ADDR);
        let mut offer = HandshakeOffer::create(&alice, challenge).unwrap();

        // Tamper: flip one byte of the public key.
        let mut pubkey_bytes = hex::decode(&offer.token.pubkey).unwrap();
        pubkey_bytes[0] ^= 0xff;
        offer.token.pubkey = hex::encode(pubkey_bytes);

        let result = HandshakeResponse::create(&bob, &offer, &secret, ADDR);
        assert!(result.is_err(), "tampered pubkey should fail offer verification");
    }

    #[test]
    fn tampered_response_offer_hash_fails_verification() {
        let alice = make_chain("alice");
        let bob = make_chain("bob");
        let secret = make_secret();

        let challenge = secret.issue(ADDR);
        let offer = HandshakeOffer::create(&alice, challenge).unwrap();
        let mut response = HandshakeResponse::create(&bob, &offer, &secret, ADDR).unwrap();

        response.offer_hash = hex::encode([0u8; 32]);

        let result = response.verify(&offer);
        assert!(
            matches!(result, Err(HandshakeError::OfferMismatch)),
            "corrupted offer_hash should return OfferMismatch"
        );
    }

    #[test]
    fn wrong_initiator_address_fails_cookie_verification() {
        let alice = make_chain("alice");
        let bob = make_chain("bob");
        let secret = make_secret();

        // Cookie issued for ADDR, but offer claims to come from a different address.
        let challenge = secret.issue(ADDR);
        let offer = HandshakeOffer::create(&alice, challenge).unwrap();

        let result = HandshakeResponse::create(&bob, &offer, &secret, "10.0.0.1:9999");
        assert!(result.is_err(), "cookie bound to different address should fail");
    }
}

