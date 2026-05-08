# Bright-net

Prove you're the same entity someone talked to before — without saying anything about who you are.

---

## The problem

TCP accepts connection attempts before knowing anything about the initiator. We've bolted security onto that for fifty years: passwords, CAPTCHAs, rate limiters. None of it fixes the root issue.

Bright-net takes a different approach. Before a connection is established, the initiator proves they are the same entity they were last time — by presenting a signed chain of past interactions. Faking six months of history requires six months of real elapsed time. You can't buy or parallelize your way around the clock.

---

## What it's not

- **Not a cryptocurrency.** No tokens, no mining, no financial layer.
- **Not a replacement for the internet.** An additional option alongside it.
- **Not a surveillance system.** Avatars are pseudonymous. The protocol proves *I am who I was yesterday* without revealing who you are in the real world.

---

## How it works

### The avatar chain

Every participant has an identity anchored by a genesis block — a public key and a timestamp. Each interaction appends a new block to the chain, signed by the current key and hash-linked to the previous block. The chain can't be forged: altering any block breaks all subsequent hashes, and you can't create blocks from the past without the private key.

### The handshake

Two nodes connecting exchange signed tokens over QUIC:

1. The initiator sends a `HandshakeOffer`: their current chain tip hash + a fresh nonce + a timestamp, signed by their key.
2. The responder verifies the offer, sends back a `HandshakeResponse` bound to that specific offer (prevents replay).
3. The initiator verifies the response. On success, both sides record a `Handshake` block in their chain.

The same public key across multiple handshakes proves continuity — you're talking to the same entity you talked to before. Failed attempts trigger exponential backoff.

### Why QUIC

QUIC has a built-in Retry mechanism (RFC 9000 §8.1): before the server allocates any state, it challenges the client to prove their source address is reachable. That's the layer TCP is missing — it filters spoofed-source floods before any application logic runs. The bright-net handshake then runs on top of that, adding identity continuity.

---

## What's implemented

```
crates/
  bn-core/       — AvatarChain: create, append, validate, save/load to disk
  bn-handshake/  — HandshakeToken, HandshakeOffer/Response, RateLimiter
  bn-daemon/     — CLI: init, status, serve, connect
```

The POC works end-to-end. Two nodes can handshake over a real QUIC connection and both chains grow:

```bash
# Node A
cargo run -p bn-daemon -- --data-dir alice init --label "alice"
cargo run -p bn-daemon -- --data-dir alice serve

# Node B (separate terminal)
cargo run -p bn-daemon -- --data-dir bob init --label "bob"
cargo run -p bn-daemon -- --data-dir bob connect 127.0.0.1:4433

# Both chains are now at height 1
cargo run -p bn-daemon -- --data-dir alice status
cargo run -p bn-daemon -- --data-dir bob status
```

---

## What's missing

**QUIC Retry not enabled.** The server config doesn't call `use_retry(true)`. This is the DDoS resistance layer — without it, we're using QUIC as transport but not getting the source-address verification that's the whole point. This is the most important gap.

**Rate limiter not wired in.** `bn-handshake` has a working `RateLimiter` with exponential backoff, but `net.rs` doesn't use it. Failed handshake attempts currently have no consequence.

**Serve exits after one connection.** The daemon handles one handshake then quits. A real node would loop and stay running.

**No peer recognition.** The data is there — each Handshake block records the peer's public key. But the daemon doesn't check whether an incoming peer is someone it's spoken to before.

**Key backup.** If you lose `identity.key`, your identity is gone. The original design called for Shamir's Secret Sharing to split the key across devices. Not implemented.

**TLS certificate verification is skipped.** Acceptable for the POC — the trust anchor is the avatar chain, not the TLS cert. But it should be replaced with proper cert pinning before any real deployment.

---

## Cryptographic primitives

| Primitive | Purpose |
|---|---|
| Ed25519 (`ed25519-dalek`) | Block and token signatures |
| SHA-256 (`sha2`) | Block hashing, chain tip |
| QUIC/TLS (`quinn` + `rustls`) | Transport with source-address verification |
