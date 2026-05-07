# Bright-net

A proof-of-continuity overlay network protocol. Passwordless authentication and DDoS resistance without central infrastructure, built on the idea that time is a resource that can't be faked or parallelized.

---

## The problem it solves

The internet was designed for a small network of trusted participants. TCP's handshake is optimistic — it accepts connection attempts before knowing anything about the initiator. We've spent fifty years bolting security onto that foundation: passwords, CAPTCHAs, rate limiters, fraud detection heuristics. None of it fixes the root issue.

Bright-net takes a different approach. Before a connection is established, the initiator has to prove they are the same entity they were last time — by presenting a cryptographically signed chain of past interactions. Faking six months of history requires six months of real elapsed time. You can't buy or parallelize your way around the clock.

---

## What it's not

- **Not a cryptocurrency.** No tokens, no mining, no financial layer. This is communication infrastructure.
- **Not a replacement for the internet.** It runs alongside the existing internet as an additional option.
- **Not a surveillance system.** Avatars are pseudonymous. The protocol proves *I am who I was yesterday* without revealing who you are in the real world. The protocol has no visibility into what flows through an established tunnel.

---

## Core concepts

### The avatar chain

Every participant has an *avatar* — an identity anchored by a genesis block containing their public key and a timestamp. Each subsequent interaction (handshake, key rotation) appends a new block to the chain, signed by the current key and hash-linked to the previous block. The chain can't be forged: altering any block breaks all subsequent hashes, and you can't fake blocks from the past without the private key.

### The handshake

Two nodes connecting to each other exchange signed `HandshakeToken`s inside an encrypted QUIC tunnel:

1. **QUIC Retry** — forces the initiator to prove their source IP is reachable before any state is allocated. Eliminates spoofed-source floods at Layer 1.
2. **Token exchange** — both parties send a signed token: current chain tip hash + fresh nonce + timestamp. The responder binds their token to the initiator's offer (preventing cross-session replay). Either both verify, or the connection aborts.
3. **Block append** — on success, both sides record a `Handshake` block in their chain. Failed attempts feed into exponential backoff.

### The avatar tree

A user's identity is a tree: one root (shardable across devices) and any number of named branches — work, personal, gaming, etc. Each branch is an independent avatar chain. External peers see only the branch they're interacting with. The root and other branches are invisible to them; the protocol provides no way to link branches together.

### Key rotation

Avatars can rotate their signing key without losing their history. A `KeyRotation` block is signed by the old key and records the new public key. The chain validator replays key history when verifying old blocks.

---

## Codebase

```
crates/
  bn-core/       — block types, AvatarChain, AvatarTree, Ed25519/SHA-256 crypto
  bn-shards/     — Shamir's Secret Sharing + ChaCha20-Poly1305 + Argon2id (key backup)
  bn-handshake/  — HandshakeToken, HandshakeOffer/Response, RateLimiter
  bn-daemon/     — identity management binary
```

### What's implemented

| Crate | Status |
|---|---|
| `bn-core` | Genesis + chain blocks, `AvatarChain` (append, validate, key rotation, persist), `AvatarTree` (branches, certifications, persist) |
| `bn-shards` | Shamir split/reconstruct, ChaCha20-Poly1305 shard encryption, shard file I/O |
| `bn-handshake` | `HandshakeToken`, `HandshakeOffer`/`HandshakeResponse` with offer binding, `perform_handshake` (in-memory), `RateLimiter` with exponential backoff |
| `bn-daemon` | `init`, `status`, `branch new`, `branch list` commands |

Network transport (QUIC), CLI, and device pairing are not yet built.

---

## Getting started

```bash
# Run all tests
cargo test --workspace

# Build the daemon
cargo build -p bn-daemon

# Create a new identity
cargo run -p bn-daemon -- init --label "my-root"

# Add avatar branches
cargo run -p bn-daemon -- branch new --label "work"
cargo run -p bn-daemon -- branch new --label "personal"

# Check status
cargo run -p bn-daemon -- status
```

Identity data is stored under `~/.bright-net/`. Override with `--data-dir <path>`.

---

## Privacy model

Two rules that are non-negotiable throughout the implementation:

1. **User data is private.** Rate limiting and analysis apply only to tunnel *establishment*. Once a handshake completes, the connection is opaque to the protocol. The protocol never inspects tunnel content.

2. **User identity is private.** Avatars are pseudonymous. The protocol proves continuity without revealing real-world identity. Branches of the same avatar tree cannot be linked through the protocol layer.

---

## Cryptographic primitives

| Primitive | Crate | Purpose |
|---|---|---|
| Ed25519 | `ed25519-dalek` | Block and token signatures |
| SHA-256 | `sha2` | Block hashing, chain tip |
| ChaCha20-Poly1305 | `chacha20poly1305` | Shard encryption |
| Argon2id | `argon2` | Key derivation |
| Shamir GF(256) | `sharks` | Secret sharing across devices |
| QUIC/TLS | `quinn` | Transport layer (Phase 5) |

---

## What's next

- **Phase 5** — QUIC transport: `bn-net` crate, wire up `HandshakeOffer`/`HandshakeResponse` over a real network connection
- **Phase 6** — CLI: `bn-cli` with `clap`, communicating with `bn-daemon` over a local socket
- **Phase 7** — Integration tests: two daemon instances over loopback QUIC, full handshake end-to-end
- Further: chain pruning/checkpointing, avatar lifecycle (burn), device pairing via shards, router/embedded targets

See `CLAUDE.md` for the full development roadmap.
