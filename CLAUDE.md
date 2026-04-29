# Bright-net — Development Guide

## What this project is

A proof-of-continuity overlay network protocol. The white paper in `README.md` is the authoritative spec. The protocol uses time-based identity continuity (not computational proof-of-work) to provide DDoS resistance, Sybil resistance, and passwordless authentication without central infrastructure.

**Not a cryptocurrency. Not a replacement for the internet. An additional option.**

## Privacy model (non-negotiable)

Two hard rules that must be preserved throughout the implementation:

1. **User data is private.** The protocol has no visibility into what flows through an established tunnel. Rate limiting, logging, and analysis apply only to tunnel *establishment* — never to tunnel *content*. Once a handshake completes, the connection is opaque to the protocol layer.

2. **User identity is private.** Avatars are pseudonymous. The protocol proves "this is the same entity I spoke to before" without revealing who that entity is in the real world. No real-world identity is required, stored, or inferable from the protocol. Branches of the same avatar tree cannot be linked through the protocol layer.

## Codebase layout

```
crates/
  bn-core/       — Block types, AvatarChain, Ed25519/SHA-256 crypto primitives
  bn-shards/     — Shamir's Secret Sharing + ChaCha20-Poly1305 + Argon2id
  bn-handshake/  — HandshakeToken, HandshakeOffer/Response, RateLimiter
```

## What's already done

- **`bn-core`**: `GenesisBlock`, `ChainBlock`, `BlockKind` (Genesis, Handshake, KeyRotation, Custom). `AvatarChain` with `append`, `validate_block`, `validate_full`, `tip_hash`, `record_handshake`, `validate_peer_tip`. Crypto wrappers: `AvatarSigningKey` (Ed25519, zeroize-on-drop), `AvatarVerifyingKey`, `sha256`.
- **`bn-handshake`**: `HandshakeToken` (fresh signed proof-of-possession with nonce + chain tip), `HandshakeOffer` / `HandshakeResponse` with offer binding (replay-prevention). `perform_handshake` for in-memory testing. `RateLimiter` with per-peer exponential backoff.
- **`bn-shards`**: `split_secret` / `reconstruct_secret` (Shamir GF256 via `sharks`), `encrypt_shard` / `decrypt_shard` (Argon2id key derivation + ChaCha20-Poly1305 AEAD).

All three crates have unit tests. Run with `cargo test --workspace`.

## Open design decisions

These must be resolved before the phases that depend on them. Writing code before deciding these will produce throwaway work.

**Branch key derivation (needed before Phase 3)**
Two candidates:
- *HKDF derivation*: branch keys derived deterministically from the root key via `HKDF(root_key, branch_label)`. Simple, but root key compromise breaks all branches.
- *Certification block*: each branch generates its own independent keypair; the root signs a certification block linking them. Root compromise doesn't expose branch keys, but reconstruction is more complex.

Recommendation: certification block — it aligns with the white paper's privacy model (branches are independent and unlink-able).

**Wire protocol format & versioning (needed before Phase 5)**
- JSON is readable and debuggable; `bincode` is faster. For v1, use length-prefixed JSON with a `version` field on every message. Switch to `bincode` later if benchmarking shows it's necessary.
- Every protocol message must carry a version byte so future format changes don't break existing nodes.

---

## Next development steps

Work through these phases in order. Each phase builds on the previous one.

---

### Phase 1 — Persistence (unblocks everything else)

Nothing can be tested end-to-end until chains and shards can be saved and reloaded.

**`bn-core`: Chain serialization**
- Derive `serde::Serialize/Deserialize` on `AvatarChain` (or add explicit `to_json`/`from_json` methods — the signing key must be excluded from the serialized form and handled separately).
- Add `AvatarChain::save(path)` and `AvatarChain::load(path, signing_key)` methods.
- The signing key bytes come from shard reconstruction (`bn-shards`) and are passed in at load time. The chain file itself never contains the private key.

**`bn-shards`: Shard file I/O**
- Add `EncryptedShard::save(path)` and `EncryptedShard::load(path)` — trivially `serde_json` to disk since `EncryptedShard` already derives Serialize/Deserialize.

**Directory convention** (propose `~/.bright-net/avatars/<avatar-id>/`):
```
~/.bright-net/
  avatars/
    <avatar-id>/
      chain.json          ← serialized chain (no private key)
      shards/
        shard-1.json      ← EncryptedShard
        shard-2.json
        ...
```

---

### Phase 2 — Key rotation

`BlockKind::KeyRotation` already exists in the type system but `AvatarChain` has no method to actually perform one.

- Add `AvatarChain::rotate_key()` → generates a new keypair, signs a `KeyRotation` block with the *old* key, swaps `signing_key` and `verifying_key`.
- `validate_full` needs to handle key rotation: when it encounters a `KeyRotation` block, subsequent blocks are verified against the new pubkey. Keep a running "current verifying key" as it walks the chain.
- Update `validate_block` similarly.
- After rotation, re-shard and redistribute: generate new shards for the new signing key, invalidate old shards.

---

### Phase 3 — Multi-avatar Merkle tree

The white paper (§2.3) describes a Merkle tree where the user's root is anchored at the home router and individual avatars are branches.

**New crate: `bn-avatar`** (or extend `bn-core`)
- `AvatarTree`: owns the root signing key + root genesis block. Contains a map of `branch_id → AvatarChain`.
- The root signing key is what gets sharded via `bn-shards`. Branch avatar keys are derived from (or certified by) the root — the exact derivation scheme needs to be designed (HKDF from root key material, or a certification block at the root level).
- `AvatarTree::new_branch(label)` creates a new avatar chain as a branch.
- Branches are private; external peers see only the specific branch they interact with (enforced by never transmitting the root or sibling branch tips).

---

### Phase 4 — `bn-daemon` crate

A long-running background process that lives on the home router/server and manages avatar presence.

- Loads `AvatarTree` from disk on startup (prompts for shard PIN to reconstruct the signing key).
- Listens for inbound handshake requests and dispatches them to the appropriate branch avatar.
- Applies `RateLimiter` to all inbound connections.
- Handles shard redistribution when devices are added/removed.
- Exposes a local Unix socket or HTTP API so CLI tools can interact with it.

Start minimal: daemon that loads a single avatar chain and accepts/initiates handshakes. Multi-avatar and device management come later.

---

### Phase 5 — Network transport (`bn-net` crate)

Currently `perform_handshake` is in-memory only. This phase puts actual bits on the wire.

- Add `bn-net` crate with `quinn` (async QUIC) as the transport.
- QUIC's built-in Retry (RFC 9000 §8.1) is the Layer 1 DDoS filter — it's automatic when using `quinn` in server mode with `ServerConfig::retry_enabled = true`. No extra code needed, just don't disable it.
- Wire protocol: `HandshakeOffer` and `HandshakeResponse` serialized as length-prefixed JSON (or `bincode` for efficiency) over a QUIC stream.
- Initiator side: open QUIC connection → open stream → send `HandshakeOffer` → receive `HandshakeResponse` → verify → record block.
- Responder side: accept stream → receive `HandshakeOffer` → check `RateLimiter` → verify offer → send `HandshakeResponse` → record block.
- Connection errors and verification failures feed back into `RateLimiter::record_failure`.
- **Important**: the rate limiter operates exclusively on handshake *establishment* attempts. It tracks how fast tunnels are being opened, not what flows through them. Once a handshake completes successfully, the tunnel is out of scope — the protocol doesn't touch it again.

TLS certs for the QUIC layer can be self-signed at first — the trust anchor is the avatar chain, not the TLS certificate (per §3.4).

---

### Phase 6 — CLI (`bn-cli` crate)

A user-facing command-line interface. Communicates with `bn-daemon` over its local socket.

Minimum viable commands:
```
bn avatar create --label "work"       # create a new avatar branch
bn avatar list                        # show all avatar branches + heights
bn avatar status <id>                 # show chain tip, height, last handshake
bn shard distribute                   # re-shard and write shard files
bn handshake <peer-addr> <avatar-id>  # initiate a handshake with a peer
bn daemon start / stop / status
```

Use `clap` for argument parsing.

---

### Phase 7 — Integration test suite

Unit tests exist but nothing exercises the full stack end-to-end. This phase adds tests that run two real daemon instances over a loopback QUIC connection so every layer is covered together.

- Spin up two `bn-daemon` processes on localhost with ephemeral ports.
- Execute a full handshake over actual QUIC — not `perform_handshake`. Verify both chains record a Handshake block and `validate_full` passes on both sides.
- Test rate limiter under simulated failed handshakes: send malformed tokens, verify exponential backoff activates, verify a successful handshake resets the counter.
- Test shard round-trip: split → encrypt → write to disk → read → decrypt → reconstruct → load chain with reconstructed key.
- Test chain load/save: save a chain with N blocks, reload it, verify `validate_full` passes and `tip_hash` is identical.
- Test key rotation: rotate key, append blocks under new key, validate full chain including pre-rotation blocks.

---

### Phase 8 — Chain pruning and checkpointing

As described in §6.5, avatar chains grow without bound. Implement before chains get large enough to matter.

- Define a `Checkpoint` type: a signed summary of chain state at block N, containing the block hash at N, the verifying key at N, and a signature from the key at N.
- `AvatarChain::checkpoint(at_index)` → `Checkpoint`.
- During `validate_full`, allow starting from a trusted checkpoint instead of genesis (verify the checkpoint signature, then validate forward from there).
- Archived blocks before the checkpoint can be moved to cold storage or discarded — the checkpoint is the new trust anchor.

---

### Phase 9 — Avatar lifecycle: destruction

New users sign up without friction — create an avatar, start handshaking. No invitation required. The exponential backoff on failed handshakes is what keeps the network safe from Sybil attacks. New chains have no history and face higher scrutiny naturally; their trust accrues over time.

**Avatar destruction (§5.3)**
- `AvatarChain::burn()`: signs a terminal `Burned` block kind with the current key, then zeroes the signing key. The chain becomes read-only and unextendable. Any future connection attempt from this avatar tip fails verification.
- For branch destruction: remove the branch from `AvatarTree` and delete its files.
- For genesis destruction: burn the root signing key after burning all branches. The entire identity becomes permanently inaccessible.
- This is intentional — there is no recovery. Document it clearly.

---

### Phase 10 — Device pairing

The full shard distribution story depends on two devices being able to prove they share the same root and negotiate a new shard.

- Two `bn-daemon` instances perform a handshake. If both present the same genesis block hash in the handshake token, they recognize each other as belonging to the same root.
- The existing device generates a new shard and transmits it over the verified QUIC connection to the new device.
- The new device encrypts it locally with its own PIN and stores it.
- On device loss: if the user still holds ≥ threshold shards, they can initiate re-sharding: reconstruct the secret, generate a new shard set, distribute.

---

### Phase 11 — Benchmarking and performance validation

The white paper claims handshakes are bounded by time, not compute, and targets 1-10ms per handshake (§2.1). Validate this claim before deployment.

- Measure end-to-end handshake latency: initiator sends offer → response received and verified → block appended. Measure p50/p95/p99 on localhost and over a real WAN link.
- Measure shard reconstruction time from encrypted shards on disk.
- Measure chain load and `validate_full` time as a function of chain height (100, 1k, 10k blocks).
- Profile hot paths with `flamegraph` / `cargo-flamegraph`. Optimize if any of the above are outside acceptable bounds.
- Measure memory footprint of `bn-daemon` at idle and under load.

---

### Phase 12 — Security review

Do not deploy without this. The crypto composition has not been externally reviewed.

- Review the handshake protocol for replay attacks, man-in-the-middle, and downgrade attacks. Specifically: does the offer binding (`offer_hash` in `HandshakeResponse`) fully prevent cross-session replay? Does the clock-skew window create any exploitable race?
- Review the rate limiter for bypass vectors: can an attacker rotate pubkeys faster than the limiter tracks them? Can they use high-height chains to exhaust the limiter's state?
- Review shard encryption: is the Argon2id parameterization (current defaults) appropriate for the threat model? Is the PHC hash extraction in `derive_key_from_hash` robust?
- Review key rotation: can an attacker who observes a rotation block perform any useful attack before the old key is retired?
- Engage an external cryptographer for at least the handshake protocol and shard scheme before v1.

---

### Phase 13 — Router / embedded target

The white paper anchors the root at home network infrastructure (§4.1). This phase makes `bn-daemon` run on real router hardware.

- Cross-compile for `mips-unknown-linux-musl` and `aarch64-unknown-linux-musl` (common OpenWrt targets).
- Test on a real device: a Raspberry Pi is an acceptable stand-in during development; a GL.iNet or similar OpenWrt router is the real target.
- Reduce daemon memory footprint to under 16MB resident. Identify and cut any dependencies that pull in heavy allocations.
- Package as an OpenWrt `.ipk`. The package should install a startup script and store shard files in the router's persistent storage partition.
- Test the full flow: router daemon holds one shard, phone holds another, laptop holds a third. Reconstruct on daemon start.

---

### Phase 14 — Packaging and distribution

Deployable means people can actually install it.

- **Linux (server/desktop)**: `systemd` unit file for `bn-daemon`. `install.sh` that compiles from source or downloads a release binary. Add `bn` to `PATH`.
- **macOS**: Homebrew formula for `bn-cli`. `launchd` plist for `bn-daemon` running on a home Mac acting as the anchor.
- **Docker**: a minimal image for users who want to run the daemon on a home server or NAS without compiling. Mounts a volume for `~/.bright-net/`.
- **OpenWrt**: `.ipk` package from Phase 13.
- **Releases**: tag a `v0.1.0` on GitHub with pre-built binaries for `x86_64-linux`, `aarch64-linux`, `x86_64-macos`, `aarch64-macos`.
- **Quickstart documentation**: single-page guide covering daemon setup, avatar creation, shard distribution to a second device, and first handshake with a peer.

---

### Post-v1: what's deliberately out of scope for first deployment

- **Internet bridge / interoperability (§8.3)**: bridging bright-net avatars to the existing public internet is a significant protocol design problem. Leave for v2.
- **FFT behavioral analysis**: not needed. The exponential backoff is sufficient — attack-pattern behavior (rapid repeated attempts) generates failed handshakes, which generate backoff, which throttles the attacker. The backoff mechanism catches the pattern by consequence, not by analysis.
- **Post-quantum cryptography (§6.6)**: swap Ed25519 for ML-DSA (FIPS 204) when `ml-dsa` crates stabilize. The abstraction in `bn-core/src/crypto.rs` makes this swap localized.
- **Biometric integration**: the composite factor (PIN || device_id || biometric_hash) is noted as a TODO in `bn-shards/src/shard.rs`. Platform-specific (TPM, Secure Enclave). Implement after the PIN-only flow is deployed and working.

---

## Cryptographic primitives in use

| Primitive | Crate | Purpose |
|---|---|---|
| Ed25519 | `ed25519-dalek` | Block and token signatures |
| SHA-256 | `sha2` | Block hashing, chain tip |
| ChaCha20-Poly1305 | `chacha20poly1305` | Shard encryption |
| Argon2id | `argon2` | Key derivation from PIN |
| Shamir GF(256) | `sharks` | Secret sharing |
| QUIC/TLS | `quinn` (Phase 5) | Transport layer |

## Running the tests

```bash
cargo test --workspace
```

All tests are inline (`#[cfg(test)]` modules). No external test runner or fixtures needed.
