let me caveat this by saying: I don't know if it'll work, but I keep checking with ChatGPT and Claude "Is this possible? Does it have any paradoxes or logical fallacies that make it flawed?" and they keep saying "it's possible. That doesn't mean it'll be easy or automatically sucessful, but it's possible", so I'm still pushing on the idea

# Bright-net: Proof-of-Continuity Protocol

**A Decentralized Internet Architecture for Cryptographic Trust**

*Alex Andria Franklin — v1.1.0*

---

## Preface

So, I was in my car, and I receive a call from "my bank", and I've been a software developer for about a decade, and I've been through this scam dozens of times before. So I just let it ring through. He calls again. That's twice. He should move on now. And then he calls again, and I start getting irritated, but I let it ring through. He calls a 4th time, so I pick up the phone and I just scream at him:

> **Me:** "Will you shut the hell up!?"
>
> **Him:** "Umm... what?"
>
> **Me:** "I know who you are! I know what you're doing! This is a hack that's so simple, it barely even qualifies as a hack anymore! Leave. me. alone."
>
> **Him:** "... No I'm not."

And then he hangs up the phone and I'm just sitting there fuming. And, I'm already vaguely familiar with SS7, and the fact that VoIP is designed to trust easily-forged headers by-default. And I'm just like "😡 Why does the internet work this way in 2026?! ..... 💡 yeah. Why does the internet work this way in 2026?"

Then I did some research and I came up with this crazy idea.

---

## Abstract

The internet we use today was designed in the 1970s for a small network of academics who trusted each other. Back then, you could take headers at face value, connection requests were handled optimistically, and nobody worried much about authentication. Fast forward to 2026, and we've got billions of users, but we're still stuck with an architecture that wasn't built for an adversarial world.

This paper presents a different approach: an internet architecture based on proof-of-continuity. Basically using the passage of time instead of computational proof-of-work. By integrating blockchain handshakes at the transport layer, distributing continuity shards across devices you actually own, and enabling cryptographic verification that proves you've existed continuously over time, this protocol attempts to tackle several classes of attacks while giving data ownership back to individuals.

**Important:** Bright-net is NOT a cryptocurrency. There are no tokens, no coins, no speculation, no financial instruments whatsoever. This is pure communication infrastructure. Think of it as a message-passing and continuity verification protocol that happens to use blockchain data structures for cryptographic verification — but that doesn't make it a cryptocurrency.

**Important:** Bright-net is NOT an authoritarian surveillance-state thing. It's not intended to replace the internet. It runs alongside it. The public internet, the dark net, and Web3, will all continue to exist exactly as they do now. Bright-net would be a fourth option you can choose to use when you want it. This is intentional. A single network with a single point of control is exactly the kind of thing authoritarian systems exploit. Coexistence is a feature, not a limitation.

Bright-net refers to both the proof-of-continuity protocol described here and its reference implementation that manages avatar chains, shard distribution, and blockchain handshakes across your own devices.

---

## License

This project is licensed under the [Creative Commons Attribution 4.0 International License (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).

Copyright (c) 2026 Alex Andria Franklin

You are free to use, share, and modify this work, even for commercial purposes, as long as you give me credit for coming up with the idea.

See the LICENSE file for full details.

---

## 1. Why We Need This

The internet's core protocols (TCP/IP, DNS, HTTP) were designed for a network where everyone knew each other. Think about it: in the '70s, if you were on ARPANET, you probably got coffee with half the people on the network. Headers could be believed, connection requests got optimistic treatment, and authentication happened through institutional relationships rather than cryptography.

Then the network grew to billions of users. We added security layers incrementally: TLS for encryption, DNSSEC for DNS validation, various authentication protocols. These helped, but they're basically band-aids on protocols that were never designed with adversaries in mind. And that creates fundamental limits on what trust models are even possible.

### 1.2 The Current Situation

Most people today rely on centralized services for pretty much everything:

- Identity providers handle authentication and manage your credentials
- Platform companies host your data and provide computational services
- Your personal devices are often glorified thin clients to the cloud
- Deepfake scams are becoming more prevalent

The existing model has worked for decades. it's economically successful and operationally convenient. It enables rapid scaling and reduces technical barriers. But it also concentrates control over data, identity, and computational resources in the hands of platform operators. You're dependent on them, and your personal autonomy is limited.

### 1.3 What Goes Wrong

Several recurring problems emerge from the current architecture:

- **Password-based authentication:** Shared secrets can be stolen, forgotten, or socially engineered. Users struggle to maintain unique strong passwords across dozens of services.
- **DDoS vulnerability:** Stateless connection protocols make it practically impossible to distinguish legitimate traffic from attack traffic until you've already allocated resources.
- **DNS as a trust anchor:** Name resolution functions as both a convenience layer and a security-critical component, making it a high-value target for attackers.
- **Sybil resistance:** Creating new identities is free, enabling spam, manipulation, and coordinated inauthentic behavior at massive scale.
- **Data portability:** Your data is often locked within platform-specific formats and APIs, making migration between services technically complex.

Bright-net explores whether different architectural choices could address these limitations while maintaining or improving usability and security.

### 1.4 Heuristics vs. Proof

The security industry's response to these problems has been heuristics — pattern matching, behavioral analysis, anomaly detection, reputation scoring. "This traffic looks suspicious, block it", "This login is from an unusual location, challenge it." These are educated guesses at scale, and they're the best the current architecture allows. They work well enough to keep the internet functional, but they're fundamentally probabilistic. They can be fooled, tuned around, and evaded by anyone patient enough to study the patterns.

Heuristics aren't a solution. They're an accommodation to a broken foundation.

Bright-net doesn't need heuristics for the problems it solves because the verification is cryptographic, not probabilistic. Either the chain tip is valid or it isn't. Either the handshake verifies or it aborts. No guessing, no pattern matching, no "this looks like a bot." The architecture produces certainty where the current internet produces estimates.

### 1.5 Beyond the Privacy vs. Security Trade-off

Network architecture has historically assumed you must sacrifice privacy for security. A false dichotomy that goes back to the political philosophy of Hobbes' Leviathan from 1651. It has been disproven many times since. Here's where I disprove it again.

Each connection requires a verifiable block on your avatar chain. When initiating a handshake, your avatar claims 'I stamped a valid block for this connection.' The recipient verifies: does the block exist? Is the signature valid? Is the timestamp legitimate? Verifiable claims proceed; unverifiable claims get rejected.

The system can't verify what didn't happen. This creates a default-deny architecture: without proof of continuous existence, connections fail. Attackers trying to flood connections without stamping blocks face repeated verification failures, effectively rate-limiting themselves through unverifiable claims.

This additional network layer — cryptographic state verification between transport and application — enables both privacy and security simultaneously. It's analogous to how TLS added encryption without replacing TCP/IP.

---

## 2. How It Works

### 2.1 Proof-of-Continuity Explained

Unlike proof-of-work systems (Bitcoin, Ethereum) that use computational difficulty as a security mechanism, proof-of-continuity uses time intervals on network interactions. Here's the key insight: while you can speed up local block generation with better hardware, the rate of network handshakes — the security-critical operations — is bounded by time itself and can't be accelerated or parallelized. The lag to establish new network connections doesn't need to be prohibitively expensive, but it can't be free either. Something around 1-10ms is enough of a time delay. For comparison: it takes about 40ms to blink.

Key properties:

- Network handshakes must occur sequentially and are rate-limited by protocol feedback mechanisms
- Each handshake requires cryptographic verification of chain continuity from previous interactions
- Attempting to establish connections too rapidly triggers negative feedback
- The time interval is on interaction frequency, not computational speed. A chain showing six months of activity can't be created instantly regardless of your hardware

This eliminates the energy waste of proof-of-work mining while providing Sybil resistance through time intervals rather than computational expenditure.

### 2.2 The Blockchain Handshake Protocol

A QUIC/TLS tunnel replaces the traditional TCP three-way handshake with a two-message blockchain handshake. The design resolves a fundamental tension: mutual authentication requires both parties to prove themselves, but DDoS resistance requires the responder to avoid allocating state for unverified initiators. Bright-net handles this through three defences that operate at distinct layers, described in §3.1.

**Step 1: TLS Tunnel Establishment (via QUIC)**

You and whoever you're connecting to establish an encrypted QUIC/TLS tunnel. This provides confidentiality for all subsequent steps and activates QUIC's built-in Retry mechanism. Before any application state is allocated, QUIC sends a Retry packet that forces the initiator to prove their source IP is reachable, eliminating spoofed-source floods at the transport layer for free, as specified in RFC 9000 §8.1.

**Step 2: Chain Tip Exchange**

Inside the encrypted tunnel, both parties exchange signed HandshakeTokens — ephemeral proofs-of-possession containing:

- Current chain tip hash (links the session to the avatar's continuous history)
- Fresh timestamp and random nonce (prevents replay)
- Ed25519 signature over all fields (proves key control)

Each party verifies the other's token: signature valid, timestamp within clock-skew window, chain tip hash well-formed. The responder binds their token to the initiator's offer via a SHA-256 hash, so no valid response can be detached and replayed against a different session.

**Step 3: Verification or Abort**

If both tokens verify, the connection proceeds and both parties append a new `Handshake` block to their respective chains documenting this interaction. If either verification fails, the handshake aborts — no block is written, no connection is established, and the failed attempt is recorded against the initiator's avatar for rate-limiting purposes. Repeated failures trigger exponentially increasing backoff, making sustained attack campaigns self-defeating.

This handshake sequence can't be parallelized or accelerated — each step must complete before the next begins, and the protocol enforces rate limits on handshake frequency through the negative feedback mechanism described in §3.1.

### 2.3 Avatar Structure and Merkle Trees

Each user's digital presence is organized as a Merkle tree rather than a single linear blockchain:

- **Root node:** Anchored to your home network infrastructure (router, typically with static IP). The root is cryptographically sharded (default 3-of-5 threshold) across your devices.
- **Branches:** Individual avatar chains fork from the root. You might have separate avatars for work, gaming, shopping, anonymous discussion, etc.
- **Privacy:** You see your full Merkle tree structure. External parties only see the specific branch relevant to their interactions. Branches can't be linked together through the protocol layer.

This structure enables compartmentalization: you can maintain multiple context-specific identities without creating linkable profiles. An attacker observing one avatar can't discover or correlate your other avatars.

Avatars are pseudonymous, not anonymous. Each avatar proves continuous existence over time — 'I am the same entity I was yesterday' — without revealing who you are in real life.

### 2.4 Shard Distribution and Device Management

The root of each user's Merkle tree is anchored by the genesis block. Both the genesis block and the current root signing key are sharded using Shamir's Secret Sharing with a default 3-of-5 threshold.

- Five shards are generated, each containing a fragment of the genesis block and root signing key
- Any three shards can reconstruct the complete genesis block and root signing key
- The genesis block proves ownership and anchors the entire chain
- The entropy seed used to generate the genesis block is destroyed after initialization
- Shards are distributed across your device ecosystem: router, phone, laptop, tablet, desktop, etc.
- You can lose up to two devices and still maintain access
- Thresholds are configurable: 2-of-3, 4-of-7, 5-of-9, etc.

**Biometric Access:** Each shard is encrypted with a key derived from a composite of multiple local factors: something you are (fingerprint, face scan) and something you have (the device itself). No single factor is sufficient. None of this ever leaves the device.

**Device Pairing:** To add a new device, you provide your biometric on both the new device and an existing shard holder. The devices perform a blockchain handshake to verify they belong to the same root, then generate and distribute a new shard.

**Device Loss or Theft:** If a device is lost, shards are recoverable as long as you can still reach your 3-of-5 threshold. To recover from a compromised device, you re-assemble the threshold, generate a new root signing key, and sign a key rotation block on the chain with the old key before the old key is retired.

---

## 3. Security Properties

### 3.1 DDoS Resistance

Bright-net inverts the cost asymmetry of DDoS attacks through three independent defences operating at different layers. Each layer handles a different class of attack.

**Layer 1 — QUIC Retry (IP-spoofing filter)**

QUIC's built-in Retry mechanism (RFC 9000 §8.1) forces any initiator to prove their source IP is reachable before the responder allocates any handshake state. The responder issues a Retry packet containing a token bound to the connection attempt; the initiator must include this token in their first fully-formed packet. A host with a spoofed source address can't receive the Retry and therefore can't complete the exchange. This filters volumetric UDP floods at the transport layer for free — Bright-net inherits this by running over QUIC.

**Layer 2 — Proof-of-Continuity (Sybil resistance)**

Every handshake requires a valid chain tip: a signed, timestamped block linked to a continuous history. This is not free to produce. Building a chain with six months of history requires six months of real elapsed time, regardless of computational power. An attacker flooding the network with valid handshakes must therefore maintain a large portfolio of aged avatar chains — the cost scales linearly with sustained attack volume and can't be parallelized or accelerated. This turns large-scale sustained attacks into prohibitively expensive infrastructure projects.

**Layer 3 — Rate Limiter (failure-rate filter)**

Failed handshake verifications trigger exponential backoff. The first failure incurs a short cooldown; each subsequent failure within the tracking window exponentiates the delay, up to a configurable maximum. Successful handshakes reset the counter. An attacker who can't produce valid chain tips — or who rotates through fresh, unaged chains — burns through attempts quickly and finds themselves progressively throttled with diminishing returns.

Together, these three layers address IP spoofing, freshchain flooding, and brute-force verification attempts without requiring the application to maintain any per-connection cookie state.

### 3.2 Sybil Resistance

Creating a single avatar requires minimal computational effort, but creating thousands of aged avatars is prohibitively expensive due to time intervals:

- New avatars have no history and can be rate-limited or treated with higher scrutiny
- Building history takes real time — a six-month-old chain requires six months to create, regardless of computational resources
- Human attention is limited — one person can realistically only use 2 or 3 devices simultaneously

### 3.3 Forward Secrecy and Ephemeral Keys

A double-ratchet mechanism ensures forward secrecy: compromising current session keys doesn't enable decryption of past communications. Each block in an avatar chain includes ephemeral public keys that expire after use or timeout.

Avatar chains are read-only from an external perspective. Historical blocks contain cryptographic hashes of interactions, not the interaction content itself. You can't decrypt past communications — only verify that they occurred.

### 3.4 DNS and IP Address Demotion

In this protocol, DNS is demoted to an optimization layer. Connections are authenticated via avatar chain tips, not domain names. If DNS lies — poisoned or hijacked — the chain tip verification in the handshake will immediately fail and the connection aborts. DNS poisoning can deny you a connection, but it cannot impersonate anyone.

Similarly, IP addresses become purely routing information. An avatar can connect from different IPs and still be recognized via chain continuity.

---

## 4. Distributed Infrastructure

### 4.1 Your Router is Already the Anchor

No new hardware required. Your router is already always-on infrastructure that most households have. Bright-net doesn't ask you to buy a server or run a datacenter in your closet — it asks your router to do slightly more than it already does.

The anchor for your avatar chain lives at your home network infrastructure. When you're connected, your avatars are reachable. When you disconnect — turn off your router, go offline, whatever — your avatars simply become unreachable, the same way any other internet service goes dark when you unplug. No chain damage. No penalty. Just offline, like normal.

For users who want to go further, the protocol supports a shift toward home-centric compute:

- Heavy computation runs on home hardware and/or distributed across your devices
- Thin clients (phones, laptops, tablets) become primarily I/O devices
- You experience a consistent computational environment across all devices

This model eliminates the need for expensive cloud subscriptions for personal compute. You own the hardware, run your own services, and pay only the electricity cost. But this is the vision, not the requirement. The protocol works today with the router you already have.

## 5. What This Enables

### 5.1 Login for the Last Time Ever

Bright-net eliminates passwords entirely:

- Initial setup creates the root shard and distributes it across devices
- Subsequent connections authenticate via biometric (local, never transmitted) plus chain continuity verification
- No passwords to forget, steal, or phish
- No 'forgot password' flows or account recovery procedures

Rather than asking for a passkey from an app, you give a passkey to them.

*(Caveat: You may still log out if desired. Your avatars will effectively "disappear" from the internet while your router is offline, and reappear when it comes back on.)*

### 5.2 Privacy by Architecture

Privacy isn't a policy or a promise. it's structurally enforced by the protocol:

- **Cryptographic fragmentation:** Your data is sharded across devices you control. No central aggregation point exists.
- **Avatar compartmentalization:** Multiple avatars can't be linked without the assembled genesis block.
- **Write-only chains:** Historical interaction content isn't preserved in recoverable form.

### 5.3 Accountability Through Protocol Design

Bright-net provides a third path between complete anonymity and complete transparency: accountability through cryptographic continuity, not through centralized data collection.

- **Reputational memory:** Entities can recognize each other across time. Persistent bad actors accumulate negative history.
- **Self-regulating systems:** DDoS, spam, and abuse trigger protocol-level responses without requiring centralized moderation.
- **Opt-in identity:** You can choose to reveal real-world identity if beneficial, but this is optional.
- **Avatar destruction:** You can selectively burn individual avatar chains or the genesis block itself.

---

## 6. Threat Model and Limitations

### 6.1 Biometric Compromise

Shard decryption relies on a composite of multiple local factors. An attacker who obtains just your thumbprint or just your device, cannot decrypt a shard. Even with a fully compromised device, they have only one shard. Insufficient to reconstruct the root without reaching the threshold across multiple devices.

### 6.2 Shard Loss and Irrecoverability

If you lose access to 3 or more shards, your avatar is permanently inaccessible. There's no customer support, no account recovery flow. This is both a feature and a risk. True ownership means true responsibility.

Mitigation: higher shard counts, geographically separated backups, trusted contacts holding encrypted backup shards.

### 6.3 Compromised IoT Devices (Aged Sybil Variant)

It's highly recommended that IoT devices don't hold shards. IoT devices are notoriously insecure. A sophisticated attacker could compromise IoT devices that have been maintaining legitimate avatar chains for months.

### 6.4 Initial Bootstrap and New User Onboarding

New users with no chain history are fully supported. The protocol is permissionless. A new chain is created at registration and immediately functional. Lack of temporal depth isn't a disqualifier. It's just a starting point. Trust accrues over time as the chain grows. A new account on Bright-net is no different than a new account anywhere else — it just hasn't had time to prove anything yet.

### 6.5 Storage Management and Chain Pruning

Avatar chains grow continuously. Mitigation strategies include Merkle tree compression, checkpointing, and distributed archival. Proving continuity doesn't require the entire historical chain — only the ability to cryptographically link the current state back to a trusted checkpoint or genesis block.

---

## 7. Comparison to Existing Systems

### 7.1 Public Internet

**Advantages:** Eliminates password-based authentication, DDoS resistance via self-regulating negative feedback, privacy by architecture, you own the infrastructure.

**Trade-offs:** Multiple shard loss can be catastrophic, not backward-compatible with existing protocols.

### 7.2 Tor / Dark Net

Tor provides maximum anonymity but no persistent identity. Bright-net provides continuous recognizability without real-world identity disclosure. These serve different use cases and can coexist.

### 7.3 Cryptocurrency / Web3

- **Proof-of-work waste:** Bright-net uses time as the constraint.
- **Financialization:** No native token or financial layer.
- **Public ledgers:** Bright-net uses private chains with cryptographic privacy guarantees.

---

## 8. Implementation Considerations

### 8.1 Cryptographic Primitives

- **Hashing:** SHA-256 or BLAKE2
- **Public-key cryptography:** Ed25519 for digital signatures
- **Symmetric encryption:** ChaCha20-Poly1305 or AES-GCM
- **Key derivation:** Double ratchet mechanism (Signal Protocol)
- **Secret sharing:** Shamir's Secret Sharing

The protocol doesn't invent new cryptography. It composes existing primitives in a novel architecture.

### 8.2 Network Topology

The protocol operates as an overlay network on top of existing internet infrastructure. Similar to how Tor routes traffic through the existing internet, this protocol uses existing physical infrastructure while replacing the application and transport layers with blockchain handshakes.

### 8.3 Adoption Pathway

- **User benefits:** Elimination of passwords, as well as user ownership of infrastructure and data
- **Interoperability:** Bridges to the existing internet where possible
- **Developer ecosystem:** SDKs, documentation, examples
- **Viral growth:** Users invite trusted contacts

---

## 9. Conclusion

That phone call wasn't a fluke. It happens millions of times a day, in every language, in every country. It happens because the protocols that carry our voices and data were designed to trust first and verify never — and fifty years later, we're still living with that decision.

Bright-net is the answer to the question I asked sitting in that car: why does the internet work this way? It doesn't have to. Time is a scarce resource that can't be faked, parallelized, or bought. Identity can be cryptographically continuous without being personally disclosed. Ownership of your data and infrastructure isn't a utopian fantasy — it's an engineering choice. We just haven't made it yet.

This protocol has real trade-offs. You maintain your own infrastructure. You are responsible for your shards. There is no account recovery. These aren't bugs — they're the direct consequence of genuine ownership. The current internet trades those responsibilities away in exchange for convenience and central control. Bright-net trades them back.

Most importantly, this isn't a theoretical exercise. The protocol is designed to be built and deployed, open-sourced under permissive licensing, and iterated upon by a community of developers and users who believe a better internet is possible.

The public internet, the dark net, and the cryptocurrency sphere will continue to exist. Bright-net is a fourth option — one built on cryptographic trust rather than institutional trust, on continuous identity rather than passwords, on your hardware rather than someone else's cloud.

The question isn't whether such a system is possible — it is. The question is whether enough people care to build it.

---

## Appendix A: Technical Glossary

**Avatar:** A cryptographic identity chain representing a continuous digital entity. Avatars are recognizable across time but don't require real-world identity disclosure.

**Blockchain handshake:** A connection establishment protocol that integrates cryptographic verification via chain tips and ephemeral keys at the transport layer, replacing traditional TCP SYN-ACK.

**Chain tip:** The most recent block in an avatar blockchain. Used during handshakes to prove continuity and verify that the entity is the same one from previous interactions.

**Double ratchet:** A cryptographic mechanism (from the Signal Protocol) that advances key material with each message exchange, ensuring forward secrecy.

**Ephemeral keys:** Public keys generated for a single session or block that expire after use or timeout.

**Forward secrecy:** The property that compromising current keys doesn't enable decryption of past communications.

**Merkle tree:** A cryptographic tree structure where each node is a hash of its children. Users organize multiple avatar chains as branches from a root node anchored at their home infrastructure.

**Proof-of-continuity:** A mechanism where an entity proves existence over time via a blockchain that can't be pre-computed or parallelized. Uses time intervals instead of computational work.

**Shard:** A cryptographic fragment of the genesis block and root signing key, distributed across multiple devices using threshold secret sharing.

**Sybil attack:** An attack where an adversary creates many fake identities to gain disproportionate influence or overwhelm a system.


