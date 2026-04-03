Bright-net: Proof-of-Continuity Protocol
Alex Andria Franklin

Preface
I was sitting in my car when I got a call from "my bank." I've been a software developer for about a decade. I've been through this scam dozens of times. So I let it ring. He calls again. Then again. Fourth time, I pick up.
Me: "Will you shut up?"
Him: "Umm... what?"
Me: "I know who you are. I know what you're doing. This is a hack so simple it barely qualifies as a hack anymore. Leave me alone."
Him: "...No I'm not."
Then he hangs up. And I'm sitting there fuming, already vaguely familiar with SS7 and the fact that VoIP is designed to trust easily-forged headers by default. And I'm thinking: why does the internet work this way in 2026?
Then: why does the internet work this way in 2026?

The Problem
The internet was designed in the 1970s for a network of people who trusted each other. In 2026, we're still using protocols built on that assumption. Headers get spoofed, identities get faked, and DDoS attacks work because connection requests are handled optimistically by default.
The security industry's response has been heuristics — pattern matching, behavioral analysis, educated guesses at scale. Heuristics aren't a solution. They're an accommodation to a broken foundation.

The Core Idea
Bright-net replaces the traditional TCP handshake with a blockchain handshake at the transport layer. Every connection requires cryptographic proof that you are the same entity you were the last time — a chain of signed, timestamped blocks linking your current session to your history. You can't fake six months of history. Time is a resource that can't be parallelized or purchased.

What This Is Not

Not a cryptocurrency. No tokens, no coins, no financial instruments. This is communication infrastructure.
Not a replacement for the internet. Bright-net runs alongside the public internet, the dark net, and Web3. Coexistence is intentional.
Not an authoritarian surveillance system. Avatars are pseudonymous. The protocol proves continuity — I am who I was yesterday — without disclosing real-world identity.


How the Handshake Works
Step 1 — TLS Tunnel Establishment (via QUIC)
A QUIC/TLS tunnel is established between both parties. QUIC's built-in Retry mechanism forces the initiator to prove their source IP is reachable before any application state is allocated, filtering spoofed-source floods at the transport layer for free.
Step 2 — Chain Tip Exchange
Inside the encrypted tunnel, both parties exchange signed HandshakeTokens containing:

Current chain tip hash (links the session to the avatar's continuous history)
Fresh timestamp and random nonce (prevents replay attacks)
Ed25519 signature over all fields (proves key control)

Each party verifies the other's token. The responder binds their token to the initiator's offer via SHA-256, so no valid response can be detached and replayed against a different session.
Step 3 — Verification or Abort
If both tokens verify, the connection proceeds and both parties append a new Handshake block to their respective chains. If either verification fails, the handshake aborts, no block is written, and the failed attempt is recorded against the initiator for rate-limiting purposes. Repeated failures trigger exponential backoff.

DDoS Resistance
Three independent defenses operate at distinct layers:
Layer 1 — QUIC Retry (IP-spoofing filter)
Forces any initiator to prove their source IP is reachable before the responder allocates any state. Spoofed-source floods are eliminated at the transport layer.
Layer 2 — Proof-of-Continuity (Sybil resistance)
Every handshake requires a valid chain tip linked to a continuous history. Building six months of history requires six months of real elapsed time, regardless of computational power. Large-scale sustained attacks become prohibitively expensive infrastructure projects.
Layer 3 — Failure-rate throttling
Failed handshake verifications trigger exponential backoff. An attacker rotating through fresh, unaged chains burns through attempts rapidly and finds themselves progressively throttled with diminishing returns.

Passkeys: Flipping the Model
Today, when you log into a service, you ask them for permission — they hold the credential, you prove yourself to them.
Bright-net inverts this. Your avatar chain is your identity. When connecting to a service, you pass a cryptographic passkey to them, derived from your chain tip. The service doesn't issue you anything. It receives proof from you.
This eliminates passwords entirely. No shared secrets to steal, phish, or forget. No "forgot password" flows. No account recovery. The credential lives with you, not with them.
Privacy isn't a policy or a promise. It's structurally enforced by the protocol.

Avatars and Compartmentalization
Your digital presence is organized as a Merkle tree. Multiple avatar chains fork from a single root — you might have separate avatars for work, gaming, shopping, or anonymous discussion. From the outside, each branch is independent. External parties only see the branch relevant to their interaction. Branches can't be linked together through the protocol layer.
Avatars are pseudonymous, not anonymous. Each avatar proves continuous existence over time — I am the same entity I was yesterday — without revealing who you are in the real world. You can maintain multiple context-specific identities without creating a linkable profile.

Comparison: Bright-net vs. Tor
Tor provides maximum anonymity but no persistent identity. There's no concept of being recognizable across sessions — that's the point. Bright-net provides continuous recognizability without real-world identity disclosure. These serve different use cases and can coexist. Someone who needs Tor, needs Tor. Someone who needs trusted, persistent pseudonymity across time needs something Tor was never designed to provide.

Conclusion
Time is a scarce resource that can't be faked, parallelized, or bought. Bright-net uses that fact as a foundation. The handshake either verifies or it doesn't — no heuristics, no guessing, no pattern matching. Cryptographic certainty where the current internet produces estimates.
The question isn't whether this is possible. It is. The question is whether enough people care to build it.
