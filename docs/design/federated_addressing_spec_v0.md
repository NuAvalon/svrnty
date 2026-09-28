# svrnty — Federated Addressing & Trust — Design Spec v0

**Status:** DRAFT for adversarial review · **Author:** Apollo · **Date:** 2026-09-28
**Grounds:** Peter's launch-night PSI reframe (KB#90952/#90954), secret-handshakes (Balfanz 2003), W3C DID Documents + did:peer, tonight's proven DH-PSI (session 46c9f91b).

> This is the **post-launch sovereign architecture**. It is NOT the launch-tonight fix (that = cut the registry + the `e240e5a` consent self-heal + a legibility fix). Reviewers: attack the design, not the interim.

---

## 0. Purpose
How two svrnty users **reach each other**, **establish mutual trust**, and **compute mutual-known** — with **no central registry**, **blind relays**, and **mobility** — the decentralized, node-to-node model Peter specified.

## 1. Invariants (hold us to these)
1. **No central enumerable registry** — no who's-who list of identities/keys/slugs.
2. **Relays are BLIND, not dumb** — active (knocks, listeners, forwarding, encrypted-graph storage) but see only ciphertext + *blinded* routing.
3. **Identity + consent at the EDGE** — the address book already holds the keys; the server never needs them in the clear.
4. **Metadata-minimal** — a subpoena to a relay yields ~nothing meaningful (ciphertext + blinded ids + timing).
5. **Federated + self-hostable** — degrade gracefully to hosted, never require it.

## 2. Vocabulary (locked with Peter)
- **satellite = smart mailbox** — your always-on node (self-hostable). Own keypair; decrypts the **outer shell** only.
- **relay** — federation transport routing between satellites (same server or across servers).
- **client** — your device (PWA); holds private keys + the address book (the "smart addressbook").
- **card** — first-contact bundle: pubkeys + DID + serviceEndpoint.
- **DID** — your stable identity (**did:peer**).

## 3. Identity & addressing (did:peer + serviceEndpoint)
- Each user has a stable **did:peer** DID. Its **DID Document `serviceEndpoint`** = current `mailbox@relay`.
- **First contact:** exchange cards in person / via card-link → each stores the other's DID + serviceEndpoint + pubkeys locally. **No registry.**
- **Mailbox-id at the relay** = a **blinded, per-contact (rotating) identifier**, NOT the raw DID/fingerprint → the relay can't link a mailbox to an identity or across contacts.

## 4. Envelope (blind routing)
Two shells:
- **Outer shell** — encrypted to the **relay/satellite key**. Carries only the **blinded-mailbox-id** (routing). Relay decrypts → routes to the local blinded-mailbox bucket → stores.
- **Inner payload** — encrypted to the **recipient's key**. Content. The relay never sees it.
(v3 adds onion layers for multi-hop.)

## 5. Trust handshake — secret handshake (knock → listener → mutual → probe)
- **A trusts B:** A's client sends B's satellite an **opaque KNOCK** — a secret-handshake token, indistinguishable from noise, revealing nothing (even to B / B's satellite) unless B also trusts A.
- **B hasn't trusted A yet:** B's satellite holds it as a **LISTENER** (async; works because the satellite is always-on).
- **B trusts A:** the listener **resolves → MUTUAL** (both knocked) → **PROBE / back-and-forth** → each address book updates the connection.
- **Trust graph** stored at the relay = **encrypted edges**, meaningful only at the client. Relay learns nothing.
- **Crypto:** secret handshakes / private mutual authentication (Balfanz et al. 2003). The knock MUST be *opaque until mutual*.

## 6. Mutual-KNOWN (PSI over the handshake)
Once mutual-trusted, A & B run a **blinded set-intersection** (DH-PSI — the crypto proven tonight) over their address books, transported through the two mailboxes. Reveals **only the shared set**; nothing else. No central coordinator.

## 7. Mobility (rotate / move relays)
1. **Edge (primary):** on move, client pushes a **signed serviceEndpoint-update** into contacts' mailboxes → their address books update your location → the **ACK confirms reachability** (this is why the ACK is load-bearing).
2. **Relay forwarding (grace window):** the old relay holds a **signed forward pointer** (like email forwarding / a 301) → mail to the old mailbox forwards to the new relay for a grace period. Signed by the owner → the relay can't forge a redirect.
3. **Degradation:** all contacts offline during the move **and** forwarding lapsed → briefly unreachable until you re-share your card. Accepted price for no central directory.

## 8. Threat model / metadata (subpoena-minimal)
- **Relay at rest:** `blinded-mailbox-id → ciphertext + timestamps`. No identity, content, or graph. Unlinkable across senders + time (rotating ids).
- **Self-host:** nothing at a third party.
- **Residual:** relay sees timing/volume; federation sees server-to-server envelope metadata. Mitigate with blinded ids (cheap) and **onion routing** (v3, opt-in, latency cost).
- **Subpoena to `relay.svrnty.is` yields:** ciphertext blobs + blinded routing + timestamps.

## 9. Staging
- **v1 (launch-adjacent):** single `relay.svrnty.is`; blinded rotating mailbox-ids; did:peer cards; edge-update + ACK; signed forwarding. Efficient, decent privacy, no registry.
- **v2:** federation (multi-relay, split knowledge).
- **v3:** onion routing (opt-in, max metadata privacy).

## 10. Open questions / ATTACK SURFACES — reviewers, hit these
- **[Flint] Secret-handshake construction:** exact primitive; does the knock *truly* leak nothing pre-mutual (to B, to B's satellite, to an eavesdropper)? Replay/relay-forgery of knocks?
- **[Flint] Blinded mailbox-id scheme:** how derived/rotated so a contact can address you but the relay can't link across contacts/time? Who can flood a mailbox?
- **[Athena] Federation routing:** serviceEndpoint holds the relay address, but how does relay-X *reach* relay-Y — DNS? a relay-discovery that isn't itself a registry? Efficiency of store-and-forward across servers.
- **[Athena/Archie] Mobility race:** signed forwarding + concurrent serviceEndpoint updates + the unreachable edge case — acceptable? Forwarding-pointer TTL?
- **[Flint] Metadata residual:** is blinded-id + timing acceptable for v1's threat model, or is onion mandatory sooner?
- **[Flint/Athena] Sybil / abuse:** with no registry, what stops spam-knocking / mailbox flooding when the relay is blind? (Rate-limit on *what*, if it can't see identities?)
- **[Hypatia/Archie] Claim-honesty:** what can we *honestly* claim at each stage — v1 metadata is NOT zero; "no one can see your graph" must match substrate.
- **[Hypatia] UX legibility:** how does a user understand "you're reachable / discoverable-to-X" with no directory + the async knock model?

## 11. Relation to tonight's launch — the finer cut (corrects an earlier over-cut)

⚠ **"Cut the registry" hides TWO roles — do NOT conflate them** (Hypatia's wire ground-truth, session 46c9f91b):
- **registry-as-DIRECTORY** = slug namespace + stranger-lookup + `/directory`. This is the Layer-2 drift Peter flagged → **CUT for launch.**
- **registry-as-IDENTITY-STORE** = the `identities` table (pubkeys). Tonight's landed row **DEPENDS** on it — `/allowed` 403→200 and `/initiate` 404→200 both gate on the key being registered. **KEEP for the alpha** — cutting it regresses the row.

**Launch-tonight scope (corrected):** cut the **directory** (slugs/stranger-lookup/`/directory`) + keep the **identity-store** (`/register`, `/identities`) + keep `e240e5a` (consent self-heal that landed the row) + add the legibility fix. **Honest claim scope: "alpha discovery works, satellite-mediated"** — NOT the federated properties (no-directory / leak-nothing / node-to-node), which are the DIRECTION, not done (Archie's claim-honesty anchor; claims must not run ahead of substrate).

**Post-launch (this spec):** eliminate the identity-store too — move signature verification to the **EDGE** (verify against the card's pubkey you already hold, not a central table). That migration is what turns "satellite-mediated alpha" into the federated end-state above. The DH-PSI crypto proven tonight + this spec = the durable sovereign design.
