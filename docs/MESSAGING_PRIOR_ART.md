# Phase 3.1 — Messaging prior-art brief

**Status:** design substrate (Aug 2026). **Claim discipline:** do not call the product “messaging” in public until Phase 3.3 (ratcheting) is green. Until then the book carries **notes between contacts**.

**Rule (Peter Phase 3):** no message *protocol* code before this brief. This document is that brief; subsequent notes code must cite it.

---

## What we are stealing (and what we are not)

We ship **our** strengths (closed-by-default graph, sealed personal containers, dumb relays, living book) and borrow Signal/MLS’s decade of hard lessons — without cloning their product shape or their identity model (phone numbers, public write-open addresses).

| System | Steal | Leave behind |
|--------|-------|--------------|
| **Signal (Double Ratchet + X3DH/PQXDH)** | Per-message forward secrecy + post-compromise security; sealed-sender *ideas*; honest “E2E means host can’t read” | Phone-number identity; anyone-who-knows-you-can-ping; centralized default host as destiny |
| **MLS (RFC 9420)** | Scalable group key schedule; membership epochs; treeKEM lessons for large rings | Premature complexity before ring-channels prove out at small N |
| **Matrix** | Federation / replaceable homeserver as existence proof | Homeserver-readable defaults; “E2E optional” culture; room state as server-side social DB |
| **WhatsApp / big-tech E2E** | Scale lessons (receipts, multi-device pain) | Metadata maximalism; identity = phone; no exportable host |

---

## Double Ratchet (1:1) — what matters for us

1. **X3DH / PQXDH-class handshake** establishes initial root + chain keys from identity + ephemeral (and PQ KEM) material. Our identity cards already advertise `pq_kem_public_key`; Flint’s hybrid-PQ ratchet (PQXDH-class) is the intended graduate path.
2. **Symmetric ratchet** advances per message → **forward secrecy** (past messages stay sealed if a chain key leaks later).
3. **DH ratchet** on each reply direction → **post-compromise security** (heals forward after compromise, given new DH).
4. **Out-of-order / skipped keys** must be bounded (memory + abuse). Signal’s skipped-key limits are load-bearing.

**Until 3.3 is green:** classical seal-to-contact-pubkey notes (OpenPGP today, hybrid wrapper when #116410 lands) are **honestly scoped “notes”** — confidentiality in transit/at host, **not** FS/PCS. Never market as Signal-grade messaging.

### Triple-ratchet primitive (unwired)

`src/lib/crypto/message-ratchet.ts` is the 3.3 candidate, not a product claim. It is a hybrid triple ratchet: a symmetric chain on every message, plus an X25519 DH and an ML-KEM-1024 encapsulation on every direction change, mixed as `ssDh ‖ ssKem` into one root KDF. Both legs have to break to follow a later epoch. It is not wired into `sealNoteTo`, the notes store, or the Encrypt tab, and `isPQEncapLive()` stays false.

Honest limits, so this file does not light rung 2 by itself:

- No one-time prekeys. The recipient's long-term X25519 + ML-KEM secrets re-open the **initial** sending chain. Forward secrecy against that seizure starts at the first reply, whose ephemeral secrets are deleted and are not a function of the identity keys.
- Post-compromise security heals when the compromised party **sends** a new ratchet. A snapshot of a receiver still opens the next inbound message addressed to keys that snapshot already holds.
- Skipped keys are capped (64 per gap, 128 stored). Over the cap the open returns null and does not advance state.
- Forking a session (two live copies sending) reuses chain keys. `clone()` is a test probe.

Public word stays **notes** until this primitive is reviewed, wired, and the rung-2 tests are green.

---

## Sealed sender — what matters for us

Signal’s sealed sender hides **who** sent a message from the *service* (with tradeoffs). Our weaker-but-aligned default:

- Relay stores **opaque blobs** addressed to a mailbox (already I-4 uniform deposit).
- **Anti-spam is graph admission**, not sealed-sender crypto: strangers cannot place a note in your book until you’ve added their key (client drops unbound senders; see custody I-1/I-2 on contact.update).
- Metadata (mailbox_id linkability, timing, size) remains a hardening track (blinded mailbox IDs) — separate from ratchet.

Do not claim “sealed sender” until we have a real sender-anonymity construction reviewed by Flint.

---

## MLS / groups — what matters for us

**Phase 3.4 Ring-channels (our default for small groups):**

- Shared symmetric content key distributed via **per-member envelopes** (seal key to each member’s pubkey).
- **Rotation on membership change** (add/remove → new key; old key retired).
- Relay sees ciphertext to **K mailboxes** — **no roster table, no group name server-side, ever**.
- Client holds membership; server-side group systems stay quarantined fleet-internal.

**MLS:** adopt if/when member-count ambitions outgrow naïve envelope fan-out. Reading MLS now prevents rediscovering treeKEM the hard way; implementing MLS before ring-channels ship is premature.

### Ring fan-out and side threads (unwired from the public word)

`src/lib/messaging/ring-session.ts` sends each ring note as a **pairwise hybrid triple ratchet** to every other member (cap 8, including you). The relay gets one mailbox blob per member and no roster. Removing someone bumps the epoch, drops pair sessions, and the next note is a fresh initiate they are not on. That is the forward-secret path; the older shared `content_key_b64` on `RingChannel` is not what these notes are sealed under.

Side threads live inside a conversation. A note with no `thread_root` is the main timeline. A reply sets `reply_to` and `thread_root` (the main-timeline note it hangs from). Those fields are inside the signed note and inside the ring plaintext. This does not light rung 2 or rung 3 in public copy — the Hive still says **notes**.

---

## Matrix postmortems — lessons

1. **Optional E2E becomes optional security.** Our default: sealed notes; host is blind. No “plaintext room for convenience.”
2. **Server-side room state becomes a social database.** Ring-channels forbid server rosters/names.
3. **Federation without portability theater** — we already want exportable/transferable containers; messaging must ride the same leaveability story.
4. **Multi-device is a crypto product**, not a sync checkbox. Defer; single-device notes first.

---

## Data architecture (points at 3.2)

| Store | Lifetime | Contents |
|-------|----------|----------|
| **Vault / living book** | Permanent (user-ruled) | Identity, contacts, trust edges, decay |
| **Notes store** (`svrnty-notes`) | Ephemeral-by-default | Threads, note bodies, per-thread TTL/retention |

Separate IndexedDB (or later container volume). **Never** stuff conversation ciphertext into the contacts vault schema — cheap now, migration hell later.

---

## Claim ladder (do not skip rungs)

| Rung | User-facing words | Requirement |
|------|-------------------|-------------|
| 0 | *(nothing)* | Prior-art brief exists (this doc) |
| 1 | **Notes between contacts** | Separate store + seal-to-admitted-key + closed receive path |
| 2 | **Messaging** | 3.3 ratchet green (FS + PCS), hybrid-PQ path named |
| 3 | **Groups / ring-channels** | 3.4: no server roster; rotation on membership change |
| 4 | **Receipt-of-record** | 3.5 after Athena coercion review |

---

## Open questions for Flint / Athena (not blocking notes scaffold)

1. PQXDH-class handshake details vs existing identity-card PQ fields. The unwired answer in `message-ratchet.ts` uses the identity X25519 + ML-KEM-1024 pubs as the first prekeys (static-static DH binds the peer; ephemeral X25519 + ML-KEM ride in the header). A one-time prekey pool is still open — without it the initial flight is not forward-secret against seizure of the recipient's long-term secrets.
2. Skipped-message key cache limits on mobile PWAs.
3. Multi-device pairing — out of Phase 3.1 scope; must not corrupt 1:1 ratchet design.
4. Receipt-of-record vs read receipts (coercion) — Athena lane; no impl in notes scaffold.

---

## References (canonical names to re-read before 3.3)

- Signal Protocol specs: X3DH, Double Ratchet, PQXDH
- MLS RFC 9420 (+ Messaging Layer Security architecture docs)
- Matrix E2EE / megolm postmortems and Olm warnings
- Our own: `contact-update-envelope.ts` (classical seal + hybrid upgrade #116410), mailbox I-1/I-2/I-4, Phase 3 plan (Peter)
