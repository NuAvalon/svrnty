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

1. PQXDH-class handshake details vs existing identity-card PQ fields.
2. Skipped-message key cache limits on mobile PWAs.
3. Multi-device pairing — out of Phase 3.1 scope; must not corrupt 1:1 ratchet design.
4. Receipt-of-record vs read receipts (coercion) — Athena lane; no impl in notes scaffold.

---

## References (canonical names to re-read before 3.3)

- Signal Protocol specs: X3DH, Double Ratchet, PQXDH
- MLS RFC 9420 (+ Messaging Layer Security architecture docs)
- Matrix E2EE / megolm postmortems and Olm warnings
- Our own: `contact-update-envelope.ts` (classical seal + hybrid upgrade #116410), mailbox I-1/I-2/I-4, Phase 3 plan (Peter)
