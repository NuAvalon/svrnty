# svrnty — frontend build queue

Work top-down: the top task first, then the next. Build to spec. Open **ONE PR per task**. Copy/code that makes a security / recovery / trust **CLAIM** needs review before merge — do **not** self-merge crypto/claim surfaces. See `.cursor/rules`.

**Cursor = RENDER-GLASS ONLY** (UI/render). Crypto / keys / PSI / relay-logic / migration-logic = TEAM (Athena/Flint/Apollo). "You render the glass, the team holds the locks." Build ✅ items top-down, one PR each. ⏳ items at the bottom are NOT actionable until their spec lands — do not start them (a missing spec would be confabulated).

*Recently completed: Camera QR-scan (#96), Mint-Build Recipe v2 KERI (#112).*

## 1. Messaging / Notes UI — thread list + view + controls — ⏳ NOT ACTIONABLE YET (render-glass)

> ⏳ **Do NOT start.** Blocked on the TEAM wire-transport hooks (dogfood send/receive) landing — the UI must wire to REAL send/receive hooks, never invent them (a missing-hook spec would be confabulated). Spec'd from the product requirements; claim-ceilings reviewed + bound (team); architecture/constitution reviewed (team). When the transport hooks land, this graduates to ✅ with the hook contract + the 2 G6 edges folded in.

The in-app **notes/messaging** surface: thread list + thread view + per-thread/per-note controls, started from a contact or from the galaxy. Builds on the EXISTING `app/msg/page.tsx`, `src/lib/messaging`, the `svrnty-notes` store (`docs/MESSAGING_STORE.md`: threads/notes/ring_channels, AES-GCM, retention/TTL, kinds direct|ring), and item #1's crypto hooks. **Render-glass only** — wire to the team hooks below; do NOT reimplement crypto / transport / store logic.

### Hooks it wires to (DO NOT reimplement)
- **Crypto (DONE, item #1):** `encryptToContact` / `decryptFromContact` (`src/lib/crypto/contact-message.ts`). ML-KEM params derive from the contact's STORED key length (never hardcode).
- **Store (DEFINED):** the `svrnty-notes` IndexedDB (`docs/MESSAGING_STORE.md`). Controls operate on THIS, never on the book/vault DB.
- **★ WIRE TRANSPORT (TBD — TEAM: Athena/Apollo/Flint):** send/receive over the svrnty relay dead-drop. **Not landed → this item is ⏳.** When the contract lands, fold in these G6-coherence edges: (1) `sending` must NOT be a silent dead-end — it resolves to `pending` (durable outbox) or a terminal, never stuck/silent; (2) deleting a thread/note with a PENDING undelivered outbox entry must CANCEL/resolve it — no zombie retries of a deleted thread, no post-delete delivery the sender believes is gone.

### UI (product requirements)
- **Thread list:** threads from `svrnty-notes` (direct|ring), last-activity, unread. Empty → "start a note."
- **Thread view:** notes (direction/sent-at), compose box → send (wires to the team transport hook).
- **Per-thread / per-note controls:** `info` (participants/fingerprint/retention), `delete` (user-ruled; thread-delete cascades to its notes), `archive` (hide from main list, keep in store), `move` (re-file the thread). Store-local.
- **Start/open a thread via:** **Contact picker** (book; KNOWN/VERIFIED only, **fail loud**) + **Galaxy select** (TrustMap node → open/start a thread).
- **Contact/group organize:** largely LIVE already (ContactManagement + TrustMap `onAssignGroup`) — spec only the DELTA (e.g. group-filter in the messaging picker); do not re-build what exists.

### ★ CLAIM-CEILINGS (binding; UI copy MUST NOT exceed these; each names its graduation gate)
**C1. Public term = "notes," NOT "messaging."** User-facing copy = **"notes"** / "private notes between contacts" — NEVER "messaging"/"chat"/"messages" in product strings (internal naming only). GROUNDED (`docs/MESSAGING_PRIOR_ART.md` claim-ladder rung1-vs-rung2 + :29): current capability = seal-to-contact-pubkey confidentiality, NOT the FS+PCS of Signal-grade messaging. GRADUATION: "messaging" unlocks only at **Phase 3.3 (FS+PCS hybrid-PQ ratchet)**. ⚠ encryptToContact being PQ-hybrid (C2) does NOT upgrade notes→messaging — PQ confidentiality ≠ the ratchet.
**C2. No present-tense PQ claim until the PQ-3-check passes; encrypt-and-carry ≠ wire-transmit.** No "post-quantum"/"quantum-safe"/"PQ-sealed" present-tense until the dev dummy-test PQ-3-check. Until then: "encrypted" or "post-quantum — rolling out." Never imply svrnty/the relay secures/transmits the note — say "end-to-end encrypted, carried by a blind relay," NEVER "sent securely through svrnty."
**C3. Agents are classical-until-minted.** No "PQ-sealed to <agent>" for any agent participant until agents mint PQ identities (currently display-only). Human↔human carries the PQ mechanism; agent-side is classical until mint.
**C4. Delivery copy ties to the G6 no-silent-loss states.** States = `sending / pending / delivered / expired`. **"delivered" renders ONLY on an AUTHENTICATED ack** (never unauthenticated; never "sent" then silent-drop). `pending` = durable send-outbox observable across restart; `expired` = sender-visible TTL. Every sent note → a VISIBLE terminal state (DELIVERED∪EXPIRED∪PENDING), no silent gap.
**C5. No "sealed sender" / metadata-privacy claim** until a **security-reviewed** sender-anonymity construction exists (`MESSAGING_PRIOR_ART.md`:41/:39). Mailbox-id linkability/timing/size metadata is an open hardening track — don't imply metadata-privacy we don't have.
Function-blueprint linkage (product; copy graduates ONLY when the §9 state ratchets green): C1→claim-ladder rung · C2→PQ-encap-live-state · C3→agent-mint-state · C4→G6-union · C5→sender-anonymity-construction.

### Constraints
Render-glass only; thin wrappers over team hooks (crypto + transport + store). No crypto/transport/relay/migration logic in the UI. Verified-contacts-only, fail-loud. Never render raw key material. Copy obeys C1–C5.

### Non-goals (defer)
No transport/relay/dead-drop LOGIC (team). No new key management. Ring/group threads = fast-follow (direct first).

### Acceptance (finalize when the transport hook contract lands)
Open a thread via contact + via galaxy → send a note (round-trips over the team transport) → controls (info/delete/archive/move) operate on `svrnty-notes` → delivery-states honest per C4/G6 (incl. the 2 edges above) → all copy within C1–C5.