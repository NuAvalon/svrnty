# svrnty — frontend build queue

Work top-down: the top task first, then the next. Build to spec. Open **ONE PR per task**. Copy/code that makes a security / recovery / trust **CLAIM** needs review before merge — do **not** self-merge crypto/claim surfaces. See `.cursor/rules`.

**Cursor = RENDER-GLASS ONLY** (UI/render). Crypto / keys / PSI / relay-logic / trust-derivation = TEAM (Athena/Flint/Apollo). "You render the glass, the team holds the locks." You CALL the crypto functions and READ the trust derivation named below — you NEVER implement/mutate them. Build items top-down, one PR each.

*Recently completed: Camera QR-scan (#96), Mint-Build Recipe v2 KERI (#112). Over-wire receive note-fix (PR#212) + beta-access (A) (PR#213) MERGED to main — the hooks below are now LIVE.*

---

## 1. Trust-state visual — pending vs mutual UNMISTAKABLY distinct (render-glass; reads one honest phase)

> ★ PETER REPORTED THIS: trusting one-way makes a connection render WHITE (reads "mutual/connected") with no visible difference from an actual mutual bond. The DATA already distinguishes them — this is a render-only bug. The GATE on this task = **PETER SEES pending ≠ mutual at a glance** on-screen (he reported the miss; he verifies the fix). Build to "unmistakable," not "we think it's distinct."

**FLOW**
1. For each edge, call the EXISTING pure derivation `livingEdgeStatus(edge)` (`src/lib/trust/living-edge-status.ts`) → `{ trust: 'none'|'outbound'|'inbound'|'mutual', connection: 'classical'|'pending'|'linked', statusLine, detailLine, ... }`; chip via `livingStatusChip(status)`. This is SHIPPED, pure, fail-closed — **READ it, never recompute trust from raw `edge.trusted`/`edge.mutual`**.
2. Map `.trust` → visual through ONE single-source phase→visual map that ALL consumers read — render `TrustMapGalaxy`, `MasterAddressBookList`, AND `ContactManagement` from THIS one map (no per-consumer re-derivation; a 4th consumer must inherit it):
   - `trust==='none'` → **Known**: dim/outline, no fill.
   - `trust==='outbound'` (I trust them, not yet reciprocated) → **Trust-sent (pending)**: dashed/hollow shape + muted/desaturated color + label **"Awaiting mutual"**. ★ NEVER white/solid/lit.
   - `trust==='inbound'` (they trust me, I haven't) → **Trust-received**: distinct + actionable, label **"Trusts you · trust back?"**.
   - `trust==='mutual'` (reciprocal) → **Mutual**: solid/filled shape + full/lit color + label **"Mutual"**. ★ the ONLY white/lit bond.
   - BLOCKED → **Blocked**: muted/struck (keep distinct).
   - `ownerHasVerified(edge)` → **Verified** overlay: a mark ON the bond (orthogonal, NOT a tier/phase).
3. Render `connection` (`'pending'` = the intro-handshake) as a SEPARATE axis — do NOT conflate the intro `connection==='pending'` with the bond `trust==='outbound'`.

**INVARIANTS + TEST-ANCHORS**
- ★★ WHITE/LIT IFF `trust === 'mutual'`. An `outbound` edge MUST NOT render white/lit. TEST: an `outbound` edge asserts the pending treatment (dashed/hollow/muted + "Awaiting mutual"); a `mutual` edge asserts white/solid + "Mutual".
- ★ pending↔mutual UNMISTAKABLE, MULTI-CHANNEL. TEST: they differ on ≥2 channels (SHAPE + COLOR) AND carry distinct LABELS — NOT a fill-shade/opacity-only diff (the faint 0.28-vs-0.16 opacity is exactly what read as "no difference"). The LABEL is the strongest honesty-channel — lead with it, shape+color reinforce.
- Verify is ORTHOGONAL. TEST: a verified-but-`outbound` edge shows the pending bond + the verify-mark — verification NEVER promotes it to mutual/white.
- No name-overload. TEST: an intro `connection==='pending'` edge and a `trust==='outbound'` edge render DISTINCTLY — add a derived `trust-sent` bond-state; do NOT reuse `isPending`.
- RENDER-ONLY. The change touches node/edge visual derivation + the single phase→visual map; `livingEdgeStatus` / trust-graph primitives are UNCHANGED (team-owned; Apollo co-verifies the derivation render). A once-mutual-then-revoked edge auto-drops white by construction (its phase flips `reciprocal→false` → render follows).

**LIVE-STATUS**
- `livingEdgeStatus` EXISTS + is pure + fail-closed + SHIPPED; `.trust` already distinguishes outbound/mutual correctly. The bug is render-only — 3 consumers inconsistent (`MasterAddressBookList.chipColor` honest ✓ / `TrustMapGalaxy` node-color over-claims outbound→white ✗ / `ContactManagement` to confirm). Fix = unify all on `livingEdgeStatus.trust`.
- GATES: Apollo co-verifies the derivation render (white IFF mutual) · Archie gates display-honesty · ★ PETER-SEES-IT on-screen = the acceptance gate. (Self-test note: `trust==='mutual'` only flips when reciprocity is genuinely established — a fleet-owned probe — so after the fix a one-way trust correctly STAYS outbound/pending until mutual is real.)

---

## 2. Over-wire SEND / INBOX UI (render-glass; crypto = call-only, DO NOT reimplement)

**FLOW**
1. COMPOSE/SEND → call `sendNoteToPeer({ sender, senderPublicKeyArmored, senderPrivateKeyArmored, passphrase, senderPqKemPublicKey, senderPqSigPublicKey, peerFingerprint, peerPublicKeyArmored, body, threadId? })` (`src/lib/messaging/transport.ts`) → `{ note_id, thread_id, deposited }`. Render the sent note as **"Sent · unconfirmed."**
2. RECEIVE (ALREADY WIRED — do NOT re-implement) → the app-shell's `startLiveBookPolling` (`src/lib/sync/live-book-poll.ts`) now routes inbound notes through the merged note-aware consume → `acceptInboundNote` persists them to the notes store. The INBOX UI just READS the store (`listThreads()` + note records, `src/lib/messaging/store.ts`) and repaints when the `emitNote` / contact-events seam fires.
3. READ THREAD → `listThreads()` + note records (encrypted-at-rest; unlock = the vault passphrase, already loaded in session).
4. YOUR SENT ITEMS → the local outbound `NoteRecord`s (body readable to you; stored by `sendNoteToPeer`).

**INVARIANTS + TEST-ANCHORS**
- ★ Senders MUST be CANONICAL-minted identities — the relay rejects classical 40-hex (res1 gate). Your UI's identities must be canonical.
- ★ STATUS = **"Sent · unconfirmed" ONLY**. NO "Delivered"/"Read"/"Expired". There is NO sender-side delivery-status query on the blind dumb mailbox (`/api/relay/msg/status` does NOT exist there — that is the keystone smart-mailbox path; do NOT poll it). Delivery-receipts = post-beta, not built.
- RECEIVE = persisted (no-silent-loss): a note is delivered-or-held, never lost. A non-contact / unsigned / forged note is DROPPED SILENTLY; the sender is NEVER told they're not admitted (anti-harassment; admit-status hidden — sender sees only "unconfirmed").
- CRYPTO = CALL-ONLY: `sendNoteToPeer` / `acceptInboundNote` / `noteOpenpgpDecryptor` are imported + called, NEVER reimplemented. (Flint signs the crypto-call surface at review.)

**LIVE-STATUS**
- SEND: proven (DAG-A round-trip + forgery-reject + confidentiality). RECEIVE: merged + co-verified GREEN (PR#212), persists on arrival. Live-inbox-repaint: the `emitNote` seam exists — wire the repaint-on-arrival. Use the honest copy strings from task #3 for all surfaced text.

---

## 3. Beta-messaging UI copy (BETA surface only — NOT the public README)

> Verbatim copy for the beta-surface screens. The README stays messaging-free. ★ The Unlock/redeem screen (below) renders ONLY when the beta gate is ON (issuer provisioned) — NOT in the gate-OFF dogfood gap. Every line is scoped to co-verified built-state; do not add a capability claim beyond these.

**Unlock screen (access-token redeem) — gate-ON only:**
- Heading: **"Turn on beta messaging"**
- Body: "Messaging is in beta. Redeem your access key to turn it on for this address book — one key per book."  · Button: `[ Redeem key ]`
- microcopy: "Your key unlocks messaging for you. It doesn't change what anyone else can do."

**What it is:** **"Encrypted messages, with the people you trust"** — "Send and receive end-to-end encrypted messages with your contacts. Every message is sealed on your device — the relay only ever moves sealed blobs, and never learns who you talk to."

**Sending:** "When you send, you'll see **Sent** — your message left your device sealed and reached the relay. (A **Delivered** confirmation is coming.)"  · *If recipient hasn't joined beta:* "your message waits for them. The moment they join and unlock their book, it delivers. A message to someone who never joins will eventually expire."

**Receiving:** "You receive messages from your **contacts**. A message arrives sealed and is saved to this device — if it doesn't appear in your inbox live yet, it's there when you open your messages. (Live inbox updates are coming.)"

**The quiet edges — copy MUST NEVER imply otherwise (test-anchored honesty):**
- A message from a non-contact is dropped. NEVER tell them why or whether you're reachable — they only ever see "unconfirmed." NO "you're not allowed" surface; NO reachability/admit-status oracle.
- **Sent** is the honest floor. NO "Delivered"/"Read"/"Expired" notifications yet (coming, only once they provably can't leak who-read-when).
- Turning on messaging unlocks YOUR ability to receive. It is NOT a revoke/block control.
- Expiry: copy may say "will expire" (general) + "delivers retroactively when they join"; NEVER "you'll be notified it expired" / "no message ever lost."

**INVARIANTS + TEST-ANCHORS:** send-status UI never renders Delivered/Read/Expired · receive-copy says "saved / there when you open" never "appears live" · no string leaks admit-status · redeem screen renders ONLY gate-ON · unclaimed ≠ unreachable (deposits buffer).

---

*Queue gate-owners (Archie's Cursor-inbox SOP): Archie gates each item (claim-honesty + no-item-without-a-blueprint); Apollo co-verifies the trust derivation render + the crypto-call surface; Flint signs any crypto surface; the trust-visual item needs PETER-SEES-IT; Athena pushes + QA + merges. Cursor renders to-spec ONLY — reads `livingEdgeStatus`, calls the crypto, never changes either.*
