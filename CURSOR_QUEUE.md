# svrnty — frontend build queue

Work top-down: the top task first, then the next. Build to spec. Open **ONE PR per task**. Copy/code that makes a security / recovery / trust **CLAIM** needs review before merge — do **not** self-merge crypto/claim surfaces. See `.cursor/rules`.

**Cursor = RENDER-GLASS ONLY** (UI/render). Crypto / keys / PSI / relay-logic / trust-derivation = TEAM (Athena/Flint/Apollo). "You render the glass, the team holds the locks." You CALL the crypto functions and READ the trust derivation named below — you NEVER implement/mutate them. Build items top-down, one PR each.

*Recently completed: Camera QR-scan (#96), Mint-Build Recipe v2 KERI (#112). Over-wire receive note-fix (PR#212) + beta-access (A) (PR#213) MERGED to main — the hooks below are now LIVE.*

---

## 1. Over-wire SEND / INBOX UI (render-glass; crypto = call-only, DO NOT reimplement)

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

## 2. Beta-messaging UI copy (BETA surface only — NOT the public README)

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