# svrnty — frontend build queue

Work top-down: the top task first, then the next. Build to spec. Open **ONE PR per task**. Copy/code that makes a security / recovery / trust **CLAIM** needs review before merge — do **not** self-merge crypto/claim surfaces. See `.cursor/rules`.

**Cursor = RENDER-GLASS ONLY** (UI/render). Crypto / keys / PSI / relay-logic / migration-logic = TEAM (Athena/Flint/Apollo). "You render the glass, the team holds the locks." Build ✅ items top-down, one PR each. ⏳ items at the bottom are NOT actionable until their spec lands — do not start them (a missing spec would be confabulated).

*Recently completed: Mint-Build Recipe v2 (KERI authority-key pre-rotation) — merged (#112).*

## 1. Card / lens UI — ✅ READY · spec: card-datamodel-orch · Peter #133587

BUILD (render-glass):
- **Custom-fields UI** — add/edit arbitrary typed fields on a card. ADDITIVE: rides the existing ContactRecord open index-sig, NO schema change, no migration.
- **Card studio** — compose/preview a card (name + selected fields/methods).
- **Receiver-local annotations** — owner-local alias/notes/tags on a received contact; local-only, PRESERVED across sender card-updates.
- **Per-method relay field** — show/edit the relay serving each method.
- **Move/switch-relay control** — UI to change a method's relay (calls the team's relay-update logic).
- **Default-lens picker** — choose which projection to send at Grow (basic; Hypatia refines context-defaults + copy).
SPEC: shared/outbox/archie/svrnty_card_datamodel_orch.md + Athena storage facts (open index-sig; ~8–16 KB soft cap; avatars referenced, not inlined).
ACCEPTANCE: add a custom field + it persists; card studio previews a card; receiver-notes survive a simulated sender update; relay field editable per method; default-lens selectable at Grow.
BOUNDARY: UI + local storage read/write ONLY. Record encryption = Athena's enc-b seam (fields ride inside the encrypted blob automatically). Lens = consent-by-INCLUSION (a projection you SEND) — NOT client-side hide; never build a "hide locally but still transmit" control. Move-relay resolution/propagation LOGIC = Apollo/Athena; Cursor builds the control that CALLS it.

## 2. Cloud-sync UI shell — ✅ READY · spec: cloud_blob_sync_spec · M9

BUILD (render-glass): connect-a-target UI (Dropbox/iCloud/Google Drive) + backup-status (last backup time, success/fail) + restore-from-backup flow. MINIMAL backup+restore only.
SPEC: products/svrnty_cloud_blob_sync_spec.md.
ACCEPTANCE: connect a target; see backup status; trigger a restore.
BOUNDARY: UI shell only. Encrypted-blob packaging + sync transport = Athena's store/infra. Copy = "backup", NOT "seamless multi-device sync" (full multi-target auto = fast-follow). No inline crypto.

## 3. PSI mutual-discovery completion tick — ⛔ PARKED (blocked on the team PSI-A session-state store) · DRAFT ONLY · behind `isPSIDiscoveryLive()` = false

**STATUS 2026-09-11 (queue owners Athena/Apollo): DO NOT BUILD YET — re-scoped, dependency not landed.**
The fleet settled on **Option A (persist PSI session-state)**. The previous version of this task
described **Option B (statelessly re-derive `sk_A`, persist nothing)** — that is **DEAD / superseded;
do not build it.** Cursor correctly stopped at the crypto boundary (draft PR #120) — that was right.

**Why parked:** the completion tick under Option A reads a *persisted* PSI session-state record
`{sessionId, sk_A, fpOrder}` — a single AES-GCM record on the encryption-b store, fail-closed,
delete-on-complete/expiry. That store is **team-owned crypto (Athena, riding PR #119 encryption-b)**
and **does not exist yet.** Building the tick before it lands would mean guessing at the crypto seam.

**When unblocked** (Athena/Apollo post here once the PSI-A store ships), the tick becomes pure glass:
read the persisted session-state → poll the relay → `completeTrustSync(...)` → `applyMutualResult(...)`
→ delete the record. No key derivation in Cursor (crypto is team-owned; you render the glass).

➡️ **Await the store.** Build the ✅ items above (#1–3) first.

---
⏳ **SPEC-PENDING — DO NOT START** (activated as their specs land while Cursor chews #1–3):
- **Migration / locked-state glass** (gate: Athena migration-doc rewrite) — render migration progress + book-locked-until-passphrase around the enc-b seam.
- **Corruption / book-manifest glass** (gate: Athena HMAC-manifest + Flint corruption spec) — surface drop/corruption detection + recovery prompt (pairs with #3 restore).
- **Self-host relay/node UI** (gate: Apollo client-relay-resolution spec + Hypatia self-host doc) — "add a custom relay/node" input in Grow; honest copy ("svrnty.is is the default relay; your identity isn't locked to it; self-host coming" — NOT "decentralized").

Then: general polish pass to Peter's aesthetic.