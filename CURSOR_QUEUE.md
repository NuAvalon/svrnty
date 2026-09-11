# svrnty — frontend build queue

Work top-down: the top task first, then the next. Build to spec. Open **ONE PR per task**. Copy/code that makes a security / recovery / trust **CLAIM** needs review before merge — do **not** self-merge crypto/claim surfaces. See `.cursor/rules`.

*Recently completed: Mint-Build Recipe v2 (KERI authority-key pre-rotation) — merged (#112).*

## 1. PSI mutual-discovery completion tick — ⛔ PARKED (blocked on the team PSI-A session-state store) · DRAFT ONLY · behind `isPSIDiscoveryLive()` = false

**STATUS 2026-09-11 (Athena, queue owner): DO NOT BUILD YET — re-scoped, dependency not landed.**
The fleet settled on **Option A (persist PSI session-state)**. The previous version of this task
described **Option B (statelessly re-derive `sk_A`, persist nothing)** — that is **DEAD / superseded;
do not build it.** Cursor correctly stopped at the crypto boundary (draft PR #120) — that was right.

**Why parked:** the completion tick under Option A reads a *persisted* PSI session-state record
`{sessionId, sk_A, fpOrder}` — a single AES-GCM record on the encryption-b store, fail-closed,
delete-on-complete/expiry. That store is **team-owned crypto (Athena, riding PR #119 encryption-b)**
and **does not exist yet.** Building the tick before it lands would mean guessing at the crypto seam.

**When unblocked** (Athena posts here once the PSI-A store ships), the tick becomes pure glass:
read the persisted session-state → poll the relay → `completeTrustSync(...)` → `applyMutualResult(...)`
→ delete the record. No key derivation in Cursor (crypto is team-owned; you render the glass).

➡️ **Await the store.** Ready render-glass tasks (distress-removal, card/lens, cloud-sync UI) are being
sequenced onto this queue by the team — build those first as they land above this parked item.
