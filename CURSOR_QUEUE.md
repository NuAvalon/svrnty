# svrnty — frontend build queue

Work top-down: the top task first, then the next. Build to spec. Open **ONE PR per task**. Copy/code that makes a security / recovery / trust **CLAIM** needs review before merge — do **not** self-merge crypto/claim surfaces. See `.cursor/rules`.

*Recently completed: Mint-Build Recipe v2 (KERI authority-key pre-rotation) — merged (#112).*

## 1. PSI mutual-discovery completion tick — TRUST / CRYPTO-ADJACENT · DRAFT PR ONLY · CO-VERIFY GATES MERGE · SHIP BEHIND `isPSIDiscoveryLive()` = false

**Orchestration only — you are wiring EXISTING crypto, not writing any.** The PSI crypto substrate is frozen, team-owned, and already verified: the PSI primitives, the satellite `/trust/psi/*` endpoints, and the mutual-trust-sync derivation are DONE and correct — **do not re-touch, reimplement, or modify them.** This task adds the one missing *caller* so an initiated PSI discovery actually completes. 100% client-side (`src/lib/sync` + `src/lib/trust`); **ZERO server / satellite changes.**

### The gap
The know-layer sync tick fires `initiate` (and peers `respond`), but the initiator's **completion** never runs — `completeTrustSync(...)` currently has **zero runtime callers**, so a mutual discovery is started but never finished. The tick captures `syncMutualTrust`'s return today and discards it.

### Build EXACTLY this (the completion tick), nothing more
In the existing `startKnowLayerSync` 5-minute interval loop, add a completion phase that, for each in-flight initiated PSI session:
1. **Statelessly re-derives** the initiator's ephemeral blinding key `sk_A` and recomputes `fpOrder` (the deterministic sort of the trusted set) — via the **existing** derivation. `sk_A` is a **domain-separated HKDF** of the (already-unlocked) identity secret and the `sessionId` the relay returns; `fpOrder` reconstructs from the local book. **Nothing is persisted.**
2. Polls the relay for the peer's response (result / pending check).
3. If ready: calls the **existing** `completeTrustSync(deps, sessionId, options, keypair, fpOrder)` → computes the intersection → `applyMutualResult(...)` (already fail-closed + tested). Then the session is consumed (nothing to delete — no store).

### DO NOT
- **DO NOT build a client-side `psi_sessions` IndexedDB store, and DO NOT persist any ephemeral keypair.** The stateless re-derive deliberately replaces persistence. (An earlier spec's "persist the session" / "expiry cleanup" parts are **superseded** — do not build them.)
- **DO NOT touch the satellite's `psi_sessions` DB table.** Name collision: that's the relay-side async mailbox — it already exists and is correct. No server / satellite changes at all.
- **DO NOT reimplement the HKDF or any PSI crypto.** Call the existing derivation. **If a callable stateless re-derive helper does not already exist, STOP and flag it in the PR — do not write the key-derivation yourself** (crypto is team-owned; you render the glass, the team holds the locks).

### Ship gated + co-verify
- Ships behind `isPSIDiscoveryLive()` = **false** (do-not-advertise) until end-to-end verified. **Do not flip the flag.**
- **DRAFT PR only — do not self-merge.** A crypto co-reviewer gates merge on: (a) the KDF **domain-separation** (the `info` prefix isolates the PSI ephemeral from any other use of the identity secret), and (b) **sessionId-uniqueness** — the load-bearing rule: **a change to the trusted set MUST force a fresh `initiate` (new sessionId), NEVER a silent re-blind under the old sessionId.** Same-set reuse under a sessionId is safe (retries); different-set under the same sessionId leaks the intersection.

### Files & handoff
`src/lib/sync/*` (the tick loop) calling into `src/lib/trust/*` (existing `completeTrustSync` / `applyMutualResult`). Coordinate back via a README in the PR: what you wired, files touched, and **whether the stateless re-derive helper already existed or needs the team to provide it.**
