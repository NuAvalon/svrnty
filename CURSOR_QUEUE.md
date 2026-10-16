# svrnty — frontend build queue

Work top-down: the top task first, then the next. Build to spec. Open **ONE PR per task**. Copy/code that makes a security / recovery / trust **CLAIM** needs review before merge — do **not** self-merge crypto/claim surfaces. See `.cursor/rules`.

**Cursor = RENDER-GLASS ONLY** (UI/render). Crypto / keys / PSI / relay-logic / trust-derivation = TEAM (Athena/Flint/Apollo). "You render the glass, the team holds the locks." You CALL the crypto functions and READ the trust derivation named below — you NEVER implement/mutate them. Build items top-down, one PR each.

*Recently completed: Camera QR-scan (#96), Mint-Build Recipe v2 KERI (#112). Over-wire note-fix (PR#212) + beta-access (A) (PR#213) + OPT-2 durable mailbox (PR#248) MERGED to main — the relay hooks are LIVE. These 3 items finish the #225 UI (lens/profile rework). [3] forged-note-gate + [4] beta-tabLabel are APOLLO's, not Cursor's.*

---

## 1. Beat5 Full-Backup reachable via the "More" menu (render-glass; interaction + test only) — ✅ READY

> #225 moved "Full Backup" into the card **"More"** menu (`CardMorePanel` → `CardMenuItem` testId=`full-backup-open`). The beat5 demo-arc flow still expects the old direct path, so it no longer reaches Full Backup.

**FLOW**
1. In the beat5 demo-arc flow, OPEN the `CardMorePanel` "More" menu first, then invoke Full Backup via `CardMenuItem` testId=`full-backup-open`.
2. Fix the interaction so the flow reaches Full Backup through the menu — OR update the beat5 e2e test to open the menu before asserting Full Backup.

**INVARIANTS + TEST-ANCHORS**
- ★ DO NOT touch the vault-export auth flow. The re-auth gate inside `VaultExportDialog` is correct + **fail-closed** (internal to the dialog — NOT a bypass; already co-witnessed). Render/interaction/test ONLY.
- No relay/trust/crypto files (CODEOWNERS never-touch). No new export path.

**LIVE-STATUS**
- Green = the beat5 e2e passes (reaches Full Backup via the More menu). The data/auth path is unchanged; this is a render-glass interaction + test alignment.

---

## 2. Galaxy-card verbs render + fire (render-glass; disclosed edges ONLY) — ✅ READY

> The galaxy-card verbs `galaxy-open-note`, `contact-send-update`, and **"Give a piece"** are not rendering. Their handlers already exist — this is render-glass wiring, call-only.

**FLOW**
1. Render the three galaxy-card verbs (`galaxy-open-note`, `contact-send-update`, "Give a piece") and wire each to its EXISTING handler (import + call; never reimplement the handler).

**INVARIANTS + TEST-ANCHORS**
- ★★ Hypatia #198 legend-doctrine: the galaxy shows **DISCLOSED** relationships ONLY — NO inferred/auto edges. The verbs act on EXPLICIT contacts; rendering them must NEVER surface an edge the user did not disclose. TEST: no inferred-edge render.
- Handlers are team-owned (crypto/trust) — CALL only. No relay/trust-derivation mutation.

**LIVE-STATUS**
- Green = the linked-demo-vaults e2e passes (verbs render + fire their handlers) AND no inferred-edge renders.

---

## 3. Ember / VivreBurn inbound distress paint — no-op gated OFF (render-glass) — ✅ READY

> Flint's ruling: VivreBurn is entangled with the galaxy render — do NOT gut it. Gate the INBOUND distress paint OFF (no-op) so it does not render.

**FLOW**
1. No-op-gate the inbound distress / VivreBurn paint so it does NOT render. The galaxy renders normally without it (remove only the paint, not the galaxy).

**INVARIANTS + TEST-ANCHORS**
- ★ DO NOT gut the galaxy (VivreBurn is entangled) — gate the PAINT only.
- ★ Survivor-safety (Flint): the distress emit-path is NOT wired. Painting a distress signal now = a FALSE life-safety claim. Re-enable is a **Flint-reviewed future flip**, only when the emit-path wires AND the paint reflects a REAL received signal — never a placeholder.
- Render-glass only; no distress/trust logic changes.

**LIVE-STATUS**
- Green = the galaxy renders with no distress paint on sample marks. Re-enable deferred (Flint-gated).

---

*Queue gate-owners (Archie's Cursor-inbox SOP): Archie gates each item (claim-honesty + no-item-without-a-blueprint); Apollo co-verifies any trust-derivation/crypto-call render; Flint signs any crypto/survivor-safety surface (item 3 re-enable); Athena pushes + QA + merges. Cursor renders to-spec ONLY — reads the derivations, calls the handlers, never changes either.*
