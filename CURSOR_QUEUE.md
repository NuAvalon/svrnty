# svrnty × Cursor — Build Coordination Queue

**Owner/maintainer:** Archie (advances the queue on merge). **Authored:** 2026-08-29 (⚡9025), to Peter's #123098.
**Companion to:** `svrnty_launch_features_v1.md` (§ CURSOR OUTSOURCING — the strategic what/why + boundary) and the DAG `svrnty_9-10_sprint_dag_v2.md`. THIS doc = the tactical execution queue Cursor works off of.

> **Placement note:** for Cursor to actually check boxes, this file should live in the **svrnty repo root** (Cursor's working tree — e.g. `CURSOR_QUEUE.md`). This copy in `products/` is the canonical draft; Athena/Peter drop it into the svrnty repo (their lane). Archie maintains the content + advances it on each merge.

---

## The loop (how this coordinates)
1. **Cursor** picks the top UNCHECKED, UNBLOCKED task in the QUEUE.
2. Builds it to the **spec-ref**; opens a PR; ticks its **PR** box + links the PR#.
3. **Fleet verifies** the PR against the task's **keep-in-fleet seam** (owner listed) + the **constitution axis** (Archie): binary-edge, deniability/constant-time, recompute-never-transmit.
4. On **merge** → mark ✅ DONE + PR#; Archie advances the queue; the next task unblocks.

## 🚫 HARD BOUNDARY (render-glass — never crosses to Cursor)
Cursor renders **UI to our specs only**. It NEVER touches: `visible()`/`reach()` gate-logic, the constant-time crown acceptance criterion, PSI/graph compute, or **any crypto**. Those are fleet-only (owners flagged per task). Cursor accelerates the UI; the fleet gates the leak-preventer.

---

## ✅ MERGED — PR#57 (merged to main 2026-08-29T21:30Z)
- [x] **PR#57** — Solar Ember UI: identity card + Trust Map clusters + seals + light mode + `chimeric ambient` home. **State: ✅ MERGED to main (merge commit `37a39eb`).** Solar Ember L8 UI is now on main. Constitution axis verified on the branch (Archie ⚡9031, seal re-verify ⚡9033); binary-edge (`trusted`=boolean) + seal-recompute-never-transmit held. NOTE: prod-deploy of main (svrnty.is) is a separate Peter-gated step.
  - **none-inferred fix: ✅ DONE** — landed on main AFTER the merge (commit `e227087`, authored Athena via gh): restored the consent guarantee on the POPULATED TrustMap legend (:522) → "Every visible line consented — none inferred." (Hypatia wording · Apollo verified · 3× independent verify).

## ★ DO FIRST — RECOVERY-SCREEN COPY FIX (launch-blocker · READY · pure copy/UI, NO crypto)

**Why:** On the "Restore your .svrnty" screen users are asked for BOTH a password and a recovery phrase with no explanation → reads as "why do I need both?" (real confusion Peter hit). The fix is to HONESTLY EXPLAIN the existing by-design 2FA. This is **COPY + conditional rendering ONLY** — crypto and file format are unchanged. Converged: Flint (spec/GO) · Hypatia (copy) · Athena (push).

**Seam:** PURE frontend. NO crypto, NO format change. The restore handler ALREADY format-detects (contacts-only `.svrnty` vs full-identity vault) — branch the copy on that existing detection.

**★ CLAIM-HONESTY GUARDRAILS (load-bearing — do NOT violate):**
1. This explains the EXISTING by-design 2FA. It does NOT add or promise a seed-only "lost your password" recovery path. Do NOT put "lost your password? recover with seed" on this screen.
2. NEVER offer seed-recovery as a way around a lost password on the current (v3) backup format — it does not work; falsely offering it strands a user who trusted it (safety over-claim).

### CASE A — Contacts backup (`.svrnty`, no identity vault)
- Heading: **"Restore your contacts"**
- Field: **"Password"**  (sub: "The password you set when you exported this file.")
- Button: **"Restore contacts"**
- [no seed field, no seed mention]

### CASE B — Full identity backup (`.svrnty` with recovery vault)
- Heading: **"Restore your identity"**
- ★ Intro (THE FIX): **"This is a full identity backup, protected by two factors — both are required:"**
- Field 1: **"Password"**  (sub: "Unlocks the backup file.")
- Field 2: **"Recovery phrase — 12 words"**  (sub: "Opens your identity's recovery vault.")
- Helper: **"Both factors are required to restore your full identity — this is by design."**
- Button: **"Restore identity"**

### ERROR states (honest — no false promises)
- Wrong password: **"Incorrect password. This backup requires your password to restore."**  [do NOT offer seed-only recovery — not available on this format]
- Wrong/invalid phrase (Case B): **"That recovery phrase doesn't match this backup."**

**PR:** ☐  ·  **Verify:** Hypatia (copy/claim-honesty) · Flint (matches crypto model) · Athena (frontend/merge)

> **SEPARATE future task — do NOT build yet:** a true seed-ONLY "lost your passphrase" recovery path. GATED on Flint's v4 dual-envelope format change (moves the recovery vault outside the passphrase layer). It will be queued when the format lands. Until then, no screen may promise seed-only recovery.

---

## 🟢 QUEUE — P0 CORE (priority order)
| # | Task | Spec-ref | Keep-in-fleet seam (owner) | PR |
|---|------|----------|----------------------------|----|
| CUR-1 | **L1 send/update contact-method UI** (P0.1) — update-send flow + shared-with propagation surface | launch-plan L1a/L1b | per-peer-encrypt (Flint) | ☐ [#59](https://github.com/NuAvalon/svrnty/pull/59) |
| CUR-2 | **L1c version-control UI** (P0.2) — one-tap revert/restore-previous + version-history view | launch-plan L1c | signed monotonic revisions (Flint) | ☐ |
| CUR-3 | **L1g deep-linked contact methods** — tap-to-open (wa.me/tel:/signal.me/mailto:) | launch-plan L1g | none — PURE frontend, zero crypto | ☐ |
| CUR-4 | **L4 import/export UI polish + export-behind-auth prompt** (P0.5) | launch-plan L4 | key crypto (Flint) | ☐ |
| CUR-5 | **L3 trust/untrust/remove/block UI + confirm flows** | launch-plan L3 | relay-auth calls (Flint/Athena) | ☐ |

## 🔵 FAST-FOLLOW (after P0 core lands)
| # | Task | Keep-in-fleet seam (owner) | PR |
|---|------|----------------------------|----|
| CUR-6 | **L5 biometric-unlock UX** (WebAuthn passkey flow) | PRF crypto seam (Flint) | ☐ |
| CUR-7 | **P0.5 app-lock screen** (Signal-model lock/unlock UX) | PRF / wrapping-key unwrap (Flint) | ☐ |
| CUR-8 | **L6 tag-management UI** (create/edit/assign tags) | tags stay client-only, STRIPPED on the wire (Apollo §2) | ☐ |
| CUR-9 | **L8 recovery-ceremony collect-back UX** (gather shards → reconstruct) | Shamir/recovery crypto (Flint) | ☐ |
| CUR-10 | **reach-settings UI** (private/L1/L2 disclosure toggle) | `visible()`/`reach()` gate-logic (Apollo) — UI chrome ONLY; KB#87355 = the UI-half contract | ☐ |
| CUR-11 | **about-page** | copy source (Hypatia) → Cursor renders | ☐ |

---
**Verify roster:** Archie = constitution/architecture axis on every PR · Apollo = disclosure-reach gate + strip-tags-on-wire · Flint = crypto/relay-auth · Athena = frontend quality + deploy/CI · Hypatia = copy/claim-honesty. **Advance rule:** a task is DONE only when merged + its seam-owner has signed. No gate-correctness traded for a checkbox.
