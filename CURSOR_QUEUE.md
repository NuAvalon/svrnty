# svrnty × Cursor — Build Coordination Queue

---
## ★ CURRENT STATE — 2026-08-30 (Athena status-sync; content roadmap owned by the fleet maintainer)

**Landed since this queue was last advanced:** the P0 launch batch (send UI, version-history, deep-links, recovery-code recovery, export-behind-auth, trust-confirms) plus the **Living Address Book** work — PR #82 (phone-book vCard with tags / fingerprint / trust stripped by construction; "Link to SVRNTY") and PR #83 (derive-and-match fingerprint↔key binding + keyless-classical fixture). #82 is in **staging QA on dev.svrnty.is**; merge to main is Peter-gated on that QA.

**On deck (fleet-ruled — unblocks after #82 merges to main):**
- **Own-identity `.vcf` export** ("Save contact card" on the identity card) — this PR (post-#82 fast-follow; book-strip already on main via #82, not repeated). Prior draft #77 can close as superseded.
- **Private tag-management CRUD** — carried in PR #68. Rebase onto post-#82 main, reconcile the ContactManagement / vcard overlap, re-review.

**Boundaries still in force:** the gap-freeze rules (`.cursor/rules/svrnty-gap-freeze.mdc`) — no crypto, vault, identity, PSI, signing, or trust-sync changes. Render-glass to spec only.

**Next NEW-feature batch:** added by the fleet roadmap maintainer — this entry reflects current state so Cursor and Peter work from an accurate picture.

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
- ⚠️ **SUPERSEDED (2026-08-30) — do NOT implement "both required".** Crypto ground-truth (Flint's matrix): the FILE is always required; PASSWORD and RECOVERY CODE are ALTERNATIVE keys (password OR code, never both). Password ALONE opens a v4 backup fully. This block's PR (#60) was CLOSED as superseded; the honest model shipped in #65. Correct copy below:
- ★ Intro: **"Two ways to restore — both need your backup file:"**
- Case A (has password): **"Password + backup file → everything (identity, contacts, and trust)."**
- Case B (lost password): **"Recovery code + backup file → your identity only (no contacts; reconnect those)."**
- Field: **"Recovery code"** (8 groups of 8 hex chars — NOT "12 words"; BIP39-24 is a separate follow-on)
- Button: **"Restore identity"**

### ERROR states (honest — no false promises)
- Wrong password: **"Incorrect password. This backup requires your password to restore."**  [do NOT offer seed-only recovery — not available on this format]
- Wrong/invalid phrase (Case B): **"That recovery phrase doesn't match this backup."**

**PR:** ☐  ·  **Verify:** Hypatia (copy/claim-honesty) · Flint (matches crypto model) · Athena (frontend/merge)

> The seed-only "lost your passphrase" recovery path is now its own **DO-SECOND** task below — Flint's v4 dual-envelope merged (4df1be429), so it's buildable and TRUE on v4 (no longer a false promise).

---

## ★ DO SECOND — SEED-ONLY RECOVERY ("Lost your passphrase?") — now BUILDABLE (v4 merged 4df1be429)

**Status:** UNBLOCKED. The v4 dual-envelope format merged to main (#61) — `extractRecoveryVault(data)` now reads the recovery vault passphrase-free, so seed-only recovery is architecturally TRUE (it was a false promise on v3). Converged: Flint (v4 crypto + seam) · Hypatia (copy) · Athena (push).

**Seam (Flint — 2 calls, NO crypto in the UI):**
```
const kv = extractRecoveryVault(data);   // no passphrase needed (v4)
await recoverFromSeedPhrase(kv, phrase); // 12-word phrase → identity
// guardian-shard variant: recoverFromShards(kv, shards)
```

**★ FORMAT-DETECT = the honest gate (do NOT skip):** detect v3 vs v4 backup. The seed-only path shows ONLY for v4. See the v3-guard below.

### RESTORE — "Lost your passphrase?" path (v4 backups only)
- Entry (alongside the passphrase path): **[Lost your passphrase?]** → "Recover with your seed phrase"
- Screen — Heading: **"Recover with your seed phrase"**
  - Body: **"Enter your 12-word recovery phrase to unlock this backup — it works without your passphrase."**
  - Field: **"Recovery phrase (12 words)"** · Button: **"Recover my identity"**
  - ⚠️ CLAIM-HONESTY (Flint co-verify): recovery needs the phrase AND this backup FILE — the phrase DECRYPTS the file (replacing your passphrase); it does NOT reconstruct identity from nothing. Do NOT imply "phrase alone / no file needed."
- Guardian shards (v4, if in scope): **[Recover with guardian shards]** → "Enter recovery shares from your guardians (**{threshold}** of **{total_shares}** needed)." — bind numbers to `kv.shamir.threshold` (needed) and `.total_shares` (total) IN THAT ORDER (never "5 of 3").

### ★ v3-backup GUARD (critical — the honest gate)
- Detection: `readVaultHeader(data).version` returns `3 | 4`. If v3 (pre-v4): do NOT show the seed-only path. Show: **"This backup was created before passphrase-free recovery. It can be restored only with your passphrase."** + if device access remains: **"Re-export your identity to enable seed-phrase recovery."**
- NEVER offer seed-only recovery on v3 (can't work = the false promise we guard against).
- Fail-safe (Flint): even if the UI-gate is bypassed, `extractRecoveryVault` HARD-REFUSES a v3 file with an actionable "re-export" throw — the crypto refuses too. Belt + suspenders.

### GENESIS re-verify (seed-reveal at identity creation — now TRUE on v4)
- **"Your 12-word recovery phrase. Write it down and keep it somewhere safe you'll still have if you lose your passphrase. If you lose your passphrase, the phrase unlocks your backup without it. Shown once — this is NOT your everyday passphrase."**  (Do NOT promise standalone device-loss recovery — lose device AND backup file = not recoverable; that backstop is a separate follow-on.)
- CO-LOCATION DIAL (Peter/team choice — NOT defaulted): the recovery model (file+phrase, no passphrase) means file+phrase together = full access. The neutral genesis phrasing above ships either way. If an active "don't store your phrase next to your backup file" warning is wanted, it's a one-line add — Peter's call.

### MIGRATION NUDGE (v3 users — Do-No-Harm, prompt BEFORE a loss event)
- **"Update your backup to enable passphrase-free recovery"** → prompts re-export to v4.

### HONEST ERRORS
- Invalid phrase: **"That recovery phrase doesn't match an identity."** (no false success)

### POST-SUCCESS INTERSTITIAL (contacts-honesty — UNMISSABLE; team-FINAL: Flint crypto-GREEN + Hypatia claim-honesty-final)
Show AFTER a successful seed-only restore — the inline pre-success line is missable; THIS is the moment the user learns contacts aren't back:
- Heading: **"Your identity is back."**
- Body: **"Your keys and identity are recovered. Your contacts and trust connections weren't restored — they were sealed with the passphrase you lost, and your recovery phrase can't unlock them. You'll rebuild your connections as you reconnect with people."**
- Button: **"Continue"**
- Honest via SCOPE-TO-FLOW: "the passphrase you lost / your recovery phrase can't unlock them" = this-flow limit, NOT an absolute forever-gone claim (a user with a remembered passphrase wouldn't be on this seed path). No phantom seed-restore (Flint crypto-confirmed), no false-despair (scope-to-flow), and NO CTA — a "restore from another backup" link confuses the common lost-passphrase case + is a separate flow (team-reconciled to no-CTA, Hypatia #123876).

### POST-QUANTUM keys (follow-on — NOT a merge blocker; Flint's lane)
- seedVaultRestore returning PQ SECRETS only is CORRECT (publics are derivable: ML-KEM-1024 pk is embedded in the sk; ML-DSA-87 pk recomputes from the sk). Do NOT invent a PQ layout in the UI — flag, don't build (render-glass ✓).
- CLAIM-HONESTY until Flint wires `reconstitutePQPublicKeys`: the recovered identity has working PQ SECRETS + classical identity — do NOT claim "post-quantum identity fully restored." A one-line note ("post-quantum keys re-derive on next card publish") keeps it honest.

**PR:** [#65](https://github.com/NuAvalon/svrnty/pull/65) · **Verify:** Flint (strings match extractRecoveryVault/recoverFromSeedPhrase + v3-guard on real format detection · PQ-reconstitution follow-on) · Hypatia (copy/claim-honesty · interstitial) · Athena (frontend/merge)

---

## 🟢 QUEUE — P0 CORE (priority order)
| # | Task | Spec-ref | Keep-in-fleet seam (owner) | PR |
|---|------|----------|----------------------------|----|
| CUR-1 | **L1 send/update contact-method UI** (P0.1) — update-send flow + shared-with propagation surface | launch-plan L1a/L1b | per-peer-encrypt (Flint) | ✅ [#59](https://github.com/NuAvalon/svrnty/pull/59) |
| CUR-2 | **L1c version-control UI** (P0.2) — one-tap revert/restore-previous + version-history view | launch-plan L1c | signed monotonic revisions (Flint) | ✅ [#64](https://github.com/NuAvalon/svrnty/pull/64) |
| CUR-3 | **L1g deep-linked contact methods** — tap-to-open (wa.me/tel:/signal.me/mailto:) | launch-plan L1g | none — PURE frontend, zero crypto | ✅ [#63](https://github.com/NuAvalon/svrnty/pull/63) |
| CUR-4 | **L4 import/export UI polish + export-behind-auth prompt** (P0.5) | launch-plan L4 | key crypto (Flint) | ☐ [#66](https://github.com/NuAvalon/svrnty/pull/66) |
| CUR-5 | **L3 trust/untrust/remove/block UI + confirm flows** | launch-plan L3 | relay-auth calls (Flint/Athena) | ✅ [#67](https://github.com/NuAvalon/svrnty/pull/67) |

## ▶ GAP BUILD PRIORITY (fleet away ~4-5 days — build safe UI in this order; crypto/claim FROZEN, see `.cursor/rules/svrnty-gap-freeze.mdc`)

**P0 CORE = DONE** (#59 / #64 / #65 / #67 / #63 / #66 merged; #60 closed as superseded by #65). Recovery-code term-consistency fix landed on main. Build these next, safest render-glass first:

1. **about-page** (#72) — pure render, Hypatia copy. Safest.
2. **tag-management** (#68) — ⚠️ tags / blocked / group-labels are **device-local**: NEVER serialize on any **publish / PSI-sync / export** payload; assert with a **negative test** (Apollo, KB#87571).
3. **VCF export** — user's own data → native `.vcf` (this PR; book phone-book strip already landed in #82).
4. **app-lock screen** (#70).
5. **biometric unlock** (#69) — WebAuthn UI **flow only**; the PRF crypto seam is fleet-owned (do NOT touch during the gap).
6. ⛔ **reach-settings** (#71) — **DEFER to fleet-return.** Render toggles are fine, but disclosure-reach LOGIC + DEFAULTS are fleet-owned (Hypatia's contract) — Cursor must NOT decide or ship what's exposed.

Any crypto / recovery / trust-CLAIM change → HOLD for agent review on return (no auto-merge while we're dark).

---

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
