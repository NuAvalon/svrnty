# svrnty — frontend build queue

Work top-down: the top task first, then the next. Build UI to spec (**render-glass**). Open **ONE PR per task**. Copy that makes a security / recovery / trust **CLAIM** needs review before merge — do **not** self-merge crypto/claim surfaces. See `.cursor/rules`.

## 1. §5 FIX — beat-4 live-update repaint (demo-arc.spec.ts:133) — EMPIRICAL-REPRO-FIRST, on the §5 branch (PR #105)

The §5 PR (#105, branch `cursor/section5-identity-auth`) has ONE red e2e beat: `demo-arc.spec.ts:133` — "beat 4: Bob edits his card → Alice's entry self-updates LIVE (no reload)". main is GREEN on this beat → §5 introduced the regression. Build passes; only the live-repaint e2e fails.

**THE FAILURE (from CI @ the PR head):** assertion at :155 — `getByTestId('contact-row').filter({ hasText: 'Bob (NEW name)' })` → **"element(s) not found"**. Alice's view NEVER renders Bob's NEW name → the legit live-update does NOT propagate/repaint. The beat-4 NEGATIVE (a garbage deposit does not repaint) PASSES — only the legit repaint is broken. The receive chain (decrypt→verify→apply→persist) has been verified correct → the break is the emit→repaint layer (live-book-poll → contact-change emit → ContactManagement subscription → the row's `data-live="push"`).

**LOCALIZATION (git-proven, not a hypothesis):** §5 = main + exactly 1 commit. On the ENTIRE beat-4 path, the only change is `src/components/ContactManagement.tsx` **+19/-0** = a new `startKnowLayerSync` useEffect (~L293-311) + its import. live-book-poll / consume-mailbox / contact-events are byte-identical to green-main. So the ONLY new runtime actor on this path is that effect. The mechanism is RUNTIME-only (next-dev/StrictMode) — invisible to static reading; it must be pinned by RUNS, not guessed.

**DO THIS — empirical-first, DO NOT patch on a guess:**
1. **CAUSATION TEST (definitive):** comment out the `startKnowLayerSync` useEffect (ContactManagement.tsx ~L293-311) → run beat-4 → does it go GREEN? If yes, the +19 lines are causal (expected).
2. **MECHANISM CAPTURE (effect enabled):** run beat-4 and capture — console errors / `pageerror` / `unhandledrejection`? Is the next-dev ERROR OVERLAY covering the DOM (would explain "element not found")? Does the poll tick — is the OLD 'Bob' row present (poll runs, no repaint) or NO Bob row at all (poll never runs)? What is the `/api/satellite/bind` network status in the trace? (Note: in e2e there is no satellite → bind returns a clean 502+JSON → buildPsiSyncOptions returns null → startKnowLayerSync never actually starts; so the break is a side-effect of the fail-closed effect itself, not the sync.)
3. **FIX the pinned mechanism, minimal.** Likely shape (confirm from the capture, don't assume): gate the effect so it doesn't fire the doomed bind in the demo / defer it off the poll's first-tick path — do NOT touch the repaint/poll code or the identity/crypto core.
4. **PROVE beat-4 e2e GREEN on a real run** before considering it done. Trusted ONLY when the e2e beat passes on a real run — never a static "should-work" patch. Attach the causation-test + capture results to the PR so the core team can byte-confirm the fix.

Also fold in this separate hardening: `app/api/satellite/trust/psi/[...path]/route.ts:24` `await request.json()` sits BEFORE its try at :32 → wrap it fail-closed (empty/invalid body → 400, never throw). (bind/register already guard this.)

Open the fix on this branch (update PR #105) if possible; otherwise a fix PR the core team folds into #105. The standing crypto/identity co-verify still gates merge.

---
*Queue updated 2026-09-05.*
*#1 = §5 beat-4 repaint fix — EMPIRICAL-REPRO-FIRST. The receive chain is verified; the break is the UI-repaint layer. No fix trusted without beat-4 e2e GREEN on a real run.*
*Prior: §5 identity refactor built as PR #105 (draft, co-verify in progress).*
