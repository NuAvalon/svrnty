# svrnty — frontend build queue

Work top-down: the top task first, then the next. Build UI to spec (**render-glass**) — the crypto / gate / PSI / trust plumbing lives behind stable hooks maintained by the core team; **wire the UI to those hooks, NEVER modify them**. Open **ONE PR per task** into the canonical branch. Copy that makes a security / recovery / trust **CLAIM** needs agent review before merge — open the PR, do **not** self-merge crypto/claim surfaces. See `.cursor/rules`.

## 1. Biometric device-unlock — make the presentation honest to the seam  [render-glass, honesty fix — THE do-no-harm item]
The WebAuthn/PRF seam is a **STUB**: `isBiometricSeamLive()` returns `false` and `unlockWithBiometric()` returns `stub-not-live`. Today the lock-screen "Unlock with device" button (`BiometricUnlockButton` in `app/page.tsx`, gated by `biometricUnlockVisible`) is shown whenever a platform authenticator is present — so it *looks available*, then only reveals "not live yet" **after** a tap. Make the **pre-tap** presentation honest.
- When `isBiometricSeamLive() === false` (today): do **NOT** present device-unlock as an available/working action. Either **omit** the lock-screen button, or render a clearly-inactive **"Device unlock — coming soon"** affordance (non-interactive, visibly not-yet). Passphrase entry stays the primary, obvious path.
- Mirror the same honesty in `BiometricSettingsPanel` — if it offers *enroll* while the seam is not live, enroll reads "coming soon"/disabled, never "on".
- Keep the existing on-tap fallback ("Device unlock is not live yet. Enter your passphrase…") as a safety net — this task fixes the pre-tap *look*, not that.
- **DO NOT TOUCH**: `src/components/biometric/biometric-seam.ts` (the crypto seam — enroll/unlock/probe bodies, owned by the core team), the passphrase unlock path, or any recovery/restore control flow. Presentation only. Flipping to "live" happens later, in a separate PR, when the PRF seam is wired.
- Goal: a user **never** sees biometric unlock presented as working while the seam is a stub. Honest "coming", never fake-ready.

## 2. Collapsible top-nav for mobile  [render-glass, layout]
On narrow / phone widths the top header (`app/page.tsx`, the `<header>` around line 527 — wordmark + `AppearanceToggle` + Grow / Join / Recovery buttons) overflows the frame: the user has to scroll **horizontally and vertically**. Collapse the **ACTION buttons** into a compact menu (hamburger / overflow) at phone widths so the header fits with no horizontal scroll and minimal vertical.
- **KEEP the "SVRNTY.IS YOURS" wordmark visible at all widths** (the brand, shipped #100). Collapse the ACTION buttons, not the wordmark.
- **Do NOT bury safety-critical actions**: unlock / recovery / Help must stay reachable. A hamburger is fine, but the recovery entry point (`RecoverySheet`) and Help must not be hidden behind ambiguous UI — one obvious tap, clearly labelled.
- **Presentation/layout only.** Do NOT change unlock/recovery **control flow** (which key decrypts what, path-selection). Wire the collapsed menu to the **same existing handlers** (`setGrowOpen`, `setJoinOpen`, `setRecoveryOpen`, `AppearanceToggle`).
- Responsive: full button row at desktop widths, collapsed menu at phone widths (breakpoint is your call). No layout shift / reflow of the wordmark when the menu opens.

---
*Queue advanced 2026-09-05 by Athena (git-push lane).*
*#1 = biometric-honesty label — Archie #129134 ("THE do-no-harm fix"); real PRF wire is a later human-gated PR (Flint seam design: shared/outbox/flint/biometric_prf_seam_design.md).*
*#2 = top-nav collapse — Peter #129066 live mobile QA; Archie flags: keep wordmark, don't bury unlock/recovery/Help.*
*Not in this queue: Camera QR-scan receive = DONE (#96, needs QA+deploy not Cursor). Real crypto (biometric PRF wire, PSI satellite) = human-gated morning, not render-glass.*
