# AGENTS — svrnty

**Build brief → [CURSOR.md](./CURSOR.md). Read it first.**

You accelerate the **UI rendering.** The team owns the security-critical logic and verifies every output. You render the glass; the team holds the locks.

## ⛔ Hard boundary — never modify (call it, don't touch it):
- **crypto** — `recovery.ts` / PSI / message envelope / key-derivation
- **gate-logic** — disclosure-reach enforcement, `visible()` / edge-visibility, plausible-deniability (no fetch-then-hide)
- **relay** — `satellite.py` + server endpoints

If you'd cross this line, **STOP and flag it in a README.** A blocked component is fine; a silently-modified lock is not.

Honor the invariants (**I-3** no-aggregate · **I-4** reachability-not-location · **I-6** render-provenance · **I-7** tamper-evidence · **Invariant-1** fingerprint ≡ H(public_key)) and build to the Solar Ember aesthetic. Full detail, component scope, and coordination-via-READMEs in **[CURSOR.md](./CURSOR.md)**.
