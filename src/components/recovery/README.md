# Recovery UI (L8) — Cursor build notes

**Component owner (UI):** Cursor · **Crypto owner:** team (do not modify `src/lib/crypto/recovery.ts`)  
**Brief:** `CURSOR.md` L8 · Aesthetic: Solar Ember

## What we built
| File | Role |
|------|------|
| `EntropyMeter.tsx` | Live strength meter for unlock passphrase / future soul-seed word entry |
| `SoulSeedReveal.tsx` | One-time reveal of the recovery phrase after forge (2nd-factor copy) |
| `IdentitySeal.tsx` | Deterministic fingerprint → SVG seal (I-6; no decorative randomness) |
| `solar-ember.ts` | Shared palette tokens from CURSOR.md |

Wired into `SoverentityFrontend.tsx`: forge passphrase meter, recovery-reveal screen, restore-verify soul-seed field when a KeyVault is present.

## Files touched
- `src/components/recovery/*` (new)
- `src/components/SoverentityFrontend.tsx` (wire-up only)
- `src/components/TrustMap.tsx` + `src/components/TrustMap/README.md` (Solar Ember + note)
- `src/components/identity/IdentitySeal.tsx` (new)

## Assumptions
1. Today’s “seed phrase” from `createKeyVault` is **hex groups** (64 hex chars), not BIP39 words — UI shows that honestly.
2. `recoverFromSeedPhrase(vault, phrase)` is the only allowed recovery crypto call from UI.
3. True “file + phrase both required as 2nd factor” needs exports that **omit plaintext keys** and keep `KeyVault`. Current full-backup often includes keys — passphrase alone unlocks those. UI requires the phrase when `vault` is present and uses it to recover/verify.

## Questions for the team (STOP line — need crypto / product)
1. **User-set 12+ word soul-seed:** CURSOR asks for set-your-own phrase + entropy meter. Crypto today *generates* a random master secret then encodes hex. Deriving master secret from user BIP39 (or similar) is **team-owned**. Please expose an API (e.g. `createKeyVaultFromSoulSeed(phrase, …)`) before we enable a writable set-UI beyond the meter on the unlock passphrase.
2. **2nd-factor export format:** Confirm preferred backup shape = `KeyVault` + contacts + identity **without** `keys`/`pq_keys`, so restore always needs the soul-seed.
3. **Social collect-back UI** — deferred per CURSOR (survivor-safety review).

## Invariants honored
- No crypto reimplementation
- I-6: IdentitySeal is fingerprint-deterministic
- No presence/location UI
