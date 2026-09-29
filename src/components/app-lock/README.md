# App lock (CUR-7 · P0.5) — render-glass

**Queue:** `CURSOR_QUEUE.md` CUR-7 · **Seam owner:** Flint (PRF / wrapping-key unwrap)  
**Aesthetic:** Solar Ember · **Hard boundary:** no PRF, no wrap material, no session-key derivation in this folder.

## What shipped
- **Lock Now** — header control when an encrypted identity is unlocked (`app/page.tsx`). Calls fleet `lockSession()`, clears React identity/contacts state, returns to the existing passphrase gate.
- **Idle auto-lock** — optional 1 / 5 / 15 / 30 / 60 min (default **Off**). Activity listeners reset the timer.
- **Lock when leaving tab** — optional `visibilitychange` / `pagehide` (Signal-model).
- **Settings** — `AppLockSettingsPanel` under identity tools.
- Prefs in `localStorage` key `svrnty.app-lock` — **UI intent only**, never keys.

## Hard boundary held
- Lock path = `lockSession()` (fleet, already on main). Unlock path unchanged = `initSessionKey(passphrase)` + `loadKey`.
- No WebAuthn / PRF / KDF in this folder. Biometric re-unlock is CUR-6 (`biometric-seam.ts`); this PR does **not** claim Face ID unlocks after idle lock.
- Copy: "lock clears keys from this tab's memory" — true via `_sessionKey = null`. No server claim.

## Files
| File | Role |
|------|------|
| `app-lock-prefs.ts` | Prefs parse/read/write + status copy |
| `app-lock-prefs.test.ts` | Prefs + claim-honest copy tests |
| `useAppLock.ts` | Idle + visibility hooks |
| `LockNowButton.tsx` | Header CTA |
| `AppLockSettingsPanel.tsx` | Settings chrome |
| Wired from `app/page.tsx`, `SoverentityFrontend.tsx` | |

## Assumptions
- App-lock only applies when `hasEncryptedKeys` — plaintext/legacy vaults have nothing meaningful to clear from a wrap.
- Defaults are **opt-in** (idle Off, lock-on-hide Off) so demos aren't surprising; Lock Now is always available when eligible.
- Prefs are **device-local**, not per-identity (same as appearance). If fleet wants per-fingerprint prefs, say so — glass can key by fingerprint without crypto.

## Questions for the fleet (answer in the PR description / merge notes — not drive-by invent)
See PR body — Flint (PRF after idle), Hypatia (copy), Athena (placement), Archie (no presence leak from lock timing).

## Verify
```bash
npx tsx --test src/components/app-lock/app-lock-prefs.test.ts
```
