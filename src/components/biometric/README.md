# Biometric unlock (CUR-6 · L5) — render-glass

**Queue:** `CURSOR_QUEUE.md` CUR-6 · **Seam owner:** Flint (PRF / wrapping-key)  
**Aesthetic:** Solar Ember · **Hard boundary:** no PRF, no key wrap, no `credentials.create` with PRF from UI.

## What shipped
- **Lock screen** — `BiometricUnlockButton` on the passphrase gate (`app/page.tsx`) when a platform authenticator is available.
- **Settings** — `BiometricSettingsPanel` under identity tools (`SoverentityFrontend`) — enable flow asks for passphrase confirm, then calls fleet enroll.
- **Seam module** — `biometric-seam.ts`: capability probe + typed enroll / unlock / disable hooks. **Stubs return `stub-not-live`** until Flint wires PRF → session unwrap.
- Unit tests for stub honesty + claim-honest status lines.

## Hard boundary held
- No crypto / KDF / PRF / session-key derivation in this folder.
- Capability probe uses only `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable` (browser feature detect).
- Enroll preference in `localStorage` is **UI intent only** — never wrap material, never a transmitted seal, never proof of enrollment.
- Copy does **not** claim Face ID unlocks keys while the seam is stubbed; passphrase remains the working unlock.

## Files
| File | Role |
|------|------|
| `biometric-seam.ts` | Hook signatures + stubs + status copy helper |
| `biometric-seam.test.ts` | Stub + copy tests |
| `BiometricUnlockButton.tsx` | Lock-screen CTA |
| `BiometricSettingsPanel.tsx` | Enable / disable chrome |
| Wired from `app/page.tsx`, `SoverentityFrontend.tsx` | |

## ⛔ Flint — replace stub bodies (do not invent in UI)
Expected contract (agree / adjust signature before glass changes):

```ts
enrollBiometric({ fingerprint, passphrase })
  // WebAuthn create + PRF → wrap unlock factor bound to this fingerprint
  // → { ok: true, credentialIdHint }

unlockWithBiometric(fingerprint)
  // WebAuthn get + PRF unwrap → initSessionKey equivalent (session unlocked)
  // → { ok: true }

disableBiometric(fingerprint)
  // revoke credential + clear wrap
```

`getBiometricEnrollment(fingerprint)` should reflect **real** wrap presence, not the UI preference flag.

## Assumptions
- Device unlock is **per identity × device**, optional; passphrase always remains a path (Signal-model).
- CUR-7 (app-lock idle timeout / lock button) is a separate queue item — this PR only adds the biometric path onto the existing lock gate.
- No server round-trip; WebAuthn stays on-device (claim-honest line in settings).

## Questions for the fleet (answer in PR / merge notes)
See PR description — Flint (PRF API), Hypatia (copy), Athena (placement), Archie (constitution / no brain-wallet).

## Verify
```bash
npx tsx --test src/components/biometric/biometric-seam.test.ts
```
