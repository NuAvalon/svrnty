# Recovery UI (L8) — Cursor build notes

**Component owner (UI):** Cursor · **Crypto owner:** team (do not modify `src/lib/crypto/recovery.ts`)  
**Brief:** `CURSOR.md` L8 · Aesthetic: Solar Ember · **Queue:** `CURSOR_QUEUE.md` DO-FIRST recovery-screen copy

## What we built
| File | Role |
|------|------|
| `EntropyMeter.tsx` | Live strength meter for unlock passphrase / future soul-seed word entry |
| `SoulSeedReveal.tsx` | One-time reveal of the recovery phrase after forge (2nd-factor copy) |
| `IdentitySeal.tsx` | Deterministic fingerprint → SVG seal (I-6; no decorative randomness) |
| `solar-ember.ts` | Shared palette tokens from CURSOR.md |

Wired into `SoverentityFrontend.tsx`: forge passphrase meter, recovery-reveal screen, restore-verify **Case A / Case B** copy (Hypatia).

## Restore-screen 2FA copy (DO-FIRST · launch-blocker)
Pure **copy + conditional render** — no crypto / format change.

| Case | Detection (existing) | UI |
|------|----------------------|-----|
| **A** contacts | `owner_fingerprint` + `contacts` + no `identity` | Heading "Restore your contacts" · Password only · no seed mention · CTA "Restore contacts" |
| **B** full identity + vault | `type === 'svrnty-full-backup'` **or** plaintext JSON with `vault` | Heading "Restore your identity" · 2FA intro · Password + Recovery phrase · helper "both required… by design" · CTA "Restore identity" |
| other | binary `svrnty-vault`, keys-only, etc. | Prior password / open-vault chrome (no false 2FA claim) |

**Claim-honesty (load-bearing):**
- Explains EXISTING by-design 2FA only.
- Does **NOT** offer seed-only "lost password" recovery (gated on Flint v4 dual-envelope — separate future task).
- Wrong password → `"Incorrect password. This backup requires your password to restore."`
- Wrong phrase (Case B) → `"That recovery phrase doesn't match this backup."`

## Files touched (this task)
- `src/components/SoverentityFrontend.tsx` (restore-verify UI + honest errors)
- `src/components/recovery/README.md` (this note)
- `CURSOR_QUEUE.md` (PR link when opened)

## Assumptions
1. Today's forge phrase from `createKeyVault` is still **hex groups** (8×8), not BIP39-12 — see **Question 1**.
2. `recoverFromSeedPhrase(vault, phrase)` remains the only recovery crypto call from UI.
3. Encrypted full backups (`svrnty-full-backup`) are treated as Case B because the KeyVault sits inside the ciphertext; L8 forge wraps a vault.

## Questions for the team (ask in PR body)
1. **Hypatia / Flint — "12 words" vs hex groups:** Case B label uses Hypatia's exact **"Recovery phrase — 12 words"**, but `masterSecretToSeedPhrase` still emits hex groups. Confirm: keep "12 words" (forward-looking), soften to "Recovery phrase", or wait for BIP39?
2. **Encrypted contacts envelope** (`{encrypted, salt, iv, data}` without top-level `owner_fingerprint`) is not classified as Case A yet — still needs decrypt-before-detect. OK to leave on ImportContactsDialog, or should restore-gate grow a decrypt-then-branch step?

## Invariants honored
- No crypto reimplementation / no format change
- I-6: IdentitySeal is fingerprint-deterministic
- No presence/location UI
- No seed-only recovery promise (claim-honesty)
