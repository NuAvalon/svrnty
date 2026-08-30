# L4 Import / Export UI (CUR-4) — Cursor build notes

**Component owner (UI):** Cursor · **Crypto owner:** Flint (`packVault` / session unlock)  
**Brief:** `CURSOR_QUEUE.md` CUR-4 · `CURSOR.md` L4 · Aesthetic: Solar Ember

## What we built
| File | Role |
|------|------|
| `ExportAuthGate.tsx` | Re-enter unlock passphrase before sensitive export |
| `verifyUnlock.ts` | Thin helper — calls fleet `initSessionKey` + `loadKey` (same pattern as `app/page.tsx`) |
| `VaultExportDialog.tsx` | Auth gate → vault passphrase (12+) → fleet `packVault` + `downloadVault` (v4) |

Wired into:
- `SoverentityFrontend.tsx` — Full Backup opens `VaultExportDialog`; Keys / Contacts open after auth gate
- `ContactManagement.tsx` — replaces `prompt()` vault export; JSON + **vCard-all** export behind auth gate
- `SecureImportExportDialogs.tsx` — contacts export **requires** password (no plaintext path); no longer echoes password in the success alert

## Claim-honesty
- Full backup uses fleet **v4** `packVault` (Argon2id) — not the old inline PBKDF2 `svrnty-full-backup` JSON envelope.
- Auth gate copy distinguishes **unlock passphrase** vs **recovery phrase** vs **vault passphrase**.
- Wrong unlock re-auth → session locked (mirrors page unlock); UI reloads to the lock screen.

## Hard boundary
- No crypto invented. Vault encrypt = `packVault`. Unlock verify = existing session APIs.
- Did **not** rewrite the legacy PBKDF2 inside `SecureImportExportDialogs` / `PrivateKeyExportDialog` — those paths pre-existed; migrating them to Argon2id is Flint's seam (flagged below).

## Assumptions
1. `exportAll` + `loadPQKeys` + `loadVault` → `createVaultContents` is the correct pack input (matches prior ContactManagement path).
2. Legacy identities without encrypted-at-rest keys skip the unlock re-auth (`skipped-plaintext`).
3. `#fullBackupBtn` testid kept on the download button inside `VaultExportDialog` for e2e Beat 4 compatibility (auth + passphrase steps now precede it).

## Questions for the team (need your call — answer in PR review / merge notes)
1. **@Flint — non-destructive verifyUnlock?** Wrong re-auth currently `lockSession()`s (initSessionKey replaces the good session key). Prefer a fleet `verifyUnlockPassphrase(fp, phrase)` that does **not** clobber an unlocked session?
2. **@Flint — contacts-only KDF:** `SecureExportDialog` / `PrivateKeyExportDialog` still use legacy PBKDF2-100k. Migrate to `encryptBackup` / shared Argon2id, or deprecate keys-only export in favor of Full Vault only?
3. **@Hypatia — vCard export:** plaintext `.vcf` is portable but not encrypted. Auth-gated only — enough, or require a password-wrapped vCard too?
4. **@Athena — e2e Beat 4:** demo-arc clicks `#fullBackupBtn` after a short password form. Flow is now Auth gate → 12-char vault passphrase → download. OK to update the e2e, or keep a faster path for demos?
5. **@Peter — biometric:** CURSOR.md says export gated behind pw/**biometric**. WebAuthn is CUR-6 — ship passphrase gate now and add passkey as fast-follow?

## Invariants honored
- No gate/crypto/relay modification
- I-3: no aggregate scores in export UI
- I-10a: export payloads are user-authored local data (not imported-card XSS sinks)
