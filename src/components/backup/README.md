# Cloud backup UI shell

Queue #1 (inbox) — **Cloud-sync UI shell** · spec cited as `products/svrnty_cloud_blob_sync_spec.md` (that file is **not in this repo**; built from the queue BUILD/ACCEPTANCE lines).

## What this is
Render-glass for **minimal backup + restore**:
- Connect a target (Dropbox / iCloud / Google Drive) — device-local preference
- Backup status (last backup time, success/fail)
- Restore-from-backup trigger on the existing start-screen restore path

Copy says **backup**, not seamless multi-device sync.

## Files
- `cloud-backup-targets.ts` — preference/status store + honest copy + `isCloudBlobTransportLive() === false`
- `CloudBackupShell.tsx` — Solar Ember panel
- Wired in `SoverentityFrontend.tsx` (Identity export cluster + restore gate)
- `VaultExportDialog` reports success/fail so status can update (still calls fleet `packVault`)

## Hard boundary
- Did **not** modify CODEOWNERS paths, cloud adapters, OAuth, or restore-gate control flow (`seedPathActive` / which-key-decrypts-what).
- Did **not** call `createCloudAdapter` / `packVault` / `unpackVault` from this folder.
- Tokens are never stored. Preference is `{ target }`. Status is `{ at, ok, target, kind: "file" }`.

## Assumptions
- Athena’s blob transport / OAuth is **not live**. Connecting a target saves intent only. **Back up now** opens the existing Full Backup dialog (local `.svrnty` download). Status records that file save, not an upload.
- Restore while an identity is already unlocked stays on the start-screen Continue path (no in-session overwrite invented here).

## Team asks (answer in the PR)
1. **Athena** — please add `products/svrnty_cloud_blob_sync_spec.md` to the repo (or point glass at the canonical path). Flip `isCloudBlobTransportLive()` when OAuth + upload/download should run; glass will call `createCloudAdapter` then, not before.
2. **Hypatia** — claim pass on “backup, not multi-device sync” / “sending the file is not wired yet”.
3. **Flint** — confirm we should keep recording `kind: "file"` until transport writes a different honest kind (never “uploaded to Dropbox” without an upload).
