# Contacts-only export chrome (gap claim-honesty residual)

**Owner (UI):** Cursor · **Seam:** Flint (legacy PBKDF2 KDF — untouched) · Hypatia (copy)

## What changed
- User-facing **Secure Export / Secure Contact Export** → **Export contacts**
- User-facing **Secure Import / Secure Contact Import** → **Import contacts**
- Download filename: `svrnty-contacts-YYYY-MM-DD.json` via `contacts-export-name.ts` — **not** bare `.svrnty`
- Description under-claims: contacts-only; Full Backup for identity vault

## What did NOT change
- Encryption path (PBKDF2-100k AES-GCM) — fleet migrate seam
- Payload shape
- Restore format-detect (still accepts legacy misnamed `.svrnty` JSON + `.json`)

## Verify
```bash
npx tsx --test src/components/export/contacts-export-name.test.ts
```

## ★ Team asks (answer in the PR description / merge notes — not review comments)

**Hypatia**
1. Approve Export contacts / Import contacts wording + “cannot restore your identity” line?
2. Keep pointing users at **Full Backup (.svrnty)** from this dialog, or only from Help (#78)?

**Flint / Archie**
3. Confirm bare `.svrnty` must stay reserved for `packVault` binary vaults — contacts-only download as `.json` is correct?
4. QUEUE CASE A still says contacts backup “`.svrnty`” — update queue language to `.json`, or keep accepting both on restore only?

**Athena**
5. Any e2e that asserted `svrnty-contacts-*.svrnty` download name? (demo-arc expects `.vcf` / `vault-*.svrnty` — should be fine.)
