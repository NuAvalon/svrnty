// src/lib/contacts/restore-report.ts
// What a vault restore tells the owner about their contacts.
//
// A vault is authenticated by the passphrase that opened it, so each contact in it goes to the store as the vault carried it (epoch, version and the
// post-quantum keys included): unlike a plain contacts file, nothing is projected away here. The store still refuses a contact whose fingerprint does
// not match its keys, and refuses to create a trusted contact without a recorded verification; those contacts are skipped, and until now they were skipped
// with a console warning only. This module counts them and names them, in the same words as the contacts-file import (book-import.ts).
// Run: npx tsx --test src/lib/contacts/restore-report.test.ts

import { MAX_NAMED, safeContactLabel, storeRefusalReason, type ImportFailure } from './book-import';

export interface VaultContactsReport {
  total: number;
  restored: number;
  skipped: ImportFailure[];
}

/** Persist each vault contact through `add` exactly as given. One that the store refuses is counted and named; the rest still restore. */
export async function restoreVaultContacts(contacts: unknown, add: (contact: never) => Promise<unknown>): Promise<VaultContactsReport> {
  const list = Array.isArray(contacts) ? contacts : [];
  const report: VaultContactsReport = { total: list.length, restored: 0, skipped: [] };
  for (const contact of list) {
    try {
      await add(contact as never);
      report.restored++;
    } catch (e) {
      console.warn('[restore] skipped a contact that failed to persist:', (e as Error)?.message);
      const c = (contact ?? {}) as { name?: unknown; display_name?: unknown };
      report.skipped.push({ label: safeContactLabel(c.name ?? c.display_name), reason: storeRefusalReason(e) });
    }
  }
  return report;
}

/** One line for the owner, or null when every contact restored. */
export function formatVaultRestoreReport(r: VaultContactsReport): string | null {
  if (r.skipped.length === 0) return null;
  const shown = r.skipped.slice(0, MAX_NAMED).map((f) => `${f.label} (${f.reason})`).join('; ');
  const more = r.skipped.length > MAX_NAMED ? `; and ${r.skipped.length - MAX_NAMED} more` : '';
  return `Restored ${r.restored} of ${r.total} contacts. Not restored: ${shown}${more}.`;
}
