// src/components/export/vault-export-copy.ts
// The sentence the vault-export dialog shows when the export does not finish (copy ledger row 232h), and the helper that picks it.
//   - The dialog used to show whatever error text came back (a store or packing error, in the code's own words). It now shows ONE fixed sentence, and the real error is logged by class and code only.
//   - A blocked database upgrade (another tab holds the database) is an expected stop with its own sentence, so the helper asks for that first and does not log it as an unknown failure.
// Run: npx tsx --test src/components/export/vault-export-copy.test.ts
import { errorTag } from '@/lib/error-tag';
import { dbUpgradeBlockedMessage } from '@/lib/db-upgrade-blocked';

export const VAULT_EXPORT_FAILED = "The vault export didn't finish. Try again.";

/** The sentence for a failed vault export: the blocked-upgrade sentence for that coded stop, else the fixed one (the real error is logged by tag only). */
export function vaultExportFailureMessage(err: unknown): string {
  const blocked = dbUpgradeBlockedMessage(err);
  if (blocked !== null) return blocked;
  console.error('Vault export failed:', errorTag(err));
  return VAULT_EXPORT_FAILED;
}
