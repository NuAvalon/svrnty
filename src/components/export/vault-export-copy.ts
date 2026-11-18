// src/components/export/vault-export-copy.ts
// The sentence the vault-export dialog shows when the export does not finish (copy ledger row 232h), and the helper that picks it.
//   - The dialog used to show whatever error text came back (a store or packing error, in the code's own words). It now shows ONE fixed sentence, and the real error is logged by class and code only.
//   - A blocked database upgrade (another tab holds the database) is an expected stop with its own sentence, so the helper asks for that first and does not log it as an unknown failure.
// Run: npx tsx --test src/components/export/vault-export-copy.test.ts
import { errorTag } from '@/lib/error-tag';
import { dbUpgradeBlockedMessage } from '@/lib/db-upgrade-blocked';
import { BlocksIncompleteError } from '@/lib/trust/block-latch';

export const VAULT_EXPORT_FAILED = "The vault export didn't finish. Try again.";

/**
 * The sentence for a sealed export that REFUSED because the blocks could not be made whole first (BlocksIncomplete, thrown before any file is made). CANDIDATE wording: the product copy is
 * reviewed and frozen before this reaches a person. It must say that NOTHING was exported and why, never the generic "didn't finish" (a refusal that hides a block).
 */
export const VAULT_EXPORT_BLOCKS_REFUSED = "We couldn't save your blocks into this backup, so no backup was made and nothing was exported. Lock the app, unlock it again, and try once more.";

/** The sentence for a failed vault export: the blocked-upgrade sentence for that coded stop, else the fixed one (the real error is logged by tag only). */
export function vaultExportFailureMessage(err: unknown): string {
  if (err instanceof BlocksIncompleteError) return VAULT_EXPORT_BLOCKS_REFUSED; // an expected, named refusal: not logged as an unknown failure
  const blocked = dbUpgradeBlockedMessage(err);
  if (blocked !== null) return blocked;
  console.error('Vault export failed:', errorTag(err));
  return VAULT_EXPORT_FAILED;
}
