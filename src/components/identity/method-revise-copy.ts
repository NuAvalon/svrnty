// src/components/identity/method-revise-copy.ts
// What the "revise a contact method" dialog says when it fails (copy ledger rows 232d and 255). The rule is the code-only rule: a screen sentence is chosen by the SITE, and
// an error's own text is never shown. An unknown error is logged by its class name and code only (error-tag), never its message.
//   - Saving: the Save button. Nothing has been sent, so a plain retry is real.
//   - Sending: the whole Send step (save the draft, write the history, then send). Every failure that reaches this dialog's catch happens BEFORE any deposit (the production sender
//     catches its own failures and returns them), so "wasn't sent" is true for all three steps; it says nothing about the draft, which a history-write failure leaves saved.
//   - A blocked database upgrade (another tab holds the database) keeps its own sentence in both places and is not logged as an unknown failure.
// Run: npx tsx --test src/components/identity/method-revise-copy.test.ts
import { errorTag } from '@/lib/error-tag';
import { dbUpgradeBlockedMessage } from '@/lib/db-upgrade-blocked';

export const METHOD_SAVE_FAILED = "Saving your change didn't finish. Try again.";
export const METHOD_SEND_FAILED = "Your update wasn't sent. Try again.";

/** The sentence for a failed save: the blocked-upgrade sentence for that coded stop, else the fixed one (the real error is logged by tag only). */
export function methodSaveFailureMessage(err: unknown): string {
  const blocked = dbUpgradeBlockedMessage(err);
  if (blocked !== null) return blocked;
  console.error('Method save failed:', errorTag(err));
  return METHOD_SAVE_FAILED;
}

/** The sentence for a failed send step: the blocked-upgrade sentence for that coded stop, else the fixed one (the real error is logged by tag only). */
export function methodSendFailureMessage(err: unknown): string {
  const blocked = dbUpgradeBlockedMessage(err);
  if (blocked !== null) return blocked;
  console.error('Method send failed:', errorTag(err));
  return METHOD_SEND_FAILED;
}
