// src/components/soverentity-frontend-copy.ts
// What the main screen says when creating an identity or sending a contact-method update fails (copy ledger row 229). The rule is the code-only rule: a screen sentence is
// chosen by the SITE, and an error's own text is never shown. An unknown error is logged by its class name and code only (contact-io-errors' errorTag), never its message.
//   - createIdentity: keys may already be stored before the throw, so the sentence says to reload.
//   - sendUpdate: several recipients are deposited to, so a throw can come after some deposits; a resend is harmless (the update carries a higher version and an absolute value,
//     and a receiver drops only versions at or below the last applied one).
// Run: npx tsx --test src/components/soverentity-frontend-copy.test.ts
import { errorTag } from '@/lib/contacts/contact-io-errors';
import { dbUpgradeBlockedMessage } from '@/lib/db-upgrade-blocked';

export const FRONTEND_FAILURE_MESSAGES = Object.freeze({
  createIdentity: "Creating your identity didn't finish. Reload the page before you try again.",
  sendUpdate: "Sending your update didn't finish. Some contacts may already have it. You can send it again.",
});

export type FrontendFailureSite = keyof typeof FRONTEND_FAILURE_MESSAGES;

/** The site's fixed sentence; the real error is logged by tag only. */
export function frontendFailureMessage(err: unknown, site: FrontendFailureSite): string {
  const blocked = dbUpgradeBlockedMessage(err);   // another tab holds the database: an expected stop, not an unknown failure, so not logged
  if (blocked !== null) return blocked;
  console.error(`${site} failed:`, errorTag(err));
  return FRONTEND_FAILURE_MESSAGES[site];
}
