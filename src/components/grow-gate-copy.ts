// src/components/grow-gate-copy.ts
// What the Gate panel says when letting someone in, or dismissing them, does not finish (copy ledger row 232b). The rule is the code-only rule: a screen sentence is chosen by the
// SITE, and an error's own text is never shown. Each catch used to put the error's text first and a short fallback after it; now it is always the site's fixed sentence. An unknown
// error is logged by its class name and code only (error-tag), never its message.
//   - admit: letting someone in writes a contact, then removes them from the Gate, then refreshes, so a failure may have run part of that: the sentence says "check" before "try again".
//     This is the one site that reaches the contact store's own refusals (a fingerprint that does not match its key): a refusal means nothing was written, so it shows the refusal's own
//     sentence (chosen by its code and reason, from the same leaf the contact book uses) and never "didn't finish, try again", which would hide the warning.
//   - dismiss: removing the arrival from the Gate; the same "check your Gate" advice. It writes no contact, so it never maps a refusal.
// Run: npx tsx --test src/components/grow-gate-copy.test.ts
import { errorTag } from '@/lib/error-tag';
import { contactRefusalMessage } from '@/lib/contacts/contact-refusal';
import { dbUpgradeBlockedMessage } from '@/lib/db-upgrade-blocked';

export const GROW_GATE_FAILURE_MESSAGES = Object.freeze({
  admit: "Letting them in didn't finish. Check your Gate before you try again.",
  dismiss: "Dismissing didn't finish. Check your Gate before you try again.",
});

export type GrowGateFailureSite = keyof typeof GROW_GATE_FAILURE_MESSAGES;

/** A contact refusal's own sentence (admit only), else the site's fixed sentence; the real error is logged by tag only. */
export function growGateFailureMessage(err: unknown, site: GrowGateFailureSite): string {
  const refusal = site === 'admit' ? contactRefusalMessage(err) : null;   // only this site writes a contact
  if (refusal) return refusal;
  const blocked = dbUpgradeBlockedMessage(err);   // both sites touch the store, so both map it; an expected stop, so not logged
  if (blocked !== null) return blocked;
  console.error(`Grow gate ${site} failed:`, errorTag(err));
  return GROW_GATE_FAILURE_MESSAGES[site];
}
