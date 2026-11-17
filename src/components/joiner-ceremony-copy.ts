// src/components/joiner-ceremony-copy.ts
// What the link-landing screen says when opening a shared link, adding the giver to your Gate, or keeping a recovery piece fails (copy ledger row 231c). The rule is the
// code-only rule: a screen sentence is chosen by the SITE, and an error's own text is never shown. Each catch used to put the error's text first and its fixed sentence only
// as a fallback; now it is always the fixed sentence. An unknown error is logged by its class name and code only (contact-io-errors' errorTag), never its message.
//   - openLink is byte-identical to the fallback this screen already carried (and to the relay's own not-found sentence).
//   - addToGate: the Gate entry or the contact write may have run before the throw, so it says "check" before "try again". This is the one site that reaches the contact store,
//     which refuses on purpose (a fingerprint that does not match its key, a trust without a verification): a refusal means nothing was written, so it shows the refusal's
//     own sentence (chosen by its code and reason, from the same leaf the contact book uses) and never "didn't finish, try again".
//   - keepPiece: storing the piece is one write and the piece stays in the page until it succeeds, so a retry is real.
// Run: npx tsx --test src/components/joiner-ceremony-copy.test.ts
import { errorTag } from '@/lib/error-tag';
import { contactRefusalMessage } from '@/lib/contacts/contact-refusal';

export const JOINER_FAILURE_MESSAGES = Object.freeze({
  openLink: "This link isn't available. It may have expired, been copied incompletely, or no longer be held by the relay. Ask the person who shared it for a new one.",
  addToGate: "Adding them to your Gate didn't finish. Check your Gate before you try again.",
  keepPiece: "The piece couldn't be saved. Try again.",
});

export type JoinerFailureSite = keyof typeof JOINER_FAILURE_MESSAGES;

/** A contact refusal's own sentence (add-to-Gate only), else the site's fixed sentence; the real error is logged by tag only. */
export function joinerFailureMessage(err: unknown, site: JoinerFailureSite): string {
  const refusal = site === 'addToGate' ? contactRefusalMessage(err) : null;   // only this site reaches the contact store
  if (refusal) return refusal;
  console.error(`Joiner ${site} failed:`, errorTag(err));
  return JOINER_FAILURE_MESSAGES[site];
}
