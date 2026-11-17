// src/components/contact-management-copy.ts
// What the contact book says when something fails. The rule (copy ledger, code-only): a screen sentence is chosen by a CODE or a SITE, and an error's own text is
// never shown. The sentences are the copy owner's words (ledger row 228) and are constants:
//   - INPUT: the nine sentences this screen refuses with ON PURPOSE (validation). They are raised as a typed ContactInputError and shown ONLY for that class.
//   - FAILURE: one fixed sentence per site for everything else. A site that writes and then reloads can be half done, so it says "check" before "try again".
//   - An unknown error is logged by its class name and code only (contact-io-errors' errorTag), never its message.
//   - The export site reuses the export sentence of the import/export screens, so the same event reads the same everywhere.
//   - A store REFUSAL (a fingerprint that does not match its key, trust without a verification, a blocked contact) keeps its own sentence (ledger row 233).
// Run: npx tsx --test src/components/contact-management-copy.test.ts
import { CONTACT_IO_MESSAGES, errorTag } from '@/lib/contacts/contact-io-errors';
import { contactRefusalMessage } from '@/lib/contacts/contact-refusal';

export type ContactInputCode =
  | 'invite-no-key'
  | 'share-no-key'
  | 'add-missing'
  | 'add-self'
  | 'edit-no-name'
  | 'edit-key-bound'
  | 'import-incomplete'
  | 'import-self'
  | 'link-empty';

/** A refusal this screen raises itself. `code` picks the sentence; `message` is for the log only and says nothing about the input. */
export class ContactInputError extends Error {
  readonly code: ContactInputCode;
  constructor(code: ContactInputCode) { super(`contact input refused: ${code}`); this.name = 'ContactInputError'; this.code = code; }
}

export const CONTACT_INPUT_MESSAGES: Readonly<Record<ContactInputCode, string>> = Object.freeze({
  'invite-no-key': 'Unlock your identity first to build an invite.',
  'share-no-key': 'Unlock your identity first to share a signed card.',
  'add-missing': 'Enter a name and a fingerprint.',
  'add-self': "You can't add yourself as a contact.",
  'edit-no-name': 'Enter a name.',
  'edit-key-bound': "This contact is tied to their key, so these details can't be edited. You can still change trust, groups and sharing.",
  'import-incomplete': "This card is missing a fingerprint or public key, so it can't be imported.",
  'import-self': "You can't import yourself as a contact.",
  'link-empty': 'Paste their SVRNTY fingerprint and public key.',
});

export type ContactFailureSite =
  | 'load'
  | 'invite'
  | 'add'
  | 'edit'
  | 'remove'
  | 'trust'
  | 'verify'
  | 'block'
  | 'unblock'
  | 'share'
  | 'import'
  | 'link'
  | 'renameGroup'
  | 'removeGroup'
  | 'assignGroup'
  | 'export';

export const CONTACT_FAILURE_MESSAGES: Readonly<Record<ContactFailureSite, string>> = Object.freeze({
  load: "Your contacts couldn't be loaded. Reload the page to try again.",
  invite: "The invite couldn't be prepared. Check your connection and try again.",
  add: "Adding the contact didn't finish. Check your contacts before you try again.",
  edit: "Saving your changes didn't finish. Check the contact before you try again.",
  remove: "Removing the contact didn't finish. Check your contacts before you try again.",
  trust: "Changing trust didn't finish. Check the contact before you try again.",
  verify: "Recording your verification didn't finish. Check the contact before you try again.",
  block: 'This person may not be blocked. Check the contact and try again.',
  unblock: "Unblocking didn't finish. Check the contact and try again.",
  share: "Your card couldn't be prepared for sharing. Try again.",
  import: "Importing this card didn't finish. Check your contacts before you try again.",
  link: "Linking didn't finish. Check the contact before you try again.",
  renameGroup: "Renaming the group didn't finish. Check your groups before you try again.",
  removeGroup: "Removing the group didn't finish. Check your groups before you try again.",
  assignGroup: "Adding the contact to the group didn't finish. Check the contact before you try again.",
  export: CONTACT_IO_MESSAGES.exportUnknown,
});

/** The sentence for a failed action: a typed refusal's own sentence (input, or a store refusal by code), else the site's fixed one (the real error is logged by tag only). */
export function contactFailureMessage(err: unknown, site: ContactFailureSite): string {
  if (err instanceof ContactInputError) return CONTACT_INPUT_MESSAGES[err.code];
  const refusal = contactRefusalMessage(err, site === 'import' ? 'import' : site === 'add' ? 'add' : 'other');
  if (refusal !== null) return refusal;
  console.error(`Contact ${site} failed:`, errorTag(err));
  return CONTACT_FAILURE_MESSAGES[site];
}
