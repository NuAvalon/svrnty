// src/components/import-contacts-copy.ts
// What the "import contacts from a .vcf file" dialog says when it fails (copy ledger rows 232c and 256). The rule is the code-only rule: a screen sentence is chosen by the SITE, and an error's own
// text is never shown. An unknown error is logged by its class name and code only (error-tag), never its message. A blocked database upgrade (another tab holds the database) keeps its own sentence.
//   - Reading the file: the file is read and parsed. Nothing is written.
//   - Reading the book to compare with: the contacts already in the book are read. Nothing is written, so "nothing was imported" is true; the usual cause is a locked session, which "try again" alone would not fix.
//   - Importing: several writes in a row, so some contacts may already be in the book. This is the contact book's own import sentence, imported and not retyped.
// What can reach each catch (checked against the code): reading the file = the browser's file read; reading the book = the book read; importing = a locked session, a store conflict (that contact is not written), a storage
// error. A vCard never carries a public key, so the typed binding refusal of addContact cannot happen here; the test pins that, so a future change that parses a key must map it first.
// Run: npx tsx --test src/components/import-contacts-copy.test.ts
import { errorTag } from '@/lib/error-tag';
import { dbUpgradeBlockedMessage } from '@/lib/db-upgrade-blocked';
import { CONTACT_IO_MESSAGES } from '@/lib/contacts/contact-io-errors';

export const VCF_READ_FAILED = "That file couldn't be read. Make sure it's a .vcf contacts file and try again.";
export const VCF_BOOK_READ_FAILED = "Your contacts couldn't be read to compare with this file, so nothing was imported. Check that your identity is unlocked, then try again.";

/** The sentence for a file that could not be read: the blocked-upgrade sentence for that coded stop, else the fixed one (the real error is logged by tag only). */
export function vcfReadFailureMessage(err: unknown): string {
  const blocked = dbUpgradeBlockedMessage(err);
  if (blocked !== null) return blocked;
  console.error('Contacts file read failed:', errorTag(err));
  return VCF_READ_FAILED;
}

/** The sentence for the book that could not be read to compare with: the blocked-upgrade sentence for that coded stop, else the fixed one (the real error is logged by tag only). */
export function vcfBookReadFailureMessage(err: unknown): string {
  const blocked = dbUpgradeBlockedMessage(err);
  if (blocked !== null) return blocked;
  console.error('Contacts book read failed:', errorTag(err));
  return VCF_BOOK_READ_FAILED;
}

/** The sentence for an import that stopped part-way: the blocked-upgrade sentence for that coded stop, else the contact book's own import sentence (the real error is logged by tag only). */
export function vcfImportFailureMessage(err: unknown): string {
  const blocked = dbUpgradeBlockedMessage(err);
  if (blocked !== null) return blocked;
  console.error('Contacts import failed:', errorTag(err));
  return CONTACT_IO_MESSAGES.importUnknown;
}
