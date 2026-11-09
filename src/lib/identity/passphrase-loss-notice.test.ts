// The static notice for people whose contacts or backup went missing after a passphrase change or a restore. Pins the words and the places.
// Run: npx tsx --test src/lib/identity/passphrase-loss-notice.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { PASSPHRASE_LOSS_NOTICE_BACKUP, PASSPHRASE_LOSS_NOTICE_CONTACTS } from './passphrase-loss-notice';

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');
const strip = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

test('the two notices say what was agreed, word for word', () => {
  assert.equal(PASSPHRASE_LOSS_NOTICE_CONTACTS, "Contacts missing after a passphrase change or restore? Don't clear this browser's data, and keep your old passphrase. We're working on recovery.");
  assert.equal(PASSPHRASE_LOSS_NOTICE_BACKUP, "If no backup file appears after you changed your passphrase or restored a backup, part of your data can't be read with your current passphrase. Don't clear this browser's data, and keep your previous passphrase. We're working on a fix.");
});

test('wording rules (ledger row 56): no promise that nothing is lost; no date or "soon"; no mention of the Set Passphrase item; no claim about what is stored', () => {
  for (const s of [PASSPHRASE_LOSS_NOTICE_CONTACTS, PASSPHRASE_LOSS_NOTICE_BACKUP]) {
    assert.doesNotMatch(s, /not lost|\bsafe\b|\bsafely\b|guarantee|will be restored|nothing was deleted/i);
    assert.doesNotMatch(s, /\b(20\d\d|today|tomorrow|soon|this week|by [A-Z][a-z]+day)\b/i);
    assert.doesNotMatch(s, /Set Passphrase/i);
    assert.match(s, /don't clear this browser's data/i);
  }
  assert.match(PASSPHRASE_LOSS_NOTICE_CONTACTS, /old passphrase/i);
  assert.match(PASSPHRASE_LOSS_NOTICE_BACKUP, /previous passphrase/i);
  assert.doesNotMatch(PASSPHRASE_LOSS_NOTICE_CONTACTS, /\bstored\b|still (there|on)|are (still )?(there|stored)/i); // the banner makes no claim about the rows; only the dialog line says what cannot be read
  assert.ok(PASSPHRASE_LOSS_NOTICE_CONTACTS.length <= 160, 'one short line');
});

test('PIN: the contacts banner is at the TOP of the address book (header, above the import buttons), only while the book is empty (no search, not the Blocked view), and not inside the empty box', () => {
  const ui = strip(read('../../components/ContactManagement.tsx'));
  assert.equal((ui.match(/PASSPHRASE_LOSS_NOTICE_CONTACTS/g) ?? []).length, 2, 'imported once, used once');
  const i = ui.indexOf('{PASSPHRASE_LOSS_NOTICE_CONTACTS}');
  const guard = ui.lastIndexOf('{!loading && filteredContacts.length === 0 && !searchQuery && !showBlocked && (', i);
  assert.ok(guard > 0 && i - guard < 500, 'inside the empty-book, no-search, not-blocked guard');
  const desc = ui.indexOf('Share your own identity from the Identity tab.');
  assert.ok(desc > 0 && desc < guard && guard - desc < 300, 'directly under the header description');
  assert.ok(i < ui.indexOf('Import Contact'), 'above the import buttons');
  assert.ok(i < ui.indexOf("'No contacts yet'"), 'not inside the empty box, which starts below the ~600px card on a phone');
  assert.doesNotMatch(ui, /empty-book-icon|hidden sm:inline-flex/, 'the icon is back to normal; it was only a workaround for the lower position');
});

test('PIN: the backup notice is in the backup dialog header and nowhere else; the two notices are used in no other file', () => {
  const dlg = strip(read('../../components/export/VaultExportDialog.tsx'));
  assert.equal((dlg.match(/PASSPHRASE_LOSS_NOTICE_BACKUP/g) ?? []).length, 2);
  assert.match(dlg, /<\/DialogDescription>\s*<p data-testid="passphrase-loss-notice-backup"/);
  const other = ['../../components/SoverentityFrontend.tsx', '../../../app/page.tsx'].map((r) => strip(read(r)));
  for (const src of other) assert.doesNotMatch(src, /PASSPHRASE_LOSS_NOTICE/);
});
