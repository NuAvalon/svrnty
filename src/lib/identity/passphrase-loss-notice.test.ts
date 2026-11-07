// The static notice for people whose contacts or backup went missing after a passphrase change or a restore. Pins the words and the places.
// Run: npx tsx --test src/lib/identity/passphrase-loss-notice.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { PASSPHRASE_LOSS_NOTICE_BACKUP, PASSPHRASE_LOSS_NOTICE_CONTACTS } from './passphrase-loss-notice';

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');
const strip = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

test('the two notices say what was agreed, word for word', () => {
  assert.equal(PASSPHRASE_LOSS_NOTICE_CONTACTS, "If your contacts disappeared after you changed your passphrase or restored a backup, don't clear this browser's data. They may still be stored on this device, and we're working on a way to bring them back. Keep your previous passphrase.");
  assert.equal(PASSPHRASE_LOSS_NOTICE_BACKUP, "If no backup file appears after you changed your passphrase or restored a backup, part of your data can't be read with your current passphrase. Don't clear this browser's data, and keep your previous passphrase. We're working on a fix.");
});

test('wording rules: "may" not "are" about the contacts; no promise that nothing is lost; no date; no mention of the Set Passphrase item', () => {
  for (const s of [PASSPHRASE_LOSS_NOTICE_CONTACTS, PASSPHRASE_LOSS_NOTICE_BACKUP]) {
    assert.doesNotMatch(s, /not lost|\bsafe\b|\bsafely\b|guarantee|will be restored/i);
    assert.doesNotMatch(s, /\b(20\d\d|today|tomorrow|soon|this week|by [A-Z][a-z]+day)\b/i);
    assert.doesNotMatch(s, /Set Passphrase/i);
    assert.match(s, /don't clear this browser's data/i);
    assert.match(s, /previous passphrase/i);
  }
  assert.match(PASSPHRASE_LOSS_NOTICE_CONTACTS, /\bmay still be stored\b/);
});

test('PIN: the contacts notice sits in the "No contacts yet" state only (no search, not the blocked list), under the title and above the hint', () => {
  const ui = strip(read('../../components/ContactManagement.tsx'));
  assert.equal((ui.match(/PASSPHRASE_LOSS_NOTICE_CONTACTS/g) ?? []).length, 2, 'imported once, used once');
  const i = ui.indexOf('{PASSPHRASE_LOSS_NOTICE_CONTACTS}');
  const guard = ui.lastIndexOf('{!searchQuery && !showBlocked && (', i);
  assert.ok(guard > 0 && i - guard < 500, 'inside the no-search, not-blocked block');
  const title = ui.indexOf("'No contacts yet'");
  const hint = ui.indexOf("'Import a VCF or add someone to start your master book'");
  assert.ok(title > 0 && title < guard && guard - title < 200, 'directly after the "No contacts yet" title');
  assert.ok(hint > i, 'above the "Import a VCF" hint, so a phone user sees it on the first screen');
});

test('PIN: the backup notice is in the backup dialog header and nowhere else; the two notices are used in no other file', () => {
  const dlg = strip(read('../../components/export/VaultExportDialog.tsx'));
  assert.equal((dlg.match(/PASSPHRASE_LOSS_NOTICE_BACKUP/g) ?? []).length, 2);
  assert.match(dlg, /<\/DialogDescription>\s*<p data-testid="passphrase-loss-notice-backup"/);
  const other = ['../../components/SoverentityFrontend.tsx', '../../../app/page.tsx'].map((r) => strip(read(r)));
  for (const src of other) assert.doesNotMatch(src, /PASSPHRASE_LOSS_NOTICE/);
});
