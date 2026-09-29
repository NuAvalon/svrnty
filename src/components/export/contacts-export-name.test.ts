import assert from 'node:assert/strict';
import { test } from 'node:test';
import { contactsEncryptedExportFilename } from './contacts-export-name';

test('contacts-only encrypted export never uses bare .svrnty (vault collision)', () => {
  const name = contactsEncryptedExportFilename(new Date('2026-08-30T12:00:00.000Z'));
  assert.equal(name, 'svrnty-contacts-2026-08-30.json');
  assert.ok(name.endsWith('.json'));
  assert.ok(!name.endsWith('.svrnty'));
  assert.ok(!/\.svrnty$/i.test(name));
});

test('filename stays distinct from vault-*.svrnty and .svrnty-keys', () => {
  const name = contactsEncryptedExportFilename();
  assert.match(name, /^svrnty-contacts-\d{4}-\d{2}-\d{2}\.json$/);
  assert.notEqual(name.includes('vault-'), true);
  assert.ok(!name.endsWith('.svrnty-keys'));
});
