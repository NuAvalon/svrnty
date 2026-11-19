// src/lib/identity/export-excludes-sealed-rows.test.ts
// STATIC guards for what a backup can carry. Owner-sealed rows (OWNER_SEALED_SETTINGS) travel in a backup only by name and by review. Today two do: the delivery-receipts default (read by
// exportAll) and the suppression carry (attached to the vault payload). These guards make sure no OTHER row can travel without a review: no generic read or loop, a closed list of readers,
// and the two known spreads. The identity store has no runtime IndexedDB test, so these read the SOURCE; they say what the code is, not what a browser ran.
//
// Other tests pin individual rows by NAME (exportAll does not mention the suppression record, the seeds are not a VaultContents field). A name-based pin cannot see a future export that loops over the
// settings rows, or reads them all at once, because that code would not name any one row. So these pin the SHAPE instead:
//   - exportAll never names the settings store or OWNER_SEALED_SETTINGS, never reads a store generically, and calls a CLOSED list of functions (a new call is a new thing the plaintext backup
//     carries: it needs a review and an edit of the list below),
//   - the vault payload block (the trust-graph object that is packed with the passphrase) names neither, and its only spreads are the two known ones,
//   - vault.ts (packVault and createVaultContents) takes an explicit contents object and cannot reach a store at all.
// Run: npx tsx --test src/lib/identity/export-excludes-sealed-rows.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const store = readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8');
const dialog = readFileSync(new URL('../../components/export/VaultExportDialog.tsx', import.meta.url), 'utf8');
const vault = readFileSync(new URL('../sync/vault.ts', import.meta.url), 'utf8');

/** Block comments and line comments removed (a `//` after a colon is kept: a URL, not a comment). Strings are kept. */
const noComments = (t: string): string => t.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:\w'"`])\/\/.*$/gm, '$1');
/** The same, with the inside of every string literal blanked, so words in a message are not read as calls. */
const noStrings = (t: string): string => noComments(t).replace(/'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|`(?:[^`\\]|\\.)*`/g, "''");
const callsOf = (t: string): string[] => [...new Set([...noStrings(t).matchAll(/(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(/g)].map((m) => m[1]))].sort();

/** The text of exportAll: from its head to the first lone closing brace. Checked to be real (not empty) so a rename cannot turn every assertion below into a pass over nothing. */
const exportAllBody = (): string => {
  const a = store.indexOf('export async function exportAll(');
  assert.ok(a >= 0, 'exportAll exists');
  const b = store.indexOf('\n}\n', a);
  assert.ok(b > a, 'exportAll ends');
  const body = store.slice(a, b);
  assert.ok(body.length > 500 && body.includes('loadIdentity(') && body.includes('getAllContacts('), 'the slice is the real exportAll, not an empty or partial one');
  return body;
};

/** The vault payload block: from the trust-graph object to the call that packs it. */
const payloadBlock = (): string => {
  const i = dialog.indexOf('const trustGraph = {');
  const j = dialog.indexOf('await packVault(contents, password)');
  assert.ok(i >= 0 && j > i, 'the payload block markers exist, in order');
  const block = dialog.slice(i, j);
  assert.ok(block.includes('edges:') && block.includes('contacts: backup.contacts'), 'the slice is the real payload block, not an empty or partial one');
  return block;
};

const GENERIC_READ = /\b(?:getAll|getAllKeys|openCursor|openKeyCursor|txGetAll|txKeysWithPrefix|txGetByIndex)\s*\(/;

test('X1 exportAll never names the settings store or OWNER_SEALED_SETTINGS, and never reads a store generically', () => {
  const body = noComments(exportAllBody());
  assert.doesNotMatch(body, /OWNER_SEALED_SETTINGS/, 'a loop over the sealed rows would carry every one of them without naming any');
  assert.doesNotMatch(body, /['"`]settings['"`]/, 'the settings store is not named');
  assert.doesNotMatch(body, GENERIC_READ, 'no read of a whole store or a key range');
});

test('X2 exportAll calls only a CLOSED list of functions: a new call is a new thing the plaintext backup carries', () => {
  const allowed = [
    'Date', 'Error', 'catch', 'exportAll', 'getAllContacts', 'if', 'loadDeviceMailbox', 'loadIdentity', 'loadKey', 'loadPQKeys', 'loadShards', 'loadVault', 'readDeliveryDefault', 'serializeMailboxKeypair',
  ];
  const calls = callsOf(exportAllBody());
  assert.ok(calls.length >= 8, 'the call list was really read');
  assert.deepEqual(calls.filter((c) => !allowed.includes(c)), [], 'if you meant to add a field to the backup, review that it is not an owner-sealed row, then add its reader to the list');
});

test('X3 the vault payload block names neither the settings store nor OWNER_SEALED_SETTINGS, reads no store generically, and spreads only the two known things', () => {
  const block = noComments(payloadBlock());
  assert.doesNotMatch(block, /OWNER_SEALED_SETTINGS/);
  assert.doesNotMatch(block, /['"`]settings['"`]/);
  assert.doesNotMatch(block, GENERIC_READ);
  const spreads = noStrings(block).split('\n').flatMap((l) => (l.match(/\.\.\.[^\n]*/) ? [l.trim().replace(/,$/, '')] : []));
  assert.deepEqual(spreads, ['...c.metadata', '...(suppression ? { suppression } : {})'], 'a new spread in the packed object could carry a whole object of rows');
});

test('X4 packVault takes an explicit VaultContents, and vault.ts cannot reach a store at all', () => {
  assert.ok(/export async function packVault\(contents: VaultContents/.test(vault), 'packVault still takes an explicit contents object (if it ever dumps whole stores, these guards must be revisited)');
  assert.ok(/export function createVaultContents\(\s*identity: VaultIdentity,/.test(vault), 'createVaultContents still takes its parts one by one');
  assert.doesNotMatch(noComments(vault), /indexedDB|openDB|\btxGet|\btxPut|client-store|localStorage|OWNER_SEALED_SETTINGS/, 'vault.ts has no way to read a store');
});
