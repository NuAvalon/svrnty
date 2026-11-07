// src/lib/contacts/restore-report.test.ts
// What a vault restore tells the owner about their contacts. Run: npx tsx --test src/lib/contacts/restore-report.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { formatVaultRestoreReport, restoreVaultContacts } from './restore-report';

const binding = new Error('fingerprint↔key binding failed — refusing to store a contact whose fingerprint does not match its public key');
const trust = new Error('verify-before-trust: refusing to create a trusted contact without owner verification');

/** A store that refuses by name, like addContact refuses by gate. */
function store(refuse: Record<string, Error> = {}) {
  const seen: unknown[] = [];
  return { seen, add: async (c: never) => { seen.push(c); const e = refuse[(c as { name: string }).name]; if (e) throw e; } };
}
const vault = (names: string[]) => names.map((name) => ({ name, id: `id-${name}`, fingerprint: name.repeat(8), trust_level: 'trusted', epoch: 7, version: 3, pq_kem_public_key: 'k', metadata: { owner_verify: { owner_verified_at: 't' } } }));

test('every contact restores: counted, no message', async () => {
  const s = store();
  const r = await restoreVaultContacts(vault(['a', 'b', 'c']), s.add);
  assert.deepEqual({ total: r.total, restored: r.restored, skipped: r.skipped.length }, { total: 3, restored: 3, skipped: 0 });
  assert.equal(formatVaultRestoreReport(r), null);
});

test('NEG: each contact reaches the store EXACTLY as the vault carried it (same object; epoch, version, post-quantum key and owner verification intact): a vault is passphrase-authenticated, so nothing is projected away', async () => {
  const list = vault(['a', 'b']);
  const s = store();
  await restoreVaultContacts(list, s.add);
  assert.equal(s.seen.length, 2);
  s.seen.forEach((c, i) => assert.equal(c, list[i], 'the same object, not a copy or a projection'));
  assert.equal((s.seen[0] as { epoch: number }).epoch, 7);
  assert.equal((s.seen[0] as { trust_level: string }).trust_level, 'trusted');
});

test('a contact the store refuses is counted and NAMED with a plain reason, and the others still restore (in order)', async () => {
  const s = store({ b: binding, d: trust, e: new Error('IDB: secret internal detail') });
  const r = await restoreVaultContacts(vault(['a', 'b', 'c', 'd', 'e']), s.add);
  assert.equal(r.restored, 2);
  assert.deepEqual(r.skipped, [
    { label: 'b', reason: 'its key does not match its fingerprint' },
    { label: 'd', reason: "it was marked as trusted, but there's no record of verifying it" },
    { label: 'e', reason: 'could not be saved' },
  ]);
  assert.deepEqual(s.seen.map((c) => (c as { name: string }).name), ['a', 'b', 'c', 'd', 'e'], 'every contact was tried, in order');
  assert.equal(formatVaultRestoreReport(r), "2 of 5 contacts from the backup are on this device. Not restored: b (its key does not match its fingerprint); d (it was marked as trusted, but there's no record of verifying it); e (could not be saved).");
  assert.equal(formatVaultRestoreReport(r)!.includes('secret'), false, 'the raw error text is never shown');
});

test('names are made safe and capped at five, with the rest counted', async () => {
  const names = Array.from({ length: 8 }, (_, i) => `n${i}\u0007\n${'x'.repeat(100)}`);
  const refuse = Object.fromEntries(names.map((n) => [n, binding]));
  const r = await restoreVaultContacts(names.map((name) => ({ name })), store(refuse).add);
  const msg = formatVaultRestoreReport(r)!;
  assert.ok(!/[\u0000-\u001f]/.test(msg));
  assert.ok(msg.startsWith('0 of 8 contacts from the backup are on this device.'));
  assert.ok(msg.endsWith('; and 3 more.'));
  assert.ok(r.skipped.every((f) => f.label.length <= 61));
});

test('no contacts, a missing list, a null entry and a non-Error throw are all handled without throwing', async () => {
  for (const v of [undefined, null, 'x', {}, []]) {
    const r = await restoreVaultContacts(v, store().add);
    assert.deepEqual({ total: r.total, restored: r.restored, skipped: r.skipped.length }, { total: 0, restored: 0, skipped: 0 });
  }
  const r = await restoreVaultContacts([null, { display_name: 'Legacy' }], async () => { throw 'a string, not an Error'; });
  assert.deepEqual(r.skipped, [{ label: 'Unnamed contact', reason: 'could not be saved' }, { label: 'Legacy', reason: 'could not be saved' }]);
});

// ── source pins ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
const strip = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const clientStore = strip(readFileSync(new URL('../identity/client-store.ts', import.meta.url), 'utf8'));
const restore = strip(readFileSync(new URL('../../components/recovery/vaultPassphraseRestore.ts', import.meta.url), 'utf8'));
const frontend = strip(readFileSync(new URL('../../components/SoverentityFrontend.tsx', import.meta.url), 'utf8'));
const mod = strip(readFileSync(new URL('./restore-report.ts', import.meta.url), 'utf8'));

test('PIN: the restore loop hands addContact the vault contact itself, and importVaultContents is only a wrapper that returns the fingerprint', () => {
  const rep = clientStore.slice(clientStore.indexOf('export async function importVaultContentsReport('), clientStore.indexOf('// ── Check if identity exists'));
  assert.match(rep, /restoreVaultContacts\(contacts, \(contact\) => addContact\(fp, contact\)\)/);
  assert.doesNotMatch(rep, /addContact\(fp, \{/);
  assert.match(clientStore, /return \(await importVaultContentsReport\(contents, fingerprint\)\)\.fingerprint;/);
  assert.match(rep, /setActiveFingerprint\(fp\);\s*return \{ fingerprint: fp, contacts: contactsReport \};/);
});

test('PIN: the restore adapter and the frontend use the report variant, and the owner is told through the same note as the plain-backup import', () => {
  assert.match(restore, /return importVaultContentsReport\(contents, derivedFp\);/);
  assert.match(restore, /return \(await restoreIdentityFromVaultReport\(contents, vaultPassphrase\)\)\.fingerprint;/);
  assert.match(frontend, /restoreIdentityFromVaultReport\(contents, vaultPassphrase\)/);
  assert.match(frontend, /formatVaultRestoreReport\(restored\.contacts\)/);
  assert.match(frontend, /if \(skippedNote\) setPlaintextImportNote\(skippedNote\);/);
});

test('PIN: the module projects nothing (no spread of the contact) and still logs the skip for the console', () => {
  assert.doesNotMatch(mod, /\.\.\.\s*contact\b/);
  assert.match(mod, /console\.warn\('\[restore\] skipped a contact that failed to persist:'/);
  assert.match(mod, /await add\(contact as never\);/);
});

test('PIN: the PAGE holds the note and gives it to BOTH mounts of the component; the tab SHOWS the page note (no copy of its own), the gate keeps its own, and every change is reported up', () => {
  const page = strip(readFileSync(new URL('../../../app/page.tsx', import.meta.url), 'utf8'));
  assert.match(page, /const \[importNote, setImportNote\] = useState<string \| null>\(null\);/);
  assert.equal((page.match(/importNote=\{importNote\}/g) ?? []).length, 2, 'both mounts');
  assert.equal((page.match(/onImportNoteChange=\{setImportNote\}/g) ?? []).length, 2, 'both mounts');
  assert.match(frontend, /const plaintextImportNote = onImportNoteChange && existingIdentity \? \(importNote \?\? null\) : localImportNote;/);
  assert.match(frontend, /setLocalImportNote\(note\);\s*onImportNoteChange\?\.\(note\);/);
});

test('PIN: the page drops the note when the identity becomes null (every lock path, and every switch, which goes through the locked screen) or changes to another, and not when it first appears', () => {
  const page = strip(readFileSync(new URL('../../../app/page.tsx', import.meta.url), 'utf8'));
  assert.match(page, /const noteIdentityFp: string \| null = identity\?\.identity\?\.fingerprint \?\? null;/);
  assert.match(page, /if \(previous !== null && previous !== noteIdentityFp\) setImportNote\(null\);/);
  assert.match(page, /\}, \[noteIdentityFp\]\);/);
});

test('PIN: the note is memory only: it never reaches localStorage, sessionStorage or the database', () => {
  const page = strip(readFileSync(new URL('../../../app/page.tsx', import.meta.url), 'utf8'));
  for (const src of [page, frontend]) {
    assert.doesNotMatch(src, /(local|session)Storage\.\w+\([^)]*(importNote|ImportNote)/);
    assert.doesNotMatch(src, /(storeIdentity|txPut|setSetting|saveLocalMethods)\([^)]*(importNote|ImportNote)/);
  }
});

test('PIN: a real-browser spec drives the whole restore and asserts the note on the screen (the source pins above cannot see a remount)', () => {
  const spec = readFileSync(new URL('../../../e2e/vault-restore-report.spec.ts', import.meta.url), 'utf8');
  assert.match(spec, /getByTestId\('plaintext-import-note'\)/);
  assert.match(spec, /toBeVisible\(\{ timeout: 10_000 \}\)/);
  assert.match(spec, /1 of 3 contacts from the backup are on this device\./);
  assert.match(spec, /after a lock and unlock the note is gone/);
  assert.match(spec, /switching to another identity on the same device shows no note/);
});
