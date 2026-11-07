// src/lib/contacts/book-import.test.ts
// The .json contact-book IMPORT. A file is an untrusted input, so an import carries identity and nothing else: every contact lands 'unverified',
// nothing about trust / verification / blocking / sync state is read from the file, and the store's own binding and verify-before-trust gates stay as
// strict as they are. The store here is a stand-in that runs the REAL fingerprintMatchesKey and the REAL ownerHasVerified in the same order addContact does.
// Run: npx tsx --test src/lib/contacts/book-import.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { fingerprintMatchesKey, mintCanonicalFingerprint } from '@/lib/identity/fingerprint';
import { generatePQKeypairBundle, uint8ToBase64 } from '@/lib/crypto/pq';
import { ownerHasVerified } from '@/lib/trust/trust-recipe';
import type { ContactRecord } from '@/lib/identity/client-store';
import { toContactBookJson } from './book-export';
import { contactBookEntries, importContactBook, importMessage, toImportedContact } from './book-import';

async function identity(name: string): Promise<ContactRecord> {
  const passphrase = `pw-${name}`;
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'ed25519Legacy', userIDs: [{ name, email: `${name}@t.test` }], passphrase, format: 'armored' });
  const decrypted = await decryptKey({ privateKey: await readPrivateKey({ armoredKey: privateKey }), passphrase });
  const pq = generatePQKeypairBundle();
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: decrypted, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  return {
    id: `c-${name}`, owner_fingerprint: 'owner', fingerprint, name, email: `${name}@t.test`, public_key: publicKey, trust_level: 'unverified', added_at: '2026-01-01T00:00:00.000Z',
    pq_kem_public_key: uint8ToBase64(pq.kem.publicKey), pq_sig_public_key: uint8ToBase64(pq.signing.publicKey),
  } as ContactRecord;
}

let ann: ContactRecord;
let bob: ContactRecord;
let mallory: ContactRecord;
before(async () => {
  [ann, bob, mallory] = [await identity('ann'), await identity('bob'), await identity('mallory')];
});

/** What addContact does with what it is handed, in its order: the binding check, then the verify-before-trust gate on a trusted create. */
function store() {
  const rows: Array<Record<string, unknown>> = [];
  const add = async (c: unknown) => {
    const r = c as Record<string, string | boolean | undefined>;
    if (!(await fingerprintMatchesKey(r.fingerprint as string, r.public_key as string, { kem_public_key: r.pq_kem_public_key as string | undefined, sig_public_key: r.pq_sig_public_key as string | undefined }))) {
      throw new Error('fingerprint↔key binding failed — refusing to store a contact whose fingerprint does not match its public key');
    }
    const trusted = r.trust_level === 'trusted' || r.trust_level === 'verified' || r.trusted === true;
    if (trusted && !ownerHasVerified(r as Parameters<typeof ownerHasVerified>[0])) throw new Error('verify-before-trust: refusing to create a trusted contact without owner verification');
    rows.push({ ...r });
  };
  return { rows, add };
}

const ALLOWED = ['name', 'email', 'fingerprint', 'public_key', 'pq_kem_public_key', 'pq_sig_public_key', 'trust_level'].sort();

test('ROUND TRIP: an export of two canonical contacts imports whole, binding intact, post-quantum keys carried', async () => {
  const text = toContactBookJson([ann, bob], '2026-01-02T03:04:05.000Z');
  const s = store();
  const summary = await importContactBook(contactBookEntries(text), s.add);
  assert.deepEqual({ total: summary.total, imported: summary.imported, failed: summary.failed.length }, { total: 2, imported: 2, failed: 0 });
  assert.equal(importMessage(summary), null);
  assert.deepEqual(s.rows.map((r) => r.fingerprint), [ann.fingerprint, bob.fingerprint]);
  assert.deepEqual(s.rows.map((r) => r.pq_kem_public_key), [ann.pq_kem_public_key, bob.pq_kem_public_key]);
  assert.deepEqual(s.rows.map((r) => r.pq_sig_public_key), [ann.pq_sig_public_key, bob.pq_sig_public_key]);
});

test('CONTROL: the stand-in store refuses what the real one refuses (a contact missing its post-quantum keys has no valid binding)', async () => {
  const s = store();
  await assert.rejects(s.add({ name: 'ann', email: '', fingerprint: ann.fingerprint, public_key: ann.public_key, trust_level: 'unverified' }), /binding failed/);
});

test('NEG (c)+(d): one corrupted contact is refused and NAMED, the others are still imported, and the binding gate is exactly as strict as before', async () => {
  const corrupted = { ...toImportedContact(bob)!, pq_kem_public_key: ann.pq_kem_public_key }; // bob's fingerprint with ann's kem key
  const text = JSON.stringify({ contacts: [ann, corrupted, mallory] });
  const s = store();
  const summary = await importContactBook(contactBookEntries(text), s.add);
  assert.equal(summary.imported, 2);
  assert.deepEqual(summary.failed, [{ label: 'bob', reason: 'its key does not match its fingerprint' }]);
  assert.deepEqual(s.rows.map((r) => r.fingerprint), [ann.fingerprint, mallory.fingerprint]);
  assert.equal(importMessage(summary), 'Imported 2 of 3. Not imported: bob (its key does not match its fingerprint).');
});

test('NEG (a): a crafted file that says trusted, with an owner_verify stamp and a VALID binding, imports as UNVERIFIED with no stamp', async () => {
  const crafted = { ...toImportedContact(mallory)!, name: 'Mom', trust_level: 'trusted', metadata: { owner_verify: { owner_verified_at: '2026-01-01T00:00:00.000Z' }, connection_method: 'in_person' } };
  // CONTROL: handed to the store as it used to be (verbatim), this file WOULD have created a trusted contact. The test is about the import, not the store.
  const verbatim = store();
  await verbatim.add(crafted);
  assert.equal(verbatim.rows[0].trust_level, 'trusted', 'control: the old pass-through creates a trusted contact from this file');

  const s = store();
  const summary = await importContactBook(contactBookEntries(JSON.stringify([crafted])), s.add);
  assert.equal(summary.imported, 1);
  assert.equal(s.rows[0].trust_level, 'unverified');
  assert.equal(s.rows[0].name, 'Mom');
  assert.equal('metadata' in s.rows[0], false);
  assert.equal(JSON.stringify(s.rows[0]).includes('owner_verif'), false);
});

test('NEG (b): trust_level "verified", a top-level verification block, owner_verify, trusted, blocked, psi_epoch, epoch, version, tags and notes are all ignored; only the named fields reach the store', async () => {
  const hostile = {
    ...toImportedContact(ann)!,
    trust_level: 'verified', trusted: true, blocked: true, tags: ['x'], notes: 'n', epoch: 99, version: 99, psi_epoch: 'AAAA', last_interaction: '2026-01-01',
    verification: { method: 'in_person', verified_at: '2026-01-01T00:00:00.000Z' },
    owner_verify: { owner_verified_at: '2026-01-01T00:00:00.000Z' },
    metadata: { verification: { method: 'in_person', verified_at: '2026-01-01T00:00:00.000Z' } },
  };
  const s = store();
  await importContactBook(contactBookEntries(JSON.stringify({ contacts: [hostile] })), s.add);
  assert.equal(s.rows.length, 1);
  assert.deepEqual(Object.keys(s.rows[0]).sort(), ALLOWED);
  assert.equal(s.rows[0].trust_level, 'unverified');
});

test('an entry without a fingerprint and a key, or that is not an object, is counted and named, not silently skipped', async () => {
  const s = store();
  const summary = await importContactBook([{ name: 'No key', fingerprint: 'abc' }, null, 5, { display_name: 'Legacy name only' }], s.add);
  assert.equal(summary.imported, 0);
  assert.equal(summary.failed.length, 4);
  assert.equal(summary.failed[0].label, 'No key');
  assert.equal(summary.failed[3].label, 'Legacy name only');
  assert.equal(s.rows.length, 0);
});

test('names from the file are made safe to show: control characters removed, long names cut, and at most five are listed', async () => {
  const entries = Array.from({ length: 7 }, (_, i) => ({ name: `n${i}\u0007\n${'x'.repeat(100)}` }));
  const summary = await importContactBook(entries, async () => {});
  const msg = importMessage(summary) as string;
  assert.ok(!/[\u0000-\u001f]/.test(msg));
  assert.ok(msg.endsWith('; and 2 more.'));
  assert.equal(msg.split(';').length - 1, 5, 'five listed, then the "and N more" part');
  assert.ok(summary.failed[0].label.length <= 61);
});

test('the file formats: the export\'s { contacts: [...] }, a bare array, and anything else is an empty list; text that is not JSON throws SyntaxError', () => {
  assert.equal(contactBookEntries('{"contacts":[{"a":1}]}').length, 1);
  assert.equal(contactBookEntries('[{"a":1},{"b":2}]').length, 2);
  assert.equal(contactBookEntries('{"contacts":"x"}').length, 0);
  assert.equal(contactBookEntries('null').length, 0);
  assert.throws(() => contactBookEntries('not json'), SyntaxError);
});

test('a failing store with an unexpected error is counted with plain words, and the raw error text is never shown', async () => {
  const summary = await importContactBook([toImportedContact(ann)], async () => { throw new Error('IDB: secret internal detail'); });
  assert.deepEqual(summary.failed, [{ label: 'ann', reason: 'could not be saved' }]);
  assert.equal((importMessage(summary) as string).includes('secret'), false);
});

// ── source pins: the shape cannot quietly come back ─────────────────────────────────────────────────────────────────────────────────────────────────
const strip = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const mod = strip(readFileSync(new URL('./book-import.ts', import.meta.url), 'utf8'));
const ui = strip(readFileSync(new URL('../../components/ContactManagement.tsx', import.meta.url), 'utf8'));

test('PIN: the module builds the contact field by field (no spread of the file entry) and reads no trust or metadata from it', () => {
  assert.doesNotMatch(mod, /\.\.\.\s*(c|entry)\b/);
  assert.doesNotMatch(mod, /c\.(trust_level|metadata|trusted|verification|owner_verify|epoch|version|psi_epoch|blocked)\b/);
  assert.match(mod, /trust_level: 'unverified',/);
});

test('PIN: the import handler goes through importContactBook and never hands the file\'s fields to addContact itself', () => {
  const start = ui.indexOf('const handleImportContacts = async');
  assert.ok(start > 0);
  const body = ui.slice(start, ui.indexOf('const openEditDialog', start));
  assert.match(body, /importContactBook\(entries, \(contact\) => addContact\(fingerprint, contact\)\)/);
  assert.doesNotMatch(body, /\bc\.(trust_level|metadata)\b/);
  assert.doesNotMatch(body, /JSON\.parse/);
});
