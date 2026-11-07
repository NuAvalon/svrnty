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
import { ContactBookTooLarge, MAX_FILE_CHARS, contactBookEntries, importContactBook, importMessage, toImportedContact } from './book-import';

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
    if (rows.some((x) => x.fingerprint === r.fingerprint)) return; // the unique index over the raw string: the existing record wins
    rows.push({ ...r });
  };
  /** What the dialog does: look first, then add (which checks the binding), and say whether the book already had it. */
  const addLikeDialog = async (c: unknown): Promise<'added' | 'existing'> => {
    const before = rows.some((x) => x.fingerprint === (c as { fingerprint: string }).fingerprint);
    await add(c);
    return before ? 'existing' : 'added';
  };
  return { rows, add, addLikeDialog };
}

const ALLOWED = ['name', 'email', 'fingerprint', 'public_key', 'pq_kem_public_key', 'pq_sig_public_key', 'trust_level'].sort();

test('ROUND TRIP: an export of two canonical contacts imports whole, binding intact, post-quantum keys carried', async () => {
  const text = toContactBookJson([ann, bob], '2026-01-02T03:04:05.000Z');
  const s = store();
  const summary = await importContactBook(contactBookEntries(text), s.add);
  assert.deepEqual({ total: summary.total, added: summary.added, existing: summary.existing, failed: summary.failed.length }, { total: 2, added: 2, existing: 0, failed: 0 });
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
  assert.equal(summary.added, 2);
  assert.deepEqual(summary.failed, [{ label: 'bob', reason: 'its key does not match its fingerprint' }]);
  assert.deepEqual(s.rows.map((r) => r.fingerprint), [ann.fingerprint, mallory.fingerprint]);
  assert.equal(importMessage(summary), 'Added 2, already in your contacts 0, not imported 1 of 3. Not imported: bob (its key does not match its fingerprint).');
});

test('NEG (a): a crafted file that says trusted, with an owner_verify stamp and a VALID binding, imports as UNVERIFIED with no stamp', async () => {
  const crafted = { ...toImportedContact(mallory)!, name: 'Mom', trust_level: 'trusted', metadata: { owner_verify: { owner_verified_at: '2026-01-01T00:00:00.000Z' }, connection_method: 'in_person' } };
  // CONTROL: handed to the store as it used to be (verbatim), this file WOULD have created a trusted contact. The test is about the import, not the store.
  const verbatim = store();
  await verbatim.add(crafted);
  assert.equal(verbatim.rows[0].trust_level, 'trusted', 'control: the old pass-through creates a trusted contact from this file');

  const s = store();
  const summary = await importContactBook(contactBookEntries(JSON.stringify([crafted])), s.add);
  assert.equal(summary.added, 1);
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
  assert.equal(summary.added, 0);
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

test('PIN: the import handler goes through importContactBook, hands addContact only the contact it was given, and never reads the file\'s fields itself', () => {
  const start = ui.indexOf('const handleImportContacts = async');
  assert.ok(start > 0);
  const body = ui.slice(start, ui.indexOf('const openEditDialog', start));
  assert.match(body, /importContactBook\(entries, async \(contact\) => \{/);
  assert.match(body, /await addContact\(fingerprint, contact\);/);
  assert.match(body, /getContactByFingerprint\(fingerprint, contact\.fingerprint\)/);
  assert.match(body, /return before \? 'existing' : 'added';/);
  assert.doesNotMatch(body, /\bc\.(trust_level|metadata)\b/);
  assert.doesNotMatch(body, /JSON\.parse/);
  assert.doesNotMatch(body, /addContact\(fingerprint, \{/);
});

// ── R1: a respelled fingerprint must not mint a second record for someone already in the book ───────────────────────────────────────────────────────
const colons = (fp: string) => fp.match(/.{2}/g)!.join(':');

test('R1 control: the store\'s binding check accepts a respelled fingerprint and its unique index is over the raw string, so handed verbatim it mints a SECOND record', async () => {
  for (const spelled of [bob.fingerprint.toUpperCase(), bob.fingerprint.slice(0, 40), colons(bob.fingerprint)]) {
    const s = store();
    await s.add({ ...toImportedContact(bob)!, blocked: true }); // the person is already in the book, blocked
    await s.add({ ...toImportedContact(bob)!, fingerprint: spelled });
    assert.equal(s.rows.length, 2, `control: ${spelled.length}-char respelling creates a second record`);
  }
});

test('R1 NEG: a blocked contact\'s real keys under an UPPERCASED, shortened or punctuated fingerprint are refused and named; still exactly ONE record, still blocked', async () => {
  const fp = bob.fingerprint;
  for (const spelled of [fp.toUpperCase(), fp.slice(0, 40), fp.slice(0, 16), colons(fp), `${fp} `, `${fp}:`, `${fp}\n`, ` ${fp}`, `${fp}00`, `0${fp}`]) {
    const s = store();
    await s.add({ ...toImportedContact(bob)!, blocked: true });
    const entry = { ...bob, fingerprint: spelled };
    const summary = await importContactBook([entry], s.addLikeDialog);
    assert.deepEqual(summary.failed, [{ label: 'bob', reason: 'its fingerprint is not in the standard form' }]);
    assert.equal(summary.added + summary.existing, 0);
    assert.equal(s.rows.length, 1, 'no second record');
    assert.equal(s.rows[0].blocked, true, 'still blocked');
  }
});

test('R1 NEG: a canonical re-import of a blocked contact returns the existing record (counted as already there), unchanged and still blocked', async () => {
  const s = store();
  await s.add({ ...toImportedContact(bob)!, blocked: true });
  const summary = await importContactBook([bob], s.addLikeDialog);
  assert.deepEqual({ added: summary.added, existing: summary.existing, failed: summary.failed.length }, { added: 0, existing: 1, failed: 0 });
  assert.equal(s.rows.length, 1);
  assert.equal(s.rows[0].blocked, true);
  assert.equal(importMessage(summary), 'Added 0, already in your contacts 1.');
});

test('the standard form is what our own export writes: lowercase 64-hex', () => {
  for (const c of [ann, bob, mallory]) assert.match(c.fingerprint, /^[0-9a-f]{64}$/);
});

// ── size and text bounds ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
test('SIZE: a file with more than 5,000 contacts is refused whole, with nothing tried; exactly 5,000 is not refused', async () => {
  let tried = 0;
  const add = async () => { tried++; };
  const over = await importContactBook(Array.from({ length: 5001 }, () => ({})), add);
  assert.equal(over.refused, 'That file has more than 5,000 contacts, so nothing was imported.');
  assert.equal(importMessage(over), over.refused);
  assert.equal(tried, 0);
  assert.deepEqual({ added: over.added, existing: over.existing, failed: over.failed.length }, { added: 0, existing: 0, failed: 0 });
  const exact = await importContactBook(Array.from({ length: 5000 }, () => ({})), add);
  assert.equal(exact.refused, undefined);
  assert.equal(exact.failed.length, 5000);
});

test('SIZE: a contact with an oversized key is refused before the store is asked (the binding check is the expensive part)', async () => {
  let tried = 0;
  for (const field of ['public_key', 'pq_kem_public_key', 'pq_sig_public_key']) {
    const summary = await importContactBook([{ ...toImportedContact(ann)!, [field]: 'A'.repeat(16385) }], async () => { tried++; });
    assert.deepEqual(summary.failed, [{ label: 'ann', reason: 'it has a key that is too long' }], field);
  }
  assert.equal(tried, 0);
});

test('TEXT: the STORED name and email are cleaned and capped like the shown label: no control characters, name at most 120, email at most 254', async () => {
  const s = store();
  await importContactBook([{ ...toImportedContact(ann)!, name: `A\u0007\u0000b\n${'x'.repeat(1_000_000)}`, email: `e\u0007${'y'.repeat(5000)}@t.test` }], s.add);
  const row = s.rows[0] as { name: string; email: string };
  assert.ok(row.name.length <= 120 && row.name.startsWith('A b x'));
  assert.ok(!/[\u0000-\u001f\u007f-\u009f]/.test(row.name + row.email));
  assert.ok(row.email.length <= 254);
});

test('COUNTS: a book that already has some of the contacts says so, and says it even when nothing failed', async () => {
  const s = store();
  await s.add({ ...toImportedContact(ann)! });
  const summary = await importContactBook([ann, bob], s.addLikeDialog);
  assert.deepEqual({ added: summary.added, existing: summary.existing }, { added: 1, existing: 1 });
  assert.equal(importMessage(summary), 'Added 1, already in your contacts 1.');
  const clean = await importContactBook([mallory], store().addLikeDialog);
  assert.equal(importMessage(clean), null, 'every contact new and nothing failed: no message, the dialog closes');
});

// ── file size: refused before the parse ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
test('SIZE (text): text over 20,000,000 characters is refused BEFORE it is parsed, with the plain message; exactly 20,000,000 reaches the parser', () => {
  const over = 'x'.repeat(MAX_FILE_CHARS + 1); // not JSON: if the parser ran first this would be a SyntaxError
  assert.throws(() => contactBookEntries(over), (e) => e instanceof ContactBookTooLarge && !(e instanceof SyntaxError) && e.message === 'That file is too large to import.');
  assert.throws(() => contactBookEntries('x'.repeat(MAX_FILE_CHARS)), SyntaxError, 'at the cap the text is parsed (and is not JSON)');
  assert.equal(MAX_FILE_CHARS, 20_000_000);
});

test('SIZE (text): a normal book is unaffected, and the refusal does not look at the content', () => {
  assert.equal(contactBookEntries(toContactBookJson([ann, bob], '2026-01-02T03:04:05.000Z')).length, 2);
  assert.throws(() => contactBookEntries(`[${' '.repeat(MAX_FILE_CHARS)}]`), ContactBookTooLarge);
});

test('PIN: the import handler shows the too-large message itself, before the SyntaxError branch', () => {
  const start = ui.indexOf('const handleImportContacts = async');
  const body = ui.slice(start, ui.indexOf('const openEditDialog', start));
  const iLarge = body.indexOf('err instanceof ContactBookTooLarge');
  const iSyntax = body.indexOf('err instanceof SyntaxError');
  assert.ok(iLarge > 0 && iLarge < iSyntax, 'the too-large branch comes first');
  assert.match(body, /setImportError\(err\.message\);/);
});
