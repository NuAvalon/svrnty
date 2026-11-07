// A friend's epoch record (`psi_epoch`) is a secret held for them: it lives inside the encrypted contact body, is written by ONE function,
// and never leaves this device. This file pins each half of that.
// Run: npx tsx --test src/lib/identity/psi-epoch-field.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  mergeContactUpdate,
  withoutPsiEpoch,
  buildPsiEpochAdoption,
  buildContactUpdateIf,
  PSI_EPOCH_FIELD,
  type ContactRecord,
} from './client-store';
import { encryptContactRecord, decryptContactRecord } from './contact-crypto';
import { toContactBookJson, toSafeExportContact } from '../contacts/book-export';

const SENTINEL = 'sentinel-epoch-record-0f3a9c';
const rec = (extra: Record<string, unknown> = {}): ContactRecord =>
  ({
    id: 'c1', owner_fingerprint: 'o'.repeat(64), fingerprint: 'f'.repeat(64), name: 'Bob', email: 'b@x.test', public_key: 'PK',
    trust_level: 'unverified', added_at: '2026-01-01T00:00:00.000Z', ...extra,
  }) as ContactRecord;
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

// ── the field name, and the merge that can never touch it ───────────────────

test('the field is called psi_epoch', () => {
  assert.equal(PSI_EPOCH_FIELD, 'psi_epoch');
});

test('a patch cannot plant psi_epoch on a record that has none (object and function form)', () => {
  const existing = rec();
  assert.equal(PSI_EPOCH_FIELD in mergeContactUpdate(existing, { psi_epoch: SENTINEL, name: 'Bobby' }), false);
  const viaFn = mergeContactUpdate(existing, () => ({ psi_epoch: SENTINEL, name: 'Bobby' }));
  assert.equal(PSI_EPOCH_FIELD in viaFn, false);
  assert.equal(viaFn.name, 'Bobby', 'the rest of the patch still applies');
});

test('a patch cannot change or clear a held psi_epoch', () => {
  const existing = rec({ psi_epoch: 'held-form' });
  assert.equal(mergeContactUpdate(existing, { psi_epoch: SENTINEL }).psi_epoch, 'held-form');
  assert.equal(mergeContactUpdate(existing, { psi_epoch: undefined, name: 'X' }).psi_epoch, 'held-form');
  assert.equal(mergeContactUpdate(existing, { name: 'X' }).psi_epoch, 'held-form');
  assert.equal(mergeContactUpdate(existing, () => ({ psi_epoch: '' })).psi_epoch, 'held-form');
});

test('an imported card or backup row spread into a patch cannot carry one in', () => {
  const imported = { ...rec({ psi_epoch: SENTINEL }), name: 'From file' };
  const merged = mergeContactUpdate(rec(), imported);
  assert.equal(PSI_EPOCH_FIELD in merged, false);
  assert.equal(merged.name, 'From file');
});

test('withoutPsiEpoch drops the field, never mutates its input, and returns the same object when there is nothing to drop', () => {
  const a = rec({ psi_epoch: SENTINEL });
  const before = clone(a);
  const b = withoutPsiEpoch(a);
  assert.equal(PSI_EPOCH_FIELD in b, false);
  assert.deepEqual(a, before);
  const c = rec();
  assert.equal(withoutPsiEpoch(c), c);
});

// ── the one writer ──────────────────────────────────────────────────────────

test('adoption: stores the decided string and keeps every other field; the decision gets the HELD epoch record and the contact without that field', () => {
  const held = rec({ metadata: { note: 'keep' }, psi_epoch: 'held-form' });
  let seenEpoch: string | null | undefined;
  let seenContact: ContactRecord | undefined;
  const next = buildPsiEpochAdoption(held, (e, c) => { seenEpoch = e; seenContact = c; return 'new-form'; });
  assert.equal(seenEpoch, 'held-form');
  assert.equal(PSI_EPOCH_FIELD in (seenContact as ContactRecord), false, 'the contact view carries no epoch record');
  assert.equal((seenContact as ContactRecord).metadata.note, 'keep');
  assert.deepEqual(next, { ...held, psi_epoch: 'new-form' });
  assert.equal(held.psi_epoch, 'held-form', 'the input is not mutated');
});

test('adoption: with nothing held the decision is given null; an empty held string counts as nothing', () => {
  const seen: Array<string | null> = [];
  buildPsiEpochAdoption(rec(), (e) => { seen.push(e); return null; });
  buildPsiEpochAdoption(rec({ psi_epoch: '' }), (e) => { seen.push(e); return null; });
  assert.deepEqual(seen, [null, null]);
});

test('adoption: a decision of null writes nothing', () => {
  assert.equal(buildPsiEpochAdoption(rec(), () => null), null);
});

test('adoption: a BLOCKED contact is never written, by either flag, and the decision is not even asked', () => {
  for (const blocked of [rec({ blocked: true }), rec({ metadata: { blocked: true } })]) {
    let asked = false;
    assert.equal(buildPsiEpochAdoption(blocked, () => { asked = true; return 'x'; }), null);
    assert.equal(asked, false);
  }
});

test('adoption: a stored form that is not a non-empty string is a programming error, not a write', () => {
  for (const bad of ['', 5, {}, undefined]) {
    assert.throws(() => buildPsiEpochAdoption(rec(), () => bad as unknown as string), TypeError);
  }
});

// ── nobody outside the store can obtain it ──────────────────────────────────

test('R1: an updater (function form) is given the record WITHOUT psi_epoch, and the held value is still kept', () => {
  const existing = rec({ psi_epoch: 'held-form' });
  let seen: ContactRecord | undefined;
  const merged = mergeContactUpdate(existing, (fresh) => { seen = fresh; return { name: 'X' }; });
  assert.equal(PSI_EPOCH_FIELD in (seen as ContactRecord), false);
  assert.equal(merged.psi_epoch, 'held-form');
  assert.equal(merged.name, 'X');
});

test('R1: a read -> write round trip keeps the stored value: a reader\'s record (no psi_epoch) used as a patch changes nothing about it', () => {
  const stored = rec({ psi_epoch: 'held-form' });
  const asRead = withoutPsiEpoch(stored);
  const merged = mergeContactUpdate(stored, { ...asRead, name: 'Renamed' });
  assert.equal(merged.psi_epoch, 'held-form');
  assert.equal(merged.name, 'Renamed');
});

test('R1: the conditional update gives its decision the record without psi_epoch and keeps the held value; a null decision writes nothing', () => {
  const existing = rec({ psi_epoch: 'held-form' });
  let seen: ContactRecord | undefined;
  const next = buildContactUpdateIf(existing, (e) => { seen = e; return { name: 'Y' }; });
  assert.equal(PSI_EPOCH_FIELD in (seen as ContactRecord), false);
  assert.equal((next as ContactRecord).psi_epoch, 'held-form');
  assert.equal(buildContactUpdateIf(existing, () => null), null);
});

// ── at rest ─────────────────────────────────────────────────────────────────

test('at rest: the encrypted row has no psi_epoch key in the clear, and the ciphertext round-trips it', async () => {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const { id, owner_fingerprint, ...body } = rec({ psi_epoch: SENTINEL });
  const payload = await encryptContactRecord(key, id, owner_fingerprint, body);
  const stored = { id, owner_fingerprint, ...payload };
  assert.equal(PSI_EPOCH_FIELD in stored, false);
  assert.equal(JSON.stringify(stored).includes(SENTINEL), false, 'the value is not in the stored row');
  const back = await decryptContactRecord<Record<string, unknown>>(key, id, owner_fingerprint, payload);
  assert.equal(back.psi_epoch, SENTINEL);
});

// ── it never leaves the device ──────────────────────────────────────────────

test('the plaintext book exports are allowlist projections: a record holding psi_epoch exports none of it', () => {
  const r = rec({ psi_epoch: SENTINEL });
  assert.equal(JSON.stringify(toSafeExportContact(r)).includes(SENTINEL), false);
  assert.equal(toContactBookJson([r], '2026-11-03T00:00:00.000Z').includes(SENTINEL), false);
});

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');
function fnBody(src: string, signature: string): string {
  const start = src.indexOf(signature);
  assert.ok(start >= 0, `${signature} not found`);
  const next = src.indexOf('\nexport ', start + 1);
  const priv = src.indexOf('\nasync function ', start + 1);
  return src.slice(start, Math.min(next === -1 ? src.length : next, priv === -1 ? src.length : priv));
}

test('GUARD: exportAll (the vault and every backup) strips psi_epoch from each contact; addContact drops it; the unlock migration drops it', () => {
  const cs = read('./client-store.ts');
  assert.match(fnBody(cs, 'export async function exportAll('), /contacts: \(await getAllContacts\(fingerprint\)\)\.map\(withoutPsiEpoch\)/);
  const add = fnBody(cs, 'export async function addContact(');
  const dropAt = add.indexOf('delete record[PSI_EPOCH_FIELD]');
  const buildAt = add.indexOf('await buildStoredContact(record)');
  assert.ok(dropAt > 0 && buildAt > dropAt, 'the drop runs before the record is encrypted and stored');
  assert.match(cs, /buildStoredContact\(withoutPsiEpoch\(rec\) as unknown as ContactRecord\)/);
  assert.match(fnBody(cs, 'export function mergeContactUpdate('), /PSI_EPOCH_FIELD in existing/);
});

test('GUARD: every public reader of decrypted contacts strips psi_epoch (the CAS keeps its own full decrypt)', () => {
  const cs = read('./client-store.ts');
  assert.match(fnBody(cs, 'export async function getContact('), /return rec \? withoutPsiEpoch\(await decryptContactIfNeeded\(rec\)\) : null;/);
  assert.match(fnBody(cs, 'export async function getContactByFingerprint('), /return found \? withoutPsiEpoch\(await decryptContactIfNeeded\(found\)\) : null;/);
  assert.match(fnBody(cs, 'export async function getAllContacts('), /withoutPsiEpoch\(await decryptContactIfNeeded\(r\)\)/);
  assert.match(cs, /decrypt: \(raw\) => decryptContactIfNeeded\(raw\),/, 'the compare-and-swap decrypts in full, so the held value survives a write');
  assert.match(fnBody(cs, 'export function mergeContactUpdate('), /updates\(withoutPsiEpoch\(existing\)\)/);
  assert.match(fnBody(cs, 'export function buildContactUpdateIf('), /decide\(withoutPsiEpoch\(existing\)\)/);
  assert.match(fnBody(cs, 'export async function updateContactIf('), /buildContactUpdateIf\(existing, decide\)/);
  // Every other exported function in the store that returns decrypted contacts goes through one of the readers above.
  const exportsReturningContacts = [...cs.matchAll(/export async function (\w+)\([^)]*\): Promise<(?:ContactRecord(?:\[\])?|ContactRecord \| null)>/g)].map((m) => m[1]).sort();
  assert.deepEqual(exportsReturningContacts, ['addContact', 'getAllContacts', 'getContact', 'getContactByFingerprint', 'searchContacts'], 'a new exported reader of contacts must strip psi_epoch and be added here');
  assert.match(fnBody(cs, 'export async function searchContacts('), /await getAllContacts\(ownerFingerprint\)/);
});

test('GUARD: the vault export builds its contacts from exportAll, nothing else', () => {
  const dlg = read('../../components/export/VaultExportDialog.tsx');
  assert.match(dlg, /await exportAll\(fingerprint, true\)/);
  assert.match(dlg, /contacts: backup\.contacts,/);
});

test('GUARD: the restore and import paths put contacts through addContact, which drops psi_epoch', () => {
  const cs = read('./client-store.ts');
  assert.match(fnBody(cs, 'export async function importPlaintextContacts('), /await addContact\(ownerFingerprint, contactFromPlaintextBackup\(contact\)\)/);
  const vaultImport = fnBody(cs, 'export async function importVaultContents(');
  assert.match(vaultImport, /addContact\(/);
  assert.doesNotMatch(vaultImport, /txPut\('contacts'/, 'no raw contact write on the restore path');
});

// The only source file that may name the field is the store itself. Adding a reader (the receive path) is a deliberate edit of this list; an
// outbound builder (an introduction, a signed card, a deposit, any export) appearing here is a failure.
// live-book-poll.ts names the store's WRITER (adoptPsiEpoch) once, to hand it to the epoch seam; it never names the field itself.
const ALLOWED_TO_NAME_THE_FIELD = new Set(['src/lib/identity/client-store.ts', 'src/lib/sync/live-book-poll.ts']);
function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (name === 'node_modules' || name === '.next') continue;
      sourceFiles(p, out);
    } else if (/\.(ts|tsx)$/.test(name) && !/\.test\.(ts|tsx)$/.test(name)) out.push(p);
  }
  return out;
}

test('GUARD: only the store names psi_epoch or PSI_EPOCH_FIELD in non-test source (no outbound builder reads it, nothing else writes it)', () => {
  const root = new URL('../../../', import.meta.url).pathname;
  const hits: string[] = [];
  for (const dir of ['src', 'app', 'scripts']) {
    let files: string[] = [];
    try { files = sourceFiles(join(root, dir)); } catch { continue; }
    for (const f of files) {
      const text = readFileSync(f, 'utf8');
      if (/psi_epoch|PSI_EPOCH_FIELD|adoptPsiEpoch|buildPsiEpochAdoption/.test(text)) hits.push(f.slice(root.length));
    }
  }
  assert.deepEqual(hits.filter((h) => !ALLOWED_TO_NAME_THE_FIELD.has(h)), [], 'a file other than the store names the epoch field');
  const lbp = readFileSync(join(root, 'src/lib/sync/live-book-poll.ts'), 'utf8').replace(/^\s*(\/\/|\*|\/\*).*$/gm, '');
  assert.doesNotMatch(lbp, /psi_epoch|PSI_EPOCH_FIELD/, 'the poll hands over the writer but never names the field');
  assert.ok(hits.includes('src/lib/identity/client-store.ts'), 'the scan found the store (a scan that finds nothing proves nothing)');
});
