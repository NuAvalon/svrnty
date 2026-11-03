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

test('adoption: stores the decided string, keeps every other field, and sees the HELD record', () => {
  const held = rec({ metadata: { note: 'keep' } });
  let seen: ContactRecord | null = null;
  const next = buildPsiEpochAdoption(held, (e) => { seen = e; return 'new-form'; });
  assert.equal(seen, held);
  assert.deepEqual(next, { ...held, psi_epoch: 'new-form' });
  assert.equal(PSI_EPOCH_FIELD in held, false, 'the input is not mutated');
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
const ALLOWED_TO_NAME_THE_FIELD = new Set(['src/lib/identity/client-store.ts']);
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
  assert.ok(hits.includes('src/lib/identity/client-store.ts'), 'the scan found the store (a scan that finds nothing proves nothing)');
});
