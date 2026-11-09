// src/lib/identity/delivery-restore-marks.test.ts
// Run: npx tsx --test src/lib/identity/delivery-restore-marks.test.ts
// Task #714 R2a. The Delivery-receipt choice is unknown after a RESTORE (the owner is asked once, nothing goes out until they answer), while an
// identity that already lived on this device keeps sending (an absent record is migrated to On). So every code path that puts an identity on this
// device must be classified, and every restore must mark. AXIS (named so it can be falsified): every non-test source file under src/ and app/ that
// calls `storeIdentity(`. A new caller fails S1 until someone decides which kind it is.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { contactFromPlaintextBackup, type ContactRecord } from './client-store';

const ROOT = join(new URL('../../..', import.meta.url).pathname);
function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    if (n === 'node_modules' || n === '.next') continue;
    const p = join(dir, n);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (/\.(ts|tsx)$/.test(n) && !/\.test\.tsx?$/.test(n) && !/\.d\.ts$/.test(n)) out.push(p);
  }
  return out;
}
const SRC = [...walk(join(ROOT, 'src')), ...walk(join(ROOT, 'app'))];
const read = (rel: string) => readFileSync(join(ROOT, rel), 'utf8');
const MARKS = /markDeliveryRestored\(|markDeliveryDefaultUnknown\(|writeDeliveryDefaultIfAbsent\(/g;
const count = (rel: string) => (read(rel).match(MARKS) ?? []).length;

// kind: 'restore' = brings an identity in from outside (must mark); 'genesis' = a brand-new identity (default On is right); 'update' = rewrites an
// identity that is already here; 'other' = not the browser store (a different class, or demo data).
const CLASSIFIED: Record<string, 'restore' | 'genesis' | 'update' | 'other'> = {
  'src/lib/identity/client-store.ts': 'restore', // importAll, importVaultContentsReport (+ the definition)
  'src/lib/identity/browser-identity.ts': 'restore', // generateIdentity (genesis) AND importIdentity (restore): checked in S2
  'src/components/recovery/seedVaultRestore.ts': 'restore',
  'src/components/SoverentityFrontend.tsx': 'restore', // three restore sites + one card_version bump (update)
  'src/lib/identity/core.ts': 'other', // its own private storeIdentity method on a separate legacy class
  'src/components/demo/seed-linked-demo.ts': 'other', // demo data
};

test('S1 (axis) every non-test file that calls storeIdentity( is classified, and every file classified as a restore marks', () => {
  const callers = SRC.map((f) => relative(ROOT, f)).filter((rel) => /\bstoreIdentity\(/.test(read(rel)));
  const unclassified = callers.filter((rel) => !(rel in CLASSIFIED));
  assert.deepEqual(unclassified, [], 'a NEW caller of storeIdentity: decide genesis / restore / update and add it to CLASSIFIED (a restore must mark)');
  for (const rel of callers) if (CLASSIFIED[rel] === 'restore') assert.ok(count(rel) > 0, `${rel} restores an identity but never marks the Delivery choice`);
});

test('S2 each restore entry point marks, by name', () => {
  const store = read('src/lib/identity/client-store.ts');
  const importAll = store.slice(store.indexOf('export async function importAll('), store.indexOf('export async function importAll(') + 3500);
  assert.match(importAll, /writeDeliveryDefaultIfAbsent\(/, 'importAll');
  const vault = store.slice(store.indexOf('export async function importVaultContentsReport('), store.indexOf('export async function importVaultContentsReport(') + 3500);
  assert.match(vault, /writeDeliveryDefaultIfAbsent\(/, 'importVaultContentsReport');
  assert.match(read('src/components/recovery/seedVaultRestore.ts'), /markDeliveryDefaultUnknown\(fingerprint\)/, 'seed-only restore');
  const bi = read('src/lib/identity/browser-identity.ts');
  const importIdentity = bi.slice(bi.indexOf('async importIdentity('), bi.indexOf('async importIdentity(') + 900);
  assert.match(importIdentity, /markDeliveryRestored\(/, 'importIdentity');
  const gen = bi.slice(bi.indexOf('async generateIdentity('), bi.indexOf('async loadIdentityData('));
  assert.doesNotMatch(gen, /markDelivery/, 'genesis must NOT mark: a new identity defaults to On');
  assert.equal((read('src/components/SoverentityFrontend.tsx').match(/markDeliveryRestored\(fp\)/g) ?? []).length, 3, 'the three restore sites in the frontend');
});

test('S3 a plaintext backup file may only TIGHTEN a contact: "off" is kept, "on" and anything else is dropped', () => {
  const base = { id: 'x', fingerprint: 'f', name: 'n', email: 'e', public_key: 'k' } as ContactRecord;
  assert.equal(contactFromPlaintextBackup({ ...base, delivery_receipts: 'off' }).delivery_receipts, 'off');
  for (const v of ['on', 'ON', '', null, 1, {}, undefined]) assert.equal('delivery_receipts' in contactFromPlaintextBackup({ ...base, delivery_receipts: v as never }), false, String(v));
});

test('S4 the migration is only-if-absent and reads the restored flag; a send never overwrites a marker or an answer', () => {
  const store = read('src/lib/identity/client-store.ts');
  const mig = store.slice(store.indexOf('export async function readDeliveryDefaultMigrating('), store.indexOf('export async function readDeliveryDefaultMigrating(') + 1400);
  assert.match(mig, /writeDeliveryDefaultIfAbsent\(/);
  assert.doesNotMatch(mig, /writeDeliveryDefault\(/, 'the migration must never use the overwriting write');
  assert.match(mig, /deliveryRestoredFlagKey/);
  assert.match(mig, /value: 'unknown'/);
  assert.match(mig, /value: 'on', notice_pending: true/);
});

test('S5 the send-time read uses the MIGRATING reader and the sealed record is not read from localStorage or the identity row', () => {
  assert.match(read('src/lib/sync/receipt-allowed.ts'), /readDeliveryDefaultMigrating/);
  const store = read('src/lib/identity/client-store.ts');
  const seg = store.slice(store.indexOf('// ── Delivery-receipt setting'), store.indexOf('export async function listIdentities('));
  const code = seg.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1'); // code only: the comments explain why not localStorage
  assert.doesNotMatch(code, /localStorage|sessionStorage/);
  assert.match(code, /encryptContactRecord\(/);
});

test('S6 the queued send\'s default decision is receiptAllowedNow (admitted AND the setting), not the bare admission check', () => {
  const poll = read('src/lib/sync/live-book-poll.ts');
  assert.match(poll, /deps\.isAdmittedNow \?\? \(\(fp: string\) => receiptAllowedNow\(owner\.fingerprint, fp\)\)/);
});
