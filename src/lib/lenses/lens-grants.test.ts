// src/lib/lenses/lens-grants.test.ts — contract R1 (separate device-local store) + R2 (fail-closed).
// Run: npx tsx --test src/lib/lenses/lens-grants.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  acceptInSeq,
  lensForRecipient,
  lensGrantKey,
  loadLensGrants,
  markPeerCapable,
  nextLensSeq,
  peerIsCapable,
  saveLensGrants,
  setRecipientLens,
  type LensGrantBook,
} from './lens-grants';

const OWNER = 'c'.repeat(64);
const FP_A = 'a'.repeat(64);
const FP_B = 'b'.repeat(64);

function memStorage(): { getItem(k: string): string | null; setItem(k: string, v: string): void; map: Map<string, string> } {
  const map = new Map<string, string>();
  return { getItem: (k) => map.get(k) ?? null, setItem: (k, v) => void map.set(k, v), map };
}

const emptyBook = (): LensGrantBook => ({ v: 1, grants: {} });

test('R1: the grant book lives under its own namespaced key — never on a contact record', () => {
  const s = memStorage();
  let book = emptyBook();
  book = setRecipientLens(book, FP_A, 'lens-work');
  saveLensGrants(OWNER, book, s);
  // The store key is namespaced to the owner — and the record is keyed by CONTACT fp, not a contact row.
  const keys = [...s.map.keys()];
  assert.equal(keys.length, 1);
  assert.match(keys[0], /^svrnty\.lens-grants\.c{64}$/);
  const back = loadLensGrants(OWNER, s);
  assert.equal(lensForRecipient(back, FP_A), 'lens-work');
});

test('R1: exportAll cannot include the record — client-store never references the grants store (source guard)', () => {
  // The R1 boundary is STRUCTURAL: the grant record rides no payload/card/log/relay and lives in a
  // store exportAll does not read. Pin it: the export path must not import or name the grants store.
  const dir = fileURLToPath(new URL('.', import.meta.url));
  const clientStore = readFileSync(`${dir}/../identity/client-store.ts`, 'utf8');
  assert.equal(clientStore.includes('lens-grants'), false, 'exportAll must never read the lens-grants store');
  assert.equal(clientStore.includes('svrnty.lens-grants'), false);
  const grantSrc = readFileSync(`${dir}/lens-grants.ts`, 'utf8');
  // And the grants module itself never touches contact records or a fetch (no path to the wire).
  assert.equal(grantSrc.includes('fetch('), false);
  assert.equal(/getAllContacts|updateContact|addContact/.test(grantSrc), false);
});

test('R2: corrupt or unreadable records read as EMPTY — identical to no record', () => {
  const s = memStorage();
  s.map.set(lensGrantKey(OWNER), '{not json');
  assert.deepEqual(loadLensGrants(OWNER, s), { v: 1, grants: {}, inSeq: {} });
  s.map.set(lensGrantKey(OWNER), '{"v":2,"grants":{}}'); // wrong version
  assert.deepEqual(loadLensGrants(OWNER, s).grants, {});
  s.map.set(lensGrantKey(OWNER), '{"v":1,"grants":{"not-a-fp":{"lens":"x"},"' + FP_A + '":{"lens":17}}}');
  const back = loadLensGrants(OWNER, s);
  assert.equal(lensForRecipient(back, FP_A), null); // non-canonical key and junk row both dropped
  assert.equal(lensForRecipient(back, 'not-a-fp'), null);
  // A throwing storage never propagates.
  const hostile = { getItem: () => { throw new Error('io'); }, setItem: () => {} };
  assert.deepEqual(loadLensGrants(OWNER, hostile).grants, {});
});

test('R2: lensForRecipient returns null with no record — the caller then gives the narrowest face', () => {
  const book = emptyBook();
  assert.equal(lensForRecipient(book, FP_B), null);
});

test('grants: set → read → clear; seq bumps monotonically; capability marks', () => {
  let book = setRecipientLens(emptyBook(), FP_A, 'lens-friends');
  assert.equal(lensForRecipient(book, FP_A), 'lens-friends');
  book = setRecipientLens(book, FP_A, null);
  assert.equal(lensForRecipient(book, FP_A), null);
  const n1 = nextLensSeq(book, FP_A);
  const n2 = nextLensSeq(n1.book, FP_A);
  assert.equal(n1.seq, 1);
  assert.equal(n2.seq, 2);
  assert.equal(peerIsCapable(n2.book, FP_A), false);
  const capable = markPeerCapable(n2.book, FP_A);
  assert.equal(peerIsCapable(capable, FP_A), true);
});

test('receive floor: acceptInSeq accepts only strictly-greater seqs (replay/stale refused)', () => {
  let book = emptyBook();
  const a1 = acceptInSeq(book, FP_A, 5);
  assert.notEqual(a1, null);
  assert.equal(acceptInSeq(a1!, FP_A, 5), null); // replay
  assert.equal(acceptInSeq(a1!, FP_A, 4), null); // stale
  const a2 = acceptInSeq(a1!, FP_A, 6);
  assert.notEqual(a2, null);
  // A different sender's floor is independent.
  assert.notEqual(acceptInSeq(a2!, FP_B, 1), null);
  assert.equal(acceptInSeq(a2!, FP_A, -1), null);
});
