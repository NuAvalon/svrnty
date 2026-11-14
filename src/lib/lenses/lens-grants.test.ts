// src/lib/lenses/lens-grants.test.ts — contract R1 (separate device-local store, sealed at rest)
// + R2 (fail-closed: no record ⇒ zero methods) + review-1 item 4 (seq floor) + item 6 (sealed book).
// Run: npx tsx --test src/lib/lenses/lens-grants.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  LENS_MAX_FUTURE_SEQ_S,
  acceptInSeq,
  lensForRecipient,
  lensGrantKey,
  lensSentKeys,
  loadLensGrants,
  helloDue,
  markHelloSent,
  markPeerCapable,
  nextLensSeq,
  peerIsCapable,
  recordLensKeys,
  saveLensGrants,
  setRecipientLens,
  type LensGrantBook,
} from './lens-grants';
import { lensMethodKey } from './lens-wire';

const OWNER = 'c'.repeat(64);
const FP_A = 'a'.repeat(64);
const FP_B = 'b'.repeat(64);

function memStorage(): { getItem(k: string): string | null; setItem(k: string, v: string): void; map: Map<string, string> } {
  const map = new Map<string, string>();
  return { getItem: (k) => map.get(k) ?? null, setItem: (k, v) => void map.set(k, v), map };
}

const emptyBook = (): LensGrantBook => ({ v: 1, grants: {} });
const NOW = 1_800_000_000; // fixed wall-clock seconds for deterministic seq tests

test('R1: the grant book round-trips through its own store — never on a contact record', async () => {
  const s = memStorage();
  let book = emptyBook();
  book = setRecipientLens(book, FP_A, 'lens-work');
  await saveLensGrants(OWNER, book, s);
  // The store key is namespaced to the owner — and the record is keyed by CONTACT fp, not a contact row.
  const keys = [...s.map.keys()];
  assert.equal(keys.length, 1);
  assert.match(keys[0], /^svrnty\.lens-grants\.c{64}$/);
  const back = await loadLensGrants(OWNER, s);
  assert.equal(lensForRecipient(back, FP_A), 'lens-work');
});

test('item 6: the grant book is SEALED at rest — never plaintext localStorage', async () => {
  // The production default is the client-store sealed record (AAD-bound, throws when locked).
  // Pin it: this module must never reach for localStorage again, and it must use the sealed path.
  const dir = fileURLToPath(new URL('.', import.meta.url));
  const grantSrc = readFileSync(`${dir}/lens-grants.ts`, 'utf8');
  assert.equal(grantSrc.includes('localStorage'), false, 'grant book must never touch localStorage');
  assert.match(grantSrc, /readLensGrantBook|writeLensGrantBook/, 'default store must be the sealed client-store record');
  const clientStore = readFileSync(`${dir}/../identity/client-store.ts`, 'utf8');
  // The sealed record itself: session-key guard on write (fail-closed, throws — never plaintext),
  // encryptContactRecord under a reserved id, the settings store exportAll never reads.
  assert.match(clientStore, /export async function readLensGrantBook\(/);
  const write = clientStore.slice(clientStore.indexOf('export async function writeLensGrantBook('));
  assert.match(write, /if \(!_sessionKey\) throw new Error\(/, 'write must throw when locked');
  assert.match(write, /encryptContactRecord\(_sessionKey, LENS_BOOK_RECORD_ID/, 'must seal via the AAD-bound contact-crypto path');
  const readFn = clientStore.slice(clientStore.indexOf('export async function readLensGrantBook('), clientStore.indexOf('export async function writeLensGrantBook('));
  // v1.10 B1/A4: only a GENUINELY ABSENT record may read as null — locked, decrypt/tag failure,
  // a non-string payload and a store error all THROW so the book reads unreadable, never empty.
  assert.match(readFn, /if \(!_sessionKey\) throw/, 'locked read must throw (unreadable), never read as empty');
  assert.match(readFn, /if \(!row\?\.value\) return null;/, 'only an absent record reads null');
  assert.equal(/catch \{\s*return null;?\s*\}/.test(readFn), false, 'no catch-and-null — a failure is unreadable, not absent');
  assert.match(clientStore, /txPut\('settings', \{ key: lensBookSettingKey/, 'the record lives in the settings store');
  // exportAll reads identity + contacts (+ explicit named records) — never the settings store wholesale,
  // and the lens record is not one it names: the book cannot ride a backup.
  const exportAll = clientStore.slice(clientStore.indexOf('export async function exportAll('), clientStore.indexOf('export async function exportAll(') + 1400);
  assert.equal(exportAll.includes('lens'), false, 'exportAll must not name the lens record');
  assert.equal(exportAll.includes("txGetAll('settings')"), false, 'exportAll must not dump the settings store');
});

test('item 6: with NO injected store the default sealed path reads UNREADABLE when locked and THROWS on write', async () => {
  // Locked session (no _sessionKey): the read itself throws inside the seam — the book loads
  // UNREADABLE (R2a read-only), never an empty stand-in a save could overwrite (v1.10 B1).
  // The filter still fails closed: zero methods go, and the write still throws — never plaintext.
  assert.deepEqual(await loadLensGrants(OWNER), { v: 1, grants: {}, inSeq: {}, unreadable: true });
  await assert.rejects(() => saveLensGrants(OWNER, emptyBook()), /Session locked|unencrypted/);
});

test('R1: the record rides no wire path (source guard — unchanged boundary)', () => {
  const dir = fileURLToPath(new URL('.', import.meta.url));
  const grantSrc = readFileSync(`${dir}/lens-grants.ts`, 'utf8');
  assert.equal(grantSrc.includes('fetch('), false);
  assert.equal(/getAllContacts|updateContact|addContact/.test(grantSrc), false);
});

test('R2: corrupt or unreadable records read as EMPTY — identical to no record', async () => {
  const s = memStorage();
  s.map.set(lensGrantKey(OWNER), '{not json');
  assert.deepEqual(await loadLensGrants(OWNER, s), { v: 1, grants: {}, inSeq: {}, unreadable: true },
    'empty for the FILTER, but marked unreadable so the send reports book-unreadable, not no-record');
  s.map.set(lensGrantKey(OWNER), '{"v":2,"grants":{}}'); // wrong version
  assert.deepEqual((await loadLensGrants(OWNER, s)).grants, {});
  s.map.set(lensGrantKey(OWNER), '{"v":1,"grants":{"not-a-fp":{"lens":"x"},"' + FP_A + '":{"lens":17}}}');
  const back = await loadLensGrants(OWNER, s);
  assert.equal(lensForRecipient(back, FP_A), null); // non-canonical key and junk row both dropped
  assert.equal(lensForRecipient(back, 'not-a-fp'), null);
  // A throwing storage never propagates.
  const hostile = { getItem: () => { throw new Error('io'); }, setItem: () => {} };
  assert.deepEqual((await loadLensGrants(OWNER, hostile)).grants, {});
});

test('R2a/T1: a VALID-JSON wrong-shape book reads unreadable — v≠1, grants not a map, or junk maps', async () => {
  const s = memStorage();
  for (const bad of [
    '{"v":2,"grants":{}}',           // valid parse, unknown version
    '{"v":1,"grants":"junk"}',       // grants not an object
    '{"v":1,"grants":null}',         // grants null
    '{"v":1,"grants":[]}',           // grants an array — parses clean, still not a map
    '{"v":1,"grants":{},"inSeq":[]}',// inSeq an array — same wrong-shape class
    '[1,2,3]',                       // valid JSON, not a book at all
  ]) {
    s.map.set(lensGrantKey(OWNER), bad);
    const book = await loadLensGrants(OWNER, s);
    assert.equal(book.unreadable, true, `${bad} must read unreadable, not a readable empty book`);
    assert.deepEqual(book.grants, {}, 'empty for the filter — R2a makes the book read-only, not absent');
  }
});

test('R2a: saveLensGrants REFUSES an unreadable book — the stored bytes stay byte-identical', async () => {
  const s = memStorage();
  s.map.set(lensGrantKey(OWNER), '{not json'); // present but unreadable
  const book = await loadLensGrants(OWNER, s);
  assert.equal(book.unreadable, true);
  await saveLensGrants(OWNER, book, s);
  assert.equal(s.map.get(lensGrantKey(OWNER)), '{not json', 'the real (corrupt) bytes survive — a stand-in never overwrites them');
  // Mutant-guard: a write-path that saves an unreadable book must go red.
  await saveLensGrants(OWNER, { v: 1, grants: { [FP_A]: { lens: 'x' } } }, s);
  assert.notEqual(s.map.get(lensGrantKey(OWNER)), '{not json', 'a READABLE book still persists normally');
});

test('R2: lensForRecipient returns null with no record — the caller sends ZERO methods and holds', () => {
  const book = emptyBook();
  assert.equal(lensForRecipient(book, FP_B), null);
});

test('grants: set → read → clear; capability marks; sent-set unions', () => {
  let book = setRecipientLens(emptyBook(), FP_A, 'lens-friends');
  assert.equal(lensForRecipient(book, FP_A), 'lens-friends');
  book = setRecipientLens(book, FP_A, null);
  assert.equal(lensForRecipient(book, FP_A), null);
  assert.equal(peerIsCapable(book, FP_A), false);
  const capable = markPeerCapable(book, FP_A);
  assert.equal(peerIsCapable(capable, FP_A), true);
  // sent-set: union-only, deduped, survives a second merge unchanged.
  const k1 = lensMethodKey({ kind: 'email' });
  const k2 = lensMethodKey({ kind: 'signal', label: 'work' });
  const m1 = recordLensKeys(book, FP_A, [k1, k2]);
  assert.deepEqual(lensSentKeys(m1, FP_A), new Set([k1, k2]));
  const m2 = recordLensKeys(m1, FP_A, [k2]);
  assert.equal(m2, m1, 'a fully-known merge returns the same book');
});

test('item 4: nextLensSeq is max(prev+1, whole seconds since epoch) — a wiped book resumes above the floor', () => {
  // A restored/cleared book (seq absent) still stamps a seq ABOVE anything the old book produced,
  // because it anchors to wall time — the strictly-greater receiver floor never strands the sender.
  const wiped = emptyBook();
  const n = nextLensSeq(wiped, FP_A, NOW);
  assert.equal(n.seq, NOW);
  // And it still bumps monotonically off a populated counter.
  const n2 = nextLensSeq({ v: 1, grants: { [FP_A]: { seq: NOW } } }, FP_A, NOW);
  assert.equal(n2.seq, NOW + 1);
  // A book AHEAD of the clock keeps its own monotonicity (prev+1 dominates).
  const n3 = nextLensSeq({ v: 1, grants: { [FP_A]: { seq: NOW + 5000 } } }, FP_A, NOW);
  assert.equal(n3.seq, NOW + 5001);
});

test('receive floor: acceptInSeq accepts strictly-greater seqs and refuses a far-future seq', () => {
  let book = emptyBook();
  const a1 = acceptInSeq(book, FP_A, 5, NOW);
  assert.notEqual(a1, null);
  assert.equal(acceptInSeq(a1!, FP_A, 5, NOW), null); // replay
  assert.equal(acceptInSeq(a1!, FP_A, 4, NOW), null); // stale
  const a2 = acceptInSeq(a1!, FP_A, 6, NOW);
  assert.notEqual(a2, null);
  // A different sender's floor is independent.
  assert.notEqual(acceptInSeq(a2!, FP_B, 1, NOW), null);
  assert.equal(acceptInSeq(a2!, FP_A, -1, NOW), null);
  // item 4: a seq more than a day ahead of the receiver's clock is REFUSED — a wrong clock cannot
  // poison the floor (inside the bound still accepts).
  assert.equal(acceptInSeq(emptyBook(), FP_A, NOW + LENS_MAX_FUTURE_SEQ_S + 1, NOW), null);
  assert.notEqual(acceptInSeq(emptyBook(), FP_A, NOW + LENS_MAX_FUTURE_SEQ_S, NOW), null);
});

test('R3-E4: a new capability version resets the hello budget — even spent, even capable', () => {
  const fp = 'a'.repeat(64);
  const spent = markHelloSent(markHelloSent({ v: 1, grants: {} }, fp, 7, 1000), fp, 7, 2000); // n=2 @ v7
  assert.equal(helloDue(spent, fp, 7, 2000 + 8 * 86400), false, 'budget spent at this version');
  assert.equal(helloDue(spent, fp, 8, 2000), true, 'a new capability version is due again');
  const capableAndSpent = markPeerCapable(spent, fp);
  assert.equal(helloDue(capableAndSpent, fp, 8, 2000), true, 'version bump outranks the capable-skip');
});

test('R3-C: a hello marker plus a capable peer is not due — no marker, or no capability, stays due', () => {
  const fp = 'a'.repeat(64);
  const marked = markHelloSent({ v: 1, grants: {} }, fp, 7, 1000);
  const capableMarked = markPeerCapable(marked, fp);
  const after = 1000 + 8 * 86400;
  assert.equal(helloDue(capableMarked, fp, 7, after), false, 'their hello came back — skip the retry');
  assert.equal(helloDue(marked, fp, 7, after), true, 'nothing came back — the one retry fires after the envelope life');
  assert.equal(helloDue(markPeerCapable({ v: 1, grants: {} }, fp), fp, 7, after), true, 'never announced ⇒ still due');
});
