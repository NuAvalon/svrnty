// src/lib/crypto/recovery-commit.test.ts
// The per-piece commitment for recovery pieces: c_i = sha256(domain || set_id || index || piece). Written BEFORE the module (tests first).
// Why it exists (recovery-shards.test.ts R2/R3/R5): Shamir has no integrity. A bad, short or foreign piece returns wrong bytes with no error, and the labels
// (index, threshold, identity) are never read, so only a commitment that BINDS THE LABEL TO THE PIECE can tell the owner which pieces to trust.
//   C1  the layout, by a known answer computed OUTSIDE the module (node:crypto), so the bytes on the wire cannot drift
//   C2  every input bit matters: set_id, index, each byte of the piece; and nothing else does
//   C3  the label is bound: a relabelled piece, two swapped labels, a piece from another split, a piece against another set's list: all fail
//   C4  sortPieces (the owner's check before combining): good vs bad with a reason for each, and what is left still recovers through a real vault
//   C5  the holder's own check of the one piece it was sent
//   C6  the stored list is parsed strictly; a malformed one is refused, never partly used
//   C7  inputs are validated; the module is a leaf (it never sees the secret, only pieces); compares are constant-time
// Run: npx tsx --test src/lib/crypto/recovery-commit.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  newSetId, commitPiece, commitSet, verifyOwnPiece, sortPieces, parseCommitments, COMMIT_DOMAIN, SET_ID_HEX_LENGTH,
  type PieceCommitments,
} from './recovery-commit';
import { createShards, createKeyVault, recoverFromShards, generateMasterSecret, type Shard, type PrivateKeyBundle } from './recovery';

const FP = 'a'.repeat(64);
const SET = '0123456789abcdef'.repeat(4);
const b64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));
const toB64 = (u: Uint8Array) => Buffer.from(u).toString('base64');
const flip = (p: Shard, pos: number): Shard => { const d = b64(p.data); d[pos] ^= 1; return { ...p, data: toB64(d) }; };
const SRC = resolve(__dirname);
const src = () => readFileSync(join(SRC, 'recovery-commit.ts'), 'utf8');

const BUNDLE: PrivateKeyBundle = { classical_private_key: 'k', classical_passphrase: 'p', pq_signing_secret_key: 'c2ln', pq_kem_secret_key: 'a2Vt' };

test('C1 the layout: sha256(domain || set_id(32) || index(1 byte) || piece), by a known answer computed with node:crypto', () => {
  const piece = new Uint8Array(33).map((_, i) => (i * 7 + 3) & 0xff);
  const expected = createHash('sha256')
    .update(Buffer.from('svrnty/recovery-piece/commit/v1\0', 'utf8'))
    .update(Buffer.from(SET, 'hex'))
    .update(Buffer.from([5]))
    .update(Buffer.from(piece))
    .digest('hex');
  assert.equal(commitPiece(SET, 5, toB64(piece)), expected);
  assert.match(commitPiece(SET, 5, toB64(piece)), /^[0-9a-f]{64}$/);
  assert.equal(SET_ID_HEX_LENGTH, 64);
  assert.equal(COMMIT_DOMAIN, 'svrnty/recovery-piece/commit/v1\0', 'the domain tag names this use and its version, exactly');
  assert.notEqual(commitPiece(SET, 5, toB64(piece)), createHash('sha256').update(Buffer.from(SET, 'hex')).update(Buffer.from([5])).update(Buffer.from(piece)).digest('hex'),
    'the domain tag is part of the hash: a bare sha256(set_id || index || piece) is not a valid commitment');
});

test('C2 every input matters: one bit of the set id, the index, or any byte of the piece changes the commitment; the same inputs never do', async () => {
  const [p] = await createShards(generateMasterSecret(), 2, 3, FP);
  const base = commitPiece(SET, 1, p.data);
  assert.equal(commitPiece(SET, 1, p.data), base, 'deterministic');
  const setBytes = Buffer.from(SET, 'hex');
  for (let i = 0; i < 32; i++) { const s = Buffer.from(setBytes); s[i] ^= 1; assert.notEqual(commitPiece(s.toString('hex'), 1, p.data), base, `set id byte ${i}`); }
  for (let idx = 2; idx <= 255; idx++) assert.notEqual(commitPiece(SET, idx, p.data), base, `index ${idx}`);
  for (let pos = 0; pos < 33; pos++) assert.notEqual(commitPiece(SET, 1, flip(p, pos).data), base, `piece byte ${pos}`);
  assert.equal(commitPiece(SET.toUpperCase(), 1, p.data), base, 'hex case of the set id does not matter');
});

test('C2b one piece has one encoding: a non-canonical base64 string for the same bytes is malformed, not a second spelling', () => {
  assert.equal(commitPiece(SET, 1, 'AQI='), commitPiece(SET, 1, toB64(new Uint8Array([1, 2]))));
  assert.throws(() => commitPiece(SET, 1, 'AQJ='), /piece/i, 'AQJ= decodes to the same two bytes but is not what a writer produces');
  const r = sortPieces(parseCommitments({ v: 1, set_id: SET, commitments: { '1': commitPiece(SET, 1, 'AQI=') } })!, [{ index: 1, data: 'AQJ=' }, { index: 1, data: 'AQI=' }]);
  assert.deepEqual(r.bad.map((b) => b.reason), ['malformed']);
  assert.equal(r.good.length, 1);
});

test('C3 the label is bound: relabelled, swapped, foreign and cross-set pieces all fail against the list', async () => {
  const secret = generateMasterSecret();
  const a = await createShards(secret, 3, 5, FP);
  const setA = newSetId();
  const listA = commitSet(setA, a);
  // relabelled: same bytes, another index
  for (const p of a) for (const idx of [1, 2, 3, 4, 5, 9, 255]) {
    if (idx === p.index) continue;
    const r = sortPieces(listA, [{ ...p, index: idx }]);
    assert.equal(r.good.length, 0, `piece ${p.index} labelled ${idx}`);
    assert.equal(r.bad[0].reason, idx > 5 ? 'unknown-index' : 'mismatch');
  }
  // two labels swapped
  const swapped = [{ ...a[1], index: 3 }, { ...a[2], index: 2 }];
  assert.deepEqual(sortPieces(listA, swapped).good, []);
  // another split of the SAME secret, same indexes: fails, and so does every piece of it
  const b = await createShards(secret, 3, 5, FP);
  assert.deepEqual(sortPieces(listA, b).good, []);
  // the same commitments under ANOTHER set id: right pieces, right labels, wrong set
  assert.deepEqual(sortPieces({ ...listA, set_id: newSetId() }, a).good, [], 'right pieces, right labels, wrong set id');
  // pieces of this split checked against a list made from ANOTHER split, and the other way round
  const listOfB = commitSet(newSetId(), b);
  assert.deepEqual(sortPieces(listOfB, a).good, []);
  assert.deepEqual(sortPieces(listA, b).good, []);
  // and a list made from these very pieces under a fresh set id does accept them: the set id is part of the list, not a secret
  assert.equal(sortPieces(commitSet(newSetId(), a), a).good.length, 5);
  assert.equal(sortPieces(listA, a).good.length, 5);
});

test('C4 sortPieces: a flipped byte, a foreign piece, a repeat, an unknown index and a malformed piece are each reported with their reason; the rest still recover', async () => {
  const secret = generateMasterSecret();
  const [n, m] = [5, 3];
  const { vault, shards } = await createKeyVault(BUNDLE, m, n, FP);
  const list = commitSet(newSetId(), shards);
  const foreign = (await createShards(generateMasterSecret(), m, n, FP))[3];
  const handed: Shard[] = [shards[0], flip(shards[1], 7), shards[2], foreign, { ...shards[4], index: 9 }, shards[2], { ...shards[0], data: '!!not base64!!' }];
  const r = sortPieces(list, handed);
  assert.deepEqual(r.good.map((p) => p.index), [1, 3]);
  assert.deepEqual(r.bad.map((b) => [b.at, b.reason]), [[1, 'mismatch'], [3, 'mismatch'], [4, 'unknown-index'], [5, 'duplicate'], [6, 'malformed']]);
  assert.equal(r.good.length >= m, false, 'two good pieces are not enough, and sortPieces says so by count');
  // M+1 handed with one bad: what is left is exactly M and opens the vault (the target of R9b, done by the owner's check)
  const four = [shards[0], flip(shards[1], 7), shards[2], shards[3]];
  const r4 = sortPieces(list, four);
  assert.deepEqual(r4.bad.map((b) => b.reason), ['mismatch']);
  assert.equal(r4.good.length, 3);
  assert.deepEqual(await recoverFromShards(vault, r4.good), BUNDLE);
  // order of the handed pieces does not matter
  assert.equal(sortPieces(list, [...four].reverse()).good.length, 3);
  void secret;
});

test('C4b a piece handed twice counts once, and a bad piece never hides behind a good one with the same index', async () => {
  const shards = await createShards(generateMasterSecret(), 3, 5, FP);
  const list = commitSet(newSetId(), shards);
  const r = sortPieces(list, [flip(shards[0], 2), shards[0], shards[0]]);
  assert.deepEqual(r.good.map((p) => p.index), [1], 'the genuine piece is kept even when a forgery with its label came first');
  assert.deepEqual(r.bad.map((b) => b.reason), ['mismatch', 'duplicate']);
});

test('C5 the holder checks the one piece it was sent against its own commitment', async () => {
  const shards = await createShards(generateMasterSecret(), 3, 5, FP);
  const set = newSetId();
  const list = commitSet(set, shards);
  for (const p of shards) {
    assert.equal(verifyOwnPiece(set, p.index, p.data, list.commitments[String(p.index)]), true);
    assert.equal(verifyOwnPiece(set, p.index, flip(p, 0).data, list.commitments[String(p.index)]), false);
    assert.equal(verifyOwnPiece(set, p.index + 1, p.data, list.commitments[String(p.index)]), false, 'wrong label');
    assert.equal(verifyOwnPiece(newSetId(), p.index, p.data, list.commitments[String(p.index)]), false, 'wrong set');
  }
  assert.equal(verifyOwnPiece(set, 1, shards[0].data, 'zz'), false, 'a malformed commitment is not a match');
  assert.equal(verifyOwnPiece(set, 1, '!!', list.commitments['1']), false, 'a malformed piece is not a match');
  assert.equal(verifyOwnPiece(set, 0, shards[0].data, list.commitments['1']), false, 'an impossible index is not a match, and does not throw');
});

test('C6 the stored list is parsed strictly: right shape in, anything else out, nothing partly used', async () => {
  const shards = await createShards(generateMasterSecret(), 3, 5, FP);
  const list = commitSet(newSetId(), shards);
  assert.deepEqual(parseCommitments(JSON.parse(JSON.stringify(list))), list, 'round trip');
  const bad: unknown[] = [
    null, 'x', 7, [], {}, { ...list, v: 2 }, { ...list, v: undefined }, { ...list, set_id: 'abc' }, { ...list, set_id: 'g'.repeat(64) },
    { ...list, commitments: null }, { ...list, commitments: [] }, { ...list, commitments: {} },
    { ...list, commitments: { ...list.commitments, '0': 'a'.repeat(64) } },
    { ...list, commitments: { ...list.commitments, '256': 'a'.repeat(64) } },
    { ...list, commitments: { ...list.commitments, '01': 'a'.repeat(64) } },
    { ...list, commitments: { ...list.commitments, '1': 'short' } },
    { ...list, commitments: { ...list.commitments, '1': 'G'.repeat(64) } },
    { ...list, commitments: { ...list.commitments, '1': 5 } },
    { ...list, extra: 1 },
    { ...list, commitments: { '1': list.commitments['1'], '2': list.commitments['1'] } },
  ];
  for (const b of bad) assert.equal(parseCommitments(b), null, JSON.stringify(b)?.slice(0, 90));
  assert.equal(parseCommitments({ ...list, set_id: list.set_id.toUpperCase() })?.set_id, list.set_id, 'a set id in upper case is read as lower case');
});

test('C6b a commitment that is not 64 hex: parseCommitments refuses it, and sortPieces on an UNPARSED list fails closed (throws or reports the piece bad, never good)', async () => {
  const shards = await createShards(generateMasterSecret(), 3, 5, FP);
  const list = commitSet(newSetId(), shards);
  for (const v of ['', 'zz', 'g'.repeat(64), 'a'.repeat(63), 'a'.repeat(65), ' ' + 'a'.repeat(63), 'a'.repeat(62) + '0x', 7, null, undefined]) {
    const forged = { ...list, commitments: { ...list.commitments, '1': v } };
    assert.equal(parseCommitments(forged), null, `parse refuses ${String(v).slice(0, 12)}`);
    // the contract: callers parse first. A list that skipped the parse and carries garbage FAILS CLOSED: it throws, or it reports the piece as bad, and never as good.
    let good = -1;
    try { good = sortPieces(forged as unknown as PieceCommitments, [shards[0]]).good.length; } catch { good = 0; }
    assert.equal(good, 0, `sortPieces on an unparsed list with ${String(v).slice(0, 12)} must not pass a piece`);
  }
  // an upper-case 64-hex value is a spelling of the same hash: read as lower case, and it still matches
  const upper = { ...list, commitments: Object.fromEntries(Object.entries(list.commitments).map(([k, v]) => [k, v.toUpperCase()])) };
  const parsed = parseCommitments(upper);
  assert.deepEqual(parsed, list);
  assert.equal(sortPieces(parsed!, shards).good.length, 5);
});

test('C7 inputs are validated, newSetId is fresh, and the module is a leaf that compares in constant time', async () => {
  const [p] = await createShards(generateMasterSecret(), 2, 2, FP);
  for (const s of ['', 'abc', 'g'.repeat(64), SET + '00', SET.slice(2)]) assert.throws(() => commitPiece(s, 1, p.data), /set id/i, s);
  for (const i of [0, 256, -1, 1.5, NaN, Infinity]) assert.throws(() => commitPiece(SET, i, p.data), /index/i, String(i));
  assert.throws(() => commitPiece(SET, 1, ''), /piece/i);
  assert.throws(() => commitPiece(SET, 1, '!!'), /piece/i);
  assert.throws(() => commitSet(SET, [p, { ...p }]), /duplicate|unique/i, 'two pieces with one label cannot be committed');
  assert.throws(() => commitSet(SET, []), /no pieces|empty/i);
  const ids = new Set(Array.from({ length: 50 }, () => newSetId()));
  assert.equal(ids.size, 50);
  for (const id of ids) assert.match(id, /^[0-9a-f]{64}$/);
  const code = src();
  assert.doesNotMatch(code, /\bBuffer\b/, 'client code: no Node Buffer (the repo uses atob/btoa loops, see recovery.ts)');
  // A source guard, not a timing measurement: the two places that compare a hash (the holder's check, the owner's check) both go through ctEqual.
  assert.equal((code.match(/ctEqual\(/g) || []).length, 2, 'both comparisons (the holder\'s and the owner\'s) use the shared constant-time helper');
  assert.doesNotMatch(code, /[!=]==\s*(list|expected|commitment|hexToBytes|bytesToHex)\b/, 'no plain compare of a commitment');
  assert.doesNotMatch(code, /bytesToHex\([^)]*\)\)?\s*[!=]==/, 'no plain compare of a hashed value');
  const imports = [...code.matchAll(/^import .* from '([^']+)'/gm)].map((m) => m[1]).sort();
  assert.deepEqual(imports, ['./ct-equal', '@noble/hashes/sha2.js', '@noble/hashes/utils.js'], 'a leaf: no store, no network, no Shamir, no vault');
});

test('C8 the list carries only what is needed: version, set id, and one commitment per index', async () => {
  const shards = await createShards(generateMasterSecret(), 3, 5, FP);
  const list: PieceCommitments = commitSet(newSetId(), shards);
  assert.deepEqual(Object.keys(list).sort(), ['commitments', 'set_id', 'v']);
  assert.equal(commitSet(SET.toUpperCase(), shards).set_id, SET, 'the stored set id is lower case');
  assert.equal(list.v, 1);
  assert.deepEqual(Object.keys(list.commitments).sort(), ['1', '2', '3', '4', '5']);
  const json = JSON.stringify(list);
  for (const p of shards) assert.equal(json.includes(p.data), false, 'no piece is stored in the list');
});
