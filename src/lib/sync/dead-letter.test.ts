// src/lib/sync/dead-letter.test.ts
// #720 R1/R2/R9 + Flint F1-F6: what a dead-letter row may hold, and which held envelopes have outlived the bounds.
// Run: npx tsx --test src/lib/sync/dead-letter.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AUTHENTICATED_REASONS,
  BENIGN_TERMINALS,
  KEEP_MAX_AGE_MS,
  KEEP_MAX_COUNT,
  classifyBlob,
  makeDeadLetterRow,
  planBound,
  safeEnvelopeId,
  type DeadLetterReason,
} from './dead-letter';

const HYBRID = JSON.stringify({ v: 1, alg: 'X25519+ML-KEM-1024/HKDF-SHA256/AES-256-GCM', mailbox_fp: 'ab'.repeat(32), epk: 'e', kem_ct: 'k', nonce: 'n', ct: 'c' });
const FP40 = 'ab'.repeat(20);
const FP64 = 'cd'.repeat(32);
const T0 = '2026-10-30T12:00:00.000Z';
const ALL_REASONS: DeadLetterReason[] = ['unknown-format', 'decrypt-failed', 'missing-key', 'verify-failed', 'not-in-book', 'ratchet-unopenable', 'expired'];

test('D1 envelope ids: a UUID passes; anything outside the plain charset, empty, too long, or not a string is refused', () => {
  assert.equal(safeEnvelopeId('3f2b8c1e-5a4d-4e8b-9c1a-0d2e3f4a5b6c'), '3f2b8c1e-5a4d-4e8b-9c1a-0d2e3f4a5b6c');
  for (const bad of ['', '../etc', 'a/b', 'a b', 'x'.repeat(101), '<script>', 'e\u0000', 'é', 42, null, undefined, {}]) {
    assert.equal(safeEnvelopeId(bad), null, JSON.stringify(bad));
  }
  assert.equal(safeEnvelopeId('x'.repeat(100)), 'x'.repeat(100));
});

test('D2 blob kind comes from SHAPE alone', () => {
  assert.equal(classifyBlob(HYBRID), 'hybrid-package');
  assert.equal(classifyBlob('-----BEGIN PGP MESSAGE-----\nabc\n-----END PGP MESSAGE-----'), 'openpgp-armor');
  assert.equal(classifyBlob(JSON.stringify({ v: 2, hello: 'x' })), 'json');
  assert.equal(classifyBlob(JSON.stringify({ v: 1, mailbox_fp: 'ab', hello: 'x' })), 'json', 'mentions mailbox_fp but is not a full package');
  assert.equal(classifyBlob('-----BEGIN PGP SIGNED MESSAGE-----\nx'), 'other', 'only an encrypted-message armor is openpgp-armor');
  assert.equal(classifyBlob('-----BEGIN PGP PUBLIC KEY BLOCK-----\nx'), 'other');
  assert.equal(classifyBlob('this-is-not-anything'), 'other');
  assert.equal(classifyBlob(''), 'other');
});

test('D3 F2/F4: a row holds exactly the metadata keys and NO text from the blob, for every reason and blob shape', () => {
  const SENTINEL = 'ATTACKER-TEXT-7f3a';
  const blobs = [
    HYBRID.replace('"ct":"c"', `"ct":"${SENTINEL}"`),
    `-----BEGIN PGP MESSAGE-----\n${SENTINEL}\n-----END PGP MESSAGE-----`,
    JSON.stringify({ subject: SENTINEL, from: SENTINEL, filename: SENTINEL }),
    SENTINEL,
  ];
  for (const blob of blobs) {
    for (const reason of ALL_REASONS) {
      const row = makeDeadLetterRow({ envelopeId: 'env-1', firstSeen: T0, reason, blob, fp: FP64 });
      assert.ok(row, `${reason}`);
      assert.equal(JSON.stringify(row).includes(SENTINEL), false, `${reason}: blob text leaked into the row`);
      for (const k of Object.keys(row)) assert.ok(['envelope_id', 'first_seen', 'reason', 'blob_kind', 'fp'].includes(k), `unexpected key ${k}`);
      // Closed value sets: even a PARTIAL copy of the blob (a prefix, a slice) cannot hide in blob_kind or reason.
      assert.ok(['hybrid-package', 'openpgp-armor', 'json', 'other'].includes(row.blob_kind), `blob_kind ${row.blob_kind}`);
      assert.equal(row.reason, reason);
      assert.equal(row.envelope_id, 'env-1');
    }
  }
});

test('D4 F3: a fingerprint is stored only for AUTHENTICATED reasons, and only when it is a well-formed fingerprint', () => {
  for (const reason of ALL_REASONS) {
    const row = makeDeadLetterRow({ envelopeId: 'e', firstSeen: T0, reason, blob: 'x', fp: FP64 });
    assert.equal('fp' in row!, AUTHENTICATED_REASONS.has(reason), reason);
  }
  assert.deepEqual([...AUTHENTICATED_REASONS].sort(), ['not-in-book', 'ratchet-unopenable']);
  const ok40 = makeDeadLetterRow({ envelopeId: 'e', firstSeen: T0, reason: 'not-in-book', blob: 'x', fp: FP40.toUpperCase() });
  assert.equal(ok40!.fp, FP40, 'lower-cased');
  for (const badFp of ['', 'zz'.repeat(20), 'ab'.repeat(19), 'ab'.repeat(33), 'ab'.repeat(20) + '\n', 7 as unknown as string]) {
    const r = makeDeadLetterRow({ envelopeId: 'e', firstSeen: T0, reason: 'not-in-book', blob: 'x', fp: badFp });
    assert.equal('fp' in r!, false, JSON.stringify(badFp));
  }
});

test('D5 a row cannot be built from an unsafe id or an unreadable time (the caller must then keep the envelope, not ack it)', () => {
  assert.equal(makeDeadLetterRow({ envelopeId: '../x', firstSeen: T0, reason: 'decrypt-failed', blob: 'x' }), null);
  assert.equal(makeDeadLetterRow({ envelopeId: 'e', firstSeen: 'not a date', reason: 'decrypt-failed', blob: 'x' }), null);
  assert.equal(makeDeadLetterRow({ envelopeId: 'e', firstSeen: '', reason: 'decrypt-failed', blob: 'x' }), null);
});

test('D6 the BENIGN terminal list is exactly these three (a new entry must be a deliberate edit of this test)', () => {
  assert.deepEqual([...BENIGN_TERMINALS], ['contact-update-stale', 'joiner-already-known', 'receipt-no-match']);
});

const NOW = Date.parse('2026-10-30T12:00:00.000Z');
const ago = (ms: number) => new Date(NOW - ms).toISOString();
const held = (n: number, ageMsOf: (i: number) => number) => Array.from({ length: n }, (_, i) => ({ envelope_id: `e${String(i).padStart(3, '0')}`, first_seen: ago(ageMsOf(i)) }));

test('D6b the F1 bounds are pinned by VALUE (tests above import the constants, so a changed constant would otherwise pass them)', () => {
  assert.equal(KEEP_MAX_AGE_MS, 7 * 24 * 60 * 60 * 1000);
  assert.equal(KEEP_MAX_COUNT, 50);
});

test('D7 age bound: exactly 7 days is kept, 1 ms past is released with cause age', () => {
  const p = planBound([{ envelope_id: 'a', first_seen: ago(KEEP_MAX_AGE_MS) }, { envelope_id: 'b', first_seen: ago(KEEP_MAX_AGE_MS + 1) }], NOW);
  assert.deepEqual(p.keep, ['a']);
  assert.deepEqual(p.release, [{ envelope_id: 'b', cause: 'age' }]);
});

test('D8 count bound: 50 are kept, 51 releases the single OLDEST with cause count', () => {
  const h50 = held(50, (i) => 1000 + i * 1000);
  assert.equal(planBound(h50, NOW).keep.length, 50);
  assert.deepEqual(planBound(h50, NOW).release, []);
  const h51 = held(51, (i) => 1000 + i * 1000); // e050 is the oldest
  const p = planBound(h51, NOW);
  assert.equal(p.keep.length, 50);
  assert.deepEqual(p.release, [{ envelope_id: 'e050', cause: 'count' }]);
  assert.equal(p.keep.includes('e050'), false);
});

test('D9 done_when 8: 60 junk envelopes -> 50 kept, the 10 OLDEST released (row first, then ack); the kept ones are the newest 50', () => {
  const p = planBound(held(60, (i) => 1000 + i * 1000), NOW);
  assert.equal(p.keep.length, 50);
  assert.deepEqual(p.release.map((r) => r.envelope_id).sort(), Array.from({ length: 10 }, (_, i) => `e${String(50 + i).padStart(3, '0')}`));
  assert.ok(p.release.every((r) => r.cause === 'count'));
});

test('D10 age and count together: aged ones are released as age first, then the count trim applies to what is left', () => {
  const rows = [
    ...held(3, () => KEEP_MAX_AGE_MS + 5000).map((r, i) => ({ ...r, envelope_id: `old${i}` })),
    ...held(52, (i) => 1000 + i * 1000),
  ];
  const p = planBound(rows, NOW);
  assert.deepEqual(p.release.filter((r) => r.cause === 'age').map((r) => r.envelope_id).sort(), ['old0', 'old1', 'old2']);
  assert.deepEqual(p.release.filter((r) => r.cause === 'count').map((r) => r.envelope_id).sort(), ['e050', 'e051']);
  assert.equal(p.keep.length, 50);
});

test('D11 an unreadable first_seen counts as expired (never kept forever), and the order does not depend on input order', () => {
  const rows = [{ envelope_id: 'z', first_seen: 'garbage' }, { envelope_id: 'a', first_seen: ago(1000) }];
  assert.deepEqual(planBound(rows, NOW).release, [{ envelope_id: 'z', cause: 'age' }]);
  const rows2 = held(55, (i) => 1000 + i * 1000);
  assert.deepEqual(planBound([...rows2].reverse(), NOW), planBound(rows2, NOW));
  assert.deepEqual(planBound([], NOW), { keep: [], release: [] });
});
