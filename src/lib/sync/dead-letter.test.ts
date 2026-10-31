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
  parseDeadLetterRow,
  planPrune,
  ROW_MAX_AGE_MS,
  ROW_MAX_COUNT,
  ROW_MAX_NOT_IN_BOOK,
  ROW_MAX_PER_CONTACT,
  planBound,
  safeEnvelopeId,
  type DeadLetterReason,
} from './dead-letter';

const HYBRID = JSON.stringify({ v: 1, alg: 'X25519+ML-KEM-1024/HKDF-SHA256/AES-256-GCM', mailbox_fp: 'ab'.repeat(32), epk: 'e', kem_ct: 'k', nonce: 'n', ct: 'c' });
const FP40 = 'ab'.repeat(20);
const FP64 = 'cd'.repeat(32);
const T0 = '2026-10-30T12:00:00.000Z';
const ALL_REASONS: DeadLetterReason[] = ['unknown-format', 'decrypt-failed', 'missing-key', 'verify-failed', 'unverified-frame', 'not-in-book', 'ratchet-unopenable', 'ratchet-local', 'expired'];

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
  assert.deepEqual([...AUTHENTICATED_REASONS].sort(), ['not-in-book', 'ratchet-local', 'ratchet-unopenable']);
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

test('D12 a stored row is accepted only with the exact key set, closed values, safe id, readable time, and a well-formed fp for an authenticated reason', () => {
  const good = { envelope_id: 'e1', first_seen: T0, reason: 'not-in-book', blob_kind: 'json', fp: FP64 };
  assert.deepEqual(parseDeadLetterRow(good), good);
  assert.deepEqual(parseDeadLetterRow({ ...good, fp: FP40.toUpperCase() })?.fp, FP40, 'fp lower-cased');
  const bads: unknown[] = [
    null, undefined, 'x', 7, [], {},
    { ...good, extra: 'x' },                               // unknown key
    { ...good, body: 'text' },                             // content can never ride along
    { ...good, envelope_id: '../x' }, { ...good, envelope_id: 5 },
    { ...good, first_seen: 'nope' }, { ...good, first_seen: 5 },
    { ...good, reason: 'whatever' }, { ...good, reason: undefined },
    { ...good, blob_kind: 'blob' }, { ...good, blob_kind: undefined },
    { ...good, fp: 'zz'.repeat(20) }, { ...good, fp: 5 },
    { ...good, reason: 'verify-failed' },                  // an unauthenticated reason must not carry an fp
  ];
  for (const bad of bads) assert.equal(parseDeadLetterRow(bad), null, JSON.stringify(bad));
  assert.deepEqual(parseDeadLetterRow({ envelope_id: 'e1', first_seen: T0, reason: 'verify-failed', blob_kind: 'other' }), { envelope_id: 'e1', first_seen: T0, reason: 'verify-failed', blob_kind: 'other' });
});

test('D13 retention pinned by VALUE: 200 rows and 30 days (the contract is silent; this is a flagged decision)', () => {
  assert.equal(ROW_MAX_COUNT, 200);
  assert.equal(ROW_MAX_AGE_MS, 30 * 24 * 60 * 60 * 1000);
});

test('D14 planPrune: exactly 30 days is kept, 1 ms past is dropped; beyond 200 the OLDEST go; unreadable time counts as old', () => {
  const day = 24 * 60 * 60 * 1000;
  const mk = (n: number, ageOf: (i: number) => number) => Array.from({ length: n }, (_, i) => ({ envelope_id: `r${String(i).padStart(3, '0')}`, first_seen: ago(ageOf(i)) }));
  assert.deepEqual(planPrune([{ envelope_id: 'a', first_seen: ago(30 * day) }, { envelope_id: 'b', first_seen: ago(30 * day + 1) }], NOW), ['b']);
  assert.deepEqual(planPrune(mk(200, (i) => 1000 + i * 1000), NOW), []);
  assert.deepEqual(planPrune(mk(201, (i) => 1000 + i * 1000), NOW), ['r200'], 'the single oldest');
  const many = planPrune(mk(230, (i) => 1000 + i * 1000), NOW);
  assert.equal(many.length, 30);
  assert.ok(many.every((id) => Number(id.slice(1)) >= 200), 'only the 30 oldest');
  assert.deepEqual(planPrune([{ envelope_id: 'z', first_seen: 'garbage' }, { envelope_id: 'a', first_seen: ago(1000) }], NOW), ['z']);
  assert.deepEqual(planPrune([...mk(205, (i) => 1000 + i * 1000)].reverse(), NOW).sort(), planPrune(mk(205, (i) => 1000 + i * 1000), NOW).sort(), 'input order does not matter');
  assert.deepEqual(planPrune([], NOW), []);
});

// ── B1 (Flint, lane:svrnty #2026): unauthenticated junk must NOT be able to evict the record of a REAL contact's failed message ─────────────
const DAYMS = 24 * 60 * 60 * 1000;
const rowAt = (id: string, ageMs: number, reason: string) => ({ envelope_id: id, first_seen: new Date(NOW - ageMs).toISOString(), reason });

test('D15 B1 NEG: 250 junk rows cannot push out an OLDER authenticated (ratchet-unopenable) row', () => {
  const rows = [
    rowAt('real-contact-msg', 20 * DAYMS, 'ratchet-unopenable'), // the oldest row of all
    ...Array.from({ length: 250 }, (_, i) => rowAt(`junk${String(i).padStart(3, '0')}`, 1000 + i * 1000, 'decrypt-failed')),
  ];
  const drop = planPrune(rows, NOW);
  assert.equal(drop.includes('real-contact-msg'), false, 'the authenticated row survives');
  assert.equal(drop.length, 50, 'the 50 oldest JUNK rows are dropped to hold the junk budget at 200');
  assert.ok(drop.every((id) => id.startsWith('junk')));
});

test('D16 B1: same for not-in-book (also authenticated); junk of every UNauthenticated reason shares ONE budget', () => {
  const rows = [
    rowAt('nib', 25 * DAYMS, 'not-in-book'),
    ...['unknown-format', 'decrypt-failed', 'missing-key', 'verify-failed', 'expired'].flatMap((reason, r) =>
      Array.from({ length: 50 }, (_, i) => rowAt(`j-${reason}-${i}`, 1000 + (r * 50 + i) * 1000, reason))),
  ]; // 250 junk across 5 reasons
  const drop = planPrune(rows, NOW);
  assert.equal(drop.includes('nib'), false);
  assert.equal(drop.length, 50);
});

const rowFp = (id: string, ageMs: number, reason: string, fp: string) => ({ ...rowAt(id, ageMs, reason), fp });
const FPA = 'aa'.repeat(32);
const FPB = 'bb'.repeat(32);

test('D17 B1 NEG (Flint #2029): 250 junk + 250 not-in-book + 1 ratchet-unopenable => the ratchet row survives; not-in-book never shares the contact budget', () => {
  const rows = [
    rowFp('real-contact-msg', 29 * DAYMS, 'ratchet-unopenable', FPA), // the oldest row of all
    ...Array.from({ length: 250 }, (_, i) => rowAt(`junk${String(i).padStart(3, '0')}`, 1000 + i * 1000, 'decrypt-failed')),
    ...Array.from({ length: 250 }, (_, i) => rowFp(`nib${String(i).padStart(3, '0')}`, 1000 + i * 1000, 'not-in-book', 'cc'.repeat(32))),
  ];
  const drop = planPrune(rows, NOW);
  assert.equal(drop.includes('real-contact-msg'), false);
  assert.equal(drop.length, 100, '50 oldest junk + 50 oldest not-in-book');
  assert.equal(drop.filter((id) => id.startsWith('junk')).length, 50);
  assert.equal(drop.filter((id) => id.startsWith('nib')).length, 50);
});

test('D18 B1: ONE contact flooding 60 rows loses only ITS OWN oldest 10 and cannot evict another contact\'s row', () => {
  const rows = [
    rowFp('bob-old', 29 * DAYMS, 'ratchet-unopenable', FPB),
    ...Array.from({ length: 60 }, (_, i) => rowFp(`a${String(i).padStart(2, '0')}`, 1000 + i * 1000, 'ratchet-unopenable', FPA)), // a59 oldest
  ];
  const drop = planPrune(rows, NOW).sort();
  assert.deepEqual(drop, ['a50', 'a51', 'a52', 'a53', 'a54', 'a55', 'a56', 'a57', 'a58', 'a59']);
  assert.equal(drop.includes('bob-old'), false);
});

test('D19 B1: per-contact fp is case-insensitive; a ratchet row with NO readable fp has its own bucket apart from every contact and from junk', () => {
  const rows = [
    ...Array.from({ length: 30 }, (_, i) => rowFp(`u${i}`, 1000 + i * 1000, 'ratchet-unopenable', FPA.toUpperCase())),
    ...Array.from({ length: 30 }, (_, i) => rowFp(`l${i}`, 31000 + i * 1000, 'ratchet-unopenable', FPA)),
  ];
  assert.equal(planPrune(rows, NOW).length, 10, 'same contact in two spellings is ONE budget of 50');
  const nofp = [...Array.from({ length: 55 }, (_, i) => rowAt(`n${i}`, 1000 + i * 1000, 'ratchet-unopenable')), rowFp('c1', 1000, 'ratchet-unopenable', FPB), ...Array.from({ length: 205 }, (_, i) => rowAt(`j${i}`, 1000 + i * 1000, 'decrypt-failed'))];
  const drop = planPrune(nofp, NOW);
  assert.equal(drop.includes('c1'), false);
  assert.equal(drop.filter((id) => id.startsWith('n')).length, 5, 'the fp-less bucket holds 50');
  assert.equal(drop.filter((id) => id.startsWith('j')).length, 5, 'junk holds 200');
});

test('D20 B1: age applies to every budget (exactly 30 days kept); caps pinned by value; reason-less and unverified-frame rows are JUNK', () => {
  assert.equal(ROW_MAX_NOT_IN_BOOK, 200);
  assert.equal(ROW_MAX_PER_CONTACT, 50);
  const aged = planPrune([rowAt('old-nib', 30 * DAYMS + 1, 'not-in-book'), rowFp('old-rat', 30 * DAYMS + 1, 'ratchet-unopenable', FPA), rowAt('old-junk', 30 * DAYMS + 1, 'decrypt-failed'), rowAt('ok-nib', 30 * DAYMS, 'not-in-book')], NOW).sort();
  assert.deepEqual(aged, ['old-junk', 'old-nib', 'old-rat']);
  const rows = [
    { envelope_id: 'noreason', first_seen: new Date(NOW - 20 * DAYMS).toISOString() },
    rowAt('stranger-frame', 19 * DAYMS, 'unverified-frame'),
    ...Array.from({ length: 199 }, (_, i) => rowAt(`j${i}`, 1000 + i * 1000, 'decrypt-failed')),
  ];
  assert.deepEqual(planPrune(rows, NOW).sort(), ['noreason'], '201 junk-class rows: only the single oldest (the reason-less one) goes');
  assert.equal(planPrune([...rows, rowAt('extra', 500, 'unverified-frame')], NOW).length, 2, 'unverified-frame competes in the junk budget');
});

test('D21 unverified-frame: a NON-MESSAGE reason that never carries an fp, even if one is offered', () => {
  const row = makeDeadLetterRow({ envelopeId: 'e1', firstSeen: T0, reason: 'unverified-frame', blob: HYBRID, fp: FP64 });
  assert.ok(row);
  assert.equal(row!.fp, undefined);
  assert.equal(parseDeadLetterRow({ ...row!, fp: FP64 }), null, 'a stored unverified-frame row with an fp is refused');
});

test('D22 v5.3: ratchet-local rows are in the PER-CONTACT protected budget with ratchet-unopenable (50 per fp together), never in the junk or not-in-book budget', () => {
  const rows = [
    ...Array.from({ length: 30 }, (_, i) => rowFp(`v${i}`, 1000 + i * 1000, 'ratchet-unopenable', FPA)),
    ...Array.from({ length: 30 }, (_, i) => rowFp(`l${i}`, 31000 + i * 1000, 'ratchet-local', FPA)),
    ...Array.from({ length: 250 }, (_, i) => rowAt(`j${i}`, 1000 + i * 1000, 'decrypt-failed')),
  ];
  const drop = planPrune(rows, NOW);
  assert.equal(drop.filter((id) => id.startsWith('v') || id.startsWith('l')).length, 10, 'one contact\'s two ratchet classes share 50');
  assert.equal(drop.filter((id) => id.startsWith('j')).length, 50, 'junk holds its own 200');
  const row = makeDeadLetterRow({ envelopeId: 'e1', firstSeen: T0, reason: 'ratchet-local', blob: 'x', fp: FP64 });
  assert.equal(row!.fp, FP64, 'a LOCAL row is named (the sender was authenticated)');
});
