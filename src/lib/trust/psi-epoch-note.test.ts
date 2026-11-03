// PSI epoch note: refusals first, then tamper (every byte), direction, decoys and shape, then the known answers.
// The vectors come from scripts/psi-epoch-note-kat.py (stdlib HKDF/HMAC, no shared code).
// Run: npx tsx --test src/lib/trust/psi-epoch-note.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import {
  buildEpochNote,
  openEpochNote,
  deriveEpochMacKey,
  EpochNoteError,
  EPOCH_NOTE_LEN,
  EPOCH_NOTE_HEADER,
  type EpochNoteContext,
} from './psi-epoch-note';

const FP_A = createHash('sha256').update('kat-fp-A').digest('hex');
const FP_B = createHash('sha256').update('kat-fp-B').digest('hex');
const S_PAIR = Uint8Array.from({ length: 32 }, (_, i) => 64 + i);
const KNOW = Uint8Array.from({ length: 32 }, (_, i) => i);
const TRUST = Uint8Array.from({ length: 32 }, (_, i) => 32 + i);
const DECOY = Uint8Array.from({ length: 32 }, (_, i) => 200 + i);

const AB: EpochNoteContext = { sPair: S_PAIR, fpSender: FP_A, fpReceiver: FP_B };
const BA: EpochNoteContext = { sPair: S_PAIR, fpSender: FP_B, fpReceiver: FP_A };

const hex = (b: Uint8Array) => bytesToHex(b);
const build = (over: Partial<Parameters<typeof buildEpochNote>[0]> = {}) =>
  buildEpochNote({ ...AB, epoch: 1, know: KNOW, trust: TRUST, ...over });
const codeOf = (fn: () => unknown) => {
  try {
    fn();
  } catch (e) {
    return e instanceof EpochNoteError ? e.code : `other:${String(e)}`;
  }
  return 'no-throw';
};
const reason = (r: ReturnType<typeof openEpochNote>) => (r.ok ? 'ok' : r.reason);

// ── building refuses ────────────────────────────────────────────────────────────────────────────────────────

test('a fingerprint that is not canonical lowercase 64-hex is refused, for sender and for receiver', () => {
  for (const bad of [FP_A.toUpperCase(), FP_A.slice(0, 40), FP_A + '0', ` ${FP_A}`, '', 'zz'.repeat(32)]) {
    assert.equal(codeOf(() => build({ fpSender: bad })), 'bad-fingerprint', `sender ${JSON.stringify(bad)}`);
    assert.equal(codeOf(() => build({ fpReceiver: bad })), 'bad-fingerprint', `receiver ${JSON.stringify(bad)}`);
  }
});

test('a note from a fingerprint to itself is refused', () => {
  assert.equal(codeOf(() => build({ fpReceiver: FP_A })), 'self-note');
});

test('an epoch that is negative, fractional, not finite or beyond the safe range is refused', () => {
  for (const bad of [-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, 2 ** 63]) {
    assert.equal(codeOf(() => build({ epoch: bad })), 'bad-epoch', String(bad));
  }
});

test('a pairwise secret or a layer field that is not exactly 32 bytes is refused', () => {
  for (const bad of [new Uint8Array(0), new Uint8Array(31), new Uint8Array(33), 'x'.repeat(32), undefined]) {
    assert.equal(codeOf(() => build({ sPair: bad as unknown as Uint8Array })), 'bad-pairwise-secret', `sPair ${String(bad)}`);
    assert.equal(codeOf(() => build({ know: bad as unknown as Uint8Array })), 'bad-secret', `know ${String(bad)}`);
    assert.equal(codeOf(() => build({ trust: bad as unknown as Uint8Array })), 'bad-secret', `trust ${String(bad)}`);
  }
});

test('a real trust secret without a real know secret is refused (the trust set is a subset of the know set)', () => {
  assert.equal(codeOf(() => build({ know: null, trust: TRUST })), 'trust-without-know');
});

test('one secret used for both layers is refused, real or drawn', () => {
  assert.equal(codeOf(() => build({ know: KNOW, trust: KNOW.slice() })), 'secrets-not-independent');
  assert.equal(codeOf(() => build({ know: null, trust: null, rand: () => DECOY.slice() })), 'secrets-not-independent');
});

test('a randomness source of the wrong width is refused', () => {
  assert.equal(codeOf(() => build({ know: KNOW, trust: null, rand: (n) => new Uint8Array(n - 1) })), 'bad-secret', 'trust decoy');
  assert.equal(codeOf(() => build({ know: null, trust: null, rand: (n) => new Uint8Array(n - 1) })), 'bad-secret', 'know decoy');
  assert.equal(codeOf(() => build({ know: null, trust: null, rand: (n) => new Uint8Array(n + 1) })), 'bad-secret', 'both decoys, too long');
  // Wrong on the FIRST draw only (the know decoy), right on the second: the know decoy's own check must refuse it.
  // (With both draws wrong, the trust decoy's check would mask a missing know check.)
  let calls = 0;
  const firstShort = (n: number) => (calls++ === 0 ? new Uint8Array(n - 1) : DECOY.slice());
  assert.equal(codeOf(() => build({ know: null, trust: null, rand: firstShort })), 'bad-secret', 'know decoy alone');
  // Wrong on the SECOND draw only (the trust decoy).
  let calls2 = 0;
  const secondShort = (n: number) => (calls2++ === 1 ? new Uint8Array(n - 1) : DECOY.slice());
  assert.equal(codeOf(() => build({ know: null, trust: null, rand: secondShort })), 'bad-secret', 'trust decoy alone');
});

// ── opening refuses ─────────────────────────────────────────────────────────────────────────────────────────

test('a wire of the wrong length, or not bytes, is malformed', () => {
  const ok = build();
  assert.equal(ok.length, EPOCH_NOTE_LEN);
  assert.equal(EPOCH_NOTE_LEN, 106);
  for (const bad of [new Uint8Array(0), ok.slice(0, 105), new Uint8Array([...ok, 0]), new Uint8Array(200)]) {
    assert.equal(reason(openEpochNote(bad, AB)), 'malformed', String(bad.length));
  }
  assert.equal(reason(openEpochNote('x' as unknown as Uint8Array, AB)), 'malformed');
});

test('a wrong header byte is malformed', () => {
  for (let i = 0; i < EPOCH_NOTE_HEADER.length; i++) {
    const w = build();
    w[i] ^= 0x01;
    assert.equal(reason(openEpochNote(w, AB)), 'malformed', `byte ${i}`);
  }
});

test('opening a note as if sender and receiver were the same fingerprint is refused', () => {
  assert.equal(reason(openEpochNote(build(), { sPair: S_PAIR, fpSender: FP_A, fpReceiver: FP_A })), 'self');
});

test('an epoch beyond the representable range is refused before the MAC is looked at', () => {
  for (const bytes of [[0x00, 0x20, 0, 0, 0, 0, 0, 0], [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], [0x80, 0, 0, 0, 0, 0, 0, 0]]) {
    const w = build();
    w.set(bytes, 2);
    assert.equal(reason(openEpochNote(w, AB)), 'epoch-range', hex(Uint8Array.from(bytes)));
  }
});

test('flipping any single bit-position after the header fails the MAC: epoch, either field, or the tag', () => {
  for (let i = 2; i < EPOCH_NOTE_LEN; i++) {
    const w = build();
    w[i] ^= 0x01;
    // The epoch range is checked before the MAC, so a flip that pushes the epoch past the representable range is
    // refused as such; every other flip must be a bad MAC exactly.
    const outOfRange = i < 10 && new DataView(w.buffer, 2, 8).getBigUint64(0, false) > BigInt(Number.MAX_SAFE_INTEGER);
    assert.equal(reason(openEpochNote(w, AB)), outOfRange ? 'epoch-range' : 'bad-mac', `byte ${i}`);
  }
});

test('a note opened with a different pairwise secret, sender or receiver fails; so does the reflected direction', () => {
  const w = build();
  assert.equal(reason(openEpochNote(w, AB)), 'ok');
  assert.equal(reason(openEpochNote(w, { ...AB, sPair: S_PAIR.map((b) => b ^ 1) })), 'bad-mac');
  assert.equal(reason(openEpochNote(w, { ...AB, fpSender: createHash('sha256').update('other').digest('hex') })), 'bad-mac');
  assert.equal(reason(openEpochNote(w, { ...AB, fpReceiver: createHash('sha256').update('other').digest('hex') })), 'bad-mac');
  assert.equal(reason(openEpochNote(w, BA)), 'bad-mac', 'reflected: B opens as if B sent it to A');
});

test('the know and trust fields swapped on the wire, or either replaced, fail the MAC', () => {
  const w = build();
  const swapped = w.slice();
  swapped.set(w.slice(42, 74), 10);
  swapped.set(w.slice(10, 42), 42);
  assert.equal(reason(openEpochNote(swapped, AB)), 'bad-mac');
  const replaced = w.slice();
  replaced.set(DECOY, 10);
  assert.equal(reason(openEpochNote(replaced, AB)), 'bad-mac');
  const replaced2 = w.slice();
  replaced2.set(DECOY, 42);
  assert.equal(reason(openEpochNote(replaced2, AB)), 'bad-mac');
});

// ── shape, decoys, round trip ───────────────────────────────────────────────────────────────────────────────

test('a note round-trips, and the real fields sit where the layout says', () => {
  const w = build({ epoch: 2 ** 40 + 7 });
  const r = openEpochNote(w, AB);
  assert.ok(r.ok);
  if (r.ok) {
    assert.equal(r.epoch, 2 ** 40 + 7);
    assert.equal(hex(r.know), hex(KNOW));
    assert.equal(hex(r.trust), hex(TRUST));
  }
  assert.equal(hex(w.slice(10, 42)), hex(KNOW));
  assert.equal(hex(w.slice(42, 74)), hex(TRUST));
});

test('both-real, know-only and outside-both-sets recipients get the same length and header', () => {
  const both = build();
  const knowOnly = build({ trust: null });
  const outside = build({ know: null, trust: null });
  for (const w of [both, knowOnly, outside]) {
    assert.equal(w.length, EPOCH_NOTE_LEN);
    assert.equal(hex(w.slice(0, 2)), hex(EPOCH_NOTE_HEADER));
    assert.equal(reason(openEpochNote(w, AB)), 'ok');
  }
  assert.equal(hex(knowOnly.slice(10, 42)), hex(KNOW), 'the real know field is carried');
});

test('a decoy field opens exactly like a real one: the receiver gets 32 bytes and no marker', () => {
  const w = build({ trust: null, rand: () => DECOY.slice() });
  const r = openEpochNote(w, AB);
  assert.ok(r.ok);
  if (r.ok) assert.equal(hex(r.trust), hex(DECOY));
});

test('decoys are fresh for every recipient and every call, and two recipients outside both sets never share one', () => {
  const seen = new Set<string>();
  for (let i = 0; i < 20; i++) {
    const w = build({ know: null, trust: null });
    seen.add(hex(w.slice(10, 42)));
    seen.add(hex(w.slice(42, 74)));
  }
  assert.equal(seen.size, 40);
  const b1 = build({ fpReceiver: FP_B, know: null, trust: null });
  const b2 = build({ fpReceiver: createHash('sha256').update('b2').digest('hex'), know: null, trust: null });
  assert.notEqual(hex(b1.slice(10, 42)), hex(b2.slice(10, 42)));
});

// ── known answers (python reference) ────────────────────────────────────────────────────────────────────────

test('the MAC key is directional: A to B and B to A differ, and both match the python reference', () => {
  const ab = hex(deriveEpochMacKey(AB));
  const ba = hex(deriveEpochMacKey(BA));
  assert.notEqual(ab, ba);
  assert.equal(ab, '1947134a51d6cc7cc69f73b2cbd42741030c460bc606ab34564bfde4937d7157');
  assert.equal(ba, 'ff23ff76883fd06eb97f7074edc4257503f131c0f29f4e9381a2a800e563de70');
});

const KAT: Array<[string, EpochNoteContext, number, Uint8Array, Uint8Array | null, string]> = [
  [
    'A to B, e=1, both real', AB, 1, KNOW, TRUST,
    '45010000000000000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f55ef8f3cdda43a2d14c5033547a262cc9655d30a9d53077779e2dd29d6ae9b27',
  ],
  [
    'A to B, e=2^40+7, both real', AB, 2 ** 40 + 7, KNOW, TRUST,
    '45010000010000000007000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fe4c6fead98af67384d256f25ff811f9088c66ebdff4c23d223e5368765a8b804',
  ],
  [
    'A to B, e=1, know real + trust decoy', AB, 1, KNOW, null,
    '45010000000000000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fc8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7465ded0b995fd0e91808d816c82e3c778ba7d775ec5506af584c9f9a32089c54',
  ],
  [
    'B to A, e=1, both real', BA, 1, KNOW, TRUST,
    '45010000000000000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f30938f4690b35c08d7abc8890b78c4c2de1a163a14dfe5a903c13b1df13029e1',
  ],
];

test('built notes agree byte for byte with the independent python reference, and open under the same context', () => {
  assert.equal(FP_A, 'd4ee8e51f0109341808b418f37f9aa1a1d9553dac333449ce14d7d855e91db9e');
  for (const [name, ctx, epoch, know, trust, want] of KAT) {
    const w = buildEpochNote({ ...ctx, epoch, know, trust, rand: () => DECOY.slice() });
    assert.equal(hex(w), want, name);
    assert.deepEqual(hexToBytes(want).length, EPOCH_NOTE_LEN);
    assert.equal(reason(openEpochNote(hexToBytes(want), ctx)), 'ok', name);
  }
});
