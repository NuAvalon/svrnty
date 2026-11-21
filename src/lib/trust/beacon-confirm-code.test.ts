/* eslint-disable @typescript-eslint/no-explicit-any -- deliberately wrong inputs */
// src/lib/trust/beacon-confirm-code.test.ts: the code two phones compare, screen to screen, to confirm that each holds the other's CURRENT beacon key,
// and the one rule that turns a matching entry into a confirm. Pure: no store, no network, no clock.
// Run: npx tsx --test src/lib/trust/beacon-confirm-code.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { confirmCode, codesMatch, decideConfirmFromCompare, CONFIRM_DOMAIN, NONCE_BYTES, type KeyView } from './beacon-confirm-code';

const bytes = (n: number, fill: number): Uint8Array => new Uint8Array(n).fill(fill);
const A: KeyView = { pub: bytes(32, 0x11), gen: 1_800_000_001 };
const B: KeyView = { pub: bytes(32, 0x22), gen: 1_800_000_002 };
const NONCE = Uint8Array.from({ length: NONCE_BYTES }, (_, i) => i + 1);

// An independent reading of the specification (node:crypto, plain BigInt), so the module is not only checked against itself.
const lp = (b: Uint8Array): Buffer => { const h = Buffer.alloc(4); h.writeUInt32BE(b.length); return Buffer.concat([h, b]); };
const pairBytes = (k: KeyView): Buffer => { const g = Buffer.alloc(8); g.writeBigUInt64BE(BigInt(k.gen)); return Buffer.concat([Buffer.from(k.pub), g]); };
function reference(own: KeyView, held: KeyView, nonce: Uint8Array, domain = CONFIRM_DOMAIN): string {
  const pairs = [pairBytes(own), pairBytes(held)].sort(Buffer.compare);
  const d = createHash('sha256').update(Buffer.concat([lp(Buffer.from(domain)), lp(pairs[0]), lp(pairs[1]), lp(nonce)])).digest();
  return (d.readBigUInt64BE(0) % BigInt(1_000_000)).toString().padStart(6, '0');
}
const code = (own: KeyView, held: KeyView, nonce = NONCE): string => {
  const r = confirmCode(own, held, nonce);
  assert.equal(r.ok, true, JSON.stringify(r));
  return (r as { ok: true; code: string }).code;
};

// ---------- the code ----------
test('CC1 the code is exactly the specified derivation: it equals an independent reference, and one fixed vector is pinned', () => {
  assert.equal(code(A, B), reference(A, B, NONCE));
  assert.equal(code(B, A), reference(B, A, NONCE));
  assert.match(code(A, B), /^[0-9]{6}$/);
  assert.equal(code(A, B), '409689');
});

test('CC2 role independence: the phone that holds (own A, held B) and the phone that holds (own B, held A) show the SAME code', () => {
  assert.equal(code(A, B), code(B, A));
});

test('CC3 every input matters: either key, either generation and the nonce each change the code (a stale or substituted key on either side gives a mismatch)', () => {
  const base = code(A, B);
  const flip = (k: KeyView): KeyView => { const p = k.pub.slice(); p[0] ^= 0x01; return { pub: p, gen: k.gen }; };
  const bump = (k: KeyView): KeyView => ({ pub: k.pub, gen: k.gen + 1 });
  const other = NONCE.slice(); other[0] ^= 0x01;
  assert.notEqual(code(flip(A), B), base, 'own key');
  assert.notEqual(code(A, flip(B)), base, 'held key');
  assert.notEqual(code(bump(A), B), base, 'own generation');
  assert.notEqual(code(A, bump(B)), base, 'held generation');
  assert.notEqual(code(A, B, other), base, 'nonce');
  assert.notEqual(reference(A, B, NONCE, CONFIRM_DOMAIN + 'x'), base, 'the domain tag is part of the input');
});

test('CC4 the two sides disagree when one holds a STALE key for the other: A holds B\'s old key, B holds A\'s current key', () => {
  const bOld: KeyView = { pub: bytes(32, 0x23), gen: 1_700_000_000 };
  assert.notEqual(code(A, bOld), code(B, A), 'A shows a code over {A, bOld}; B shows one over {B, A}');
});

test('CC5 the code is always 6 digits, zero-padded', () => {
  let leading = 0;
  for (let i = 0; i < 4000 && leading < 3; i++) {
    const n = Uint8Array.from({ length: NONCE_BYTES }, (_, j) => (i >> (8 * (j % 2))) & 0xff);
    const c = code(A, B, n);
    assert.equal(c.length, 6);
    assert.match(c, /^[0-9]{6}$/);
    if (c.startsWith('0')) leading++;
  }
  assert.ok(leading >= 1, 'the search must have met a code with a leading zero');
});

test('CC6a generations above 2^32 are encoded in full: the high half is part of the code and the code equals the reference', () => {
  const big = (g: number): KeyView => ({ pub: B.pub, gen: g });
  const TWO32 = 4294967296;
  for (const g of [TWO32 + 7, 2 * TWO32, 1099511627783, Number.MAX_SAFE_INTEGER]) assert.equal(code(A, big(g)), reference(A, big(g), NONCE), `generation ${g}`);
  assert.notEqual(code(A, big(7)), code(A, big(TWO32 + 7)), 'generations that differ only in the high 32 bits must not collide');
  assert.notEqual(code(A, big(TWO32 + 7)), code(A, big(2 * TWO32 + 7)));
});

test('CC6 inputs are never mutated', () => {
  const a: KeyView = { pub: A.pub.slice(), gen: A.gen }, b: KeyView = { pub: B.pub.slice(), gen: B.gen }, n = NONCE.slice();
  code(a, b, n);
  assert.deepEqual(a.pub, A.pub); assert.deepEqual(b.pub, B.pub); assert.deepEqual(n, NONCE);
});

test('CC7 refusals: a malformed own key, held key or nonce, and a REFLECTED key (held equals own), each give a typed reason and never throw', () => {
  const badKeys: any[] = [undefined, null, 'x', {}, { pub: bytes(31, 1), gen: 1 }, { pub: bytes(33, 1), gen: 1 }, { pub: 'a'.repeat(32), gen: 1 },
    { pub: bytes(32, 1), gen: 0 }, { pub: bytes(32, 1), gen: -1 }, { pub: bytes(32, 1), gen: 1.5 }, { pub: bytes(32, 1), gen: NaN },
    { pub: bytes(32, 1), gen: Number.MAX_SAFE_INTEGER + 1 }, { pub: bytes(32, 1), gen: '5' }];
  for (const k of badKeys) {
    assert.deepEqual(confirmCode(k, B, NONCE), { ok: false, reason: 'own-key' }, `own ${JSON.stringify(k)}`);
    assert.deepEqual(confirmCode(A, k, NONCE), { ok: false, reason: 'held-key' }, `held ${JSON.stringify(k)}`);
  }
  const badNonces: any[] = [undefined, null, 'abc', bytes(15, 1), bytes(17, 1), bytes(0, 0), [1, 2, 3]];
  for (const n of badNonces) assert.deepEqual(confirmCode(A, B, n), { ok: false, reason: 'nonce' }, `nonce ${JSON.stringify(n)}`);
  assert.deepEqual(confirmCode(A, { pub: A.pub.slice(), gen: A.gen + 5 }, NONCE), { ok: false, reason: 'reflected' }, 'the same key under another generation is still a reflection');
  assert.deepEqual(confirmCode(A, A, NONCE), { ok: false, reason: 'reflected' });
});

test('CC8 a reflected key is refused BEFORE the other checks cannot hide it: a reflection with a bad nonce reports the nonce, a reflection with good inputs reports the reflection', () => {
  assert.deepEqual(confirmCode(A, A, bytes(3, 1)), { ok: false, reason: 'nonce' });
  assert.deepEqual(confirmCode(A, A, NONCE), { ok: false, reason: 'reflected' });
});

// ---------- the typed entry ----------
test('CC9 codesMatch: only two identical 6-digit strings match; whitespace, letters, short, long and non-strings never do', () => {
  assert.equal(codesMatch('048213', '048213'), true);
  assert.equal(codesMatch('048213', '048214'), false);
  for (const typed of [' 048213', '048213 ', '04 8213', '48213', '0482130', 'abcdef', '', '048-213', '٠٤٨٢١٣', undefined, null, 48213, 48213.0] as any[]) {
    assert.equal(codesMatch(typed, '048213'), false, `typed ${JSON.stringify(typed)}`);
  }
  assert.equal(codesMatch('048213', 'abcdef'), false, 'a computed value that is not a 6-digit code never matches itself');
  assert.equal(codesMatch('abcdef', 'abcdef'), false);
});

// ---------- the rule ----------
const keys = (own: KeyView, held: KeyView) => ({ own, held });
const S = keys(A, B);

test('CD1 a match with both keys unchanged since the session started confirms, at the generation of the HELD key that was compared', () => {
  assert.deepEqual(decideConfirmFromCompare('match', S, keys(A, B)), { confirm: true, generation: B.gen });
  assert.deepEqual(decideConfirmFromCompare('match', S, keys({ pub: A.pub.slice(), gen: A.gen }, { pub: B.pub.slice(), gen: B.gen })), { confirm: true, generation: B.gen });
});

test('CD2 a mismatch NEVER confirms, whatever the keys', () => {
  assert.deepEqual(decideConfirmFromCompare('mismatch', S, keys(A, B)), { confirm: false, reason: 'mismatch' });
  assert.deepEqual(decideConfirmFromCompare('mismatch', S, keys(B, A)), { confirm: false, reason: 'mismatch' });
});

test('CD3 a match is refused when the own key or the held key changed since the session started (a different key, or the same key under a new generation)', () => {
  const flip = (k: KeyView): KeyView => { const p = k.pub.slice(); p[31] ^= 0x80; return { pub: p, gen: k.gen }; };
  assert.deepEqual(decideConfirmFromCompare('match', S, keys(flip(A), B)), { confirm: false, reason: 'own-changed' });
  assert.deepEqual(decideConfirmFromCompare('match', S, keys({ pub: A.pub, gen: A.gen + 1 }, B)), { confirm: false, reason: 'own-changed' });
  assert.deepEqual(decideConfirmFromCompare('match', S, keys(A, flip(B))), { confirm: false, reason: 'held-changed' });
  assert.deepEqual(decideConfirmFromCompare('match', S, keys(A, { pub: B.pub, gen: B.gen + 1 })), { confirm: false, reason: 'held-changed' });
});

test('CD4 anything malformed, or an entry that is not exactly "match", is refused as invalid or as a mismatch and never confirms', () => {
  const junk: any[] = [undefined, null, {}, { own: A }, { own: A, held: { pub: bytes(5, 1), gen: 1 } }, { own: { pub: bytes(32, 1), gen: 0 }, held: B }];
  for (const j of junk) {
    assert.deepEqual(decideConfirmFromCompare('match', j, keys(A, B)), { confirm: false, reason: 'invalid' }, `start ${JSON.stringify(j)}`);
    assert.deepEqual(decideConfirmFromCompare('match', S, j), { confirm: false, reason: 'invalid' }, `now ${JSON.stringify(j)}`);
  }
  for (const e of ['MATCH', 'matched', '', undefined, null, true, 1] as any[]) {
    assert.equal(decideConfirmFromCompare(e, S, keys(A, B)).confirm, false, `entry ${JSON.stringify(e)}`);
  }
});
