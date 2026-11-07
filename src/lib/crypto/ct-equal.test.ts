// The shared constant-time compare: equal inputs are true; a difference in ANY single byte, at ANY position, in ANY bit, is false; a length
// mismatch is false, including a prefix of the other. The loop must visit every byte (the first-byte-only and early-exit mutants go RED).
//
// Run: npx tsx --test src/lib/crypto/ct-equal.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ctEqual } from './ct-equal';

const bytes = (n: number, fill = 0): Uint8Array => new Uint8Array(n).fill(fill);

test('equal inputs are true, including empty and a copy', () => {
  assert.equal(ctEqual(new Uint8Array(0), new Uint8Array(0)), true);
  const a = Uint8Array.from({ length: 64 }, (_, i) => (i * 37 + 11) & 255);
  assert.equal(ctEqual(a, a), true);
  assert.equal(ctEqual(a, new Uint8Array(a)), true);
});

test('a difference in any single byte at any position is false (all 32 positions, every bit)', () => {
  for (const len of [1, 2, 31, 32, 33]) {
    for (let pos = 0; pos < len; pos++) {
      for (let bit = 0; bit < 8; bit++) {
        const a = bytes(len, 0xa5);
        const b = new Uint8Array(a);
        b[pos] ^= 1 << bit;
        assert.equal(ctEqual(a, b), false, `len ${len} pos ${pos} bit ${bit}`);
        assert.equal(ctEqual(b, a), false, `reversed: len ${len} pos ${pos} bit ${bit}`);
      }
    }
  }
});

test('the last byte alone differing is false (a loop that stops early or checks only the head would pass this as true)', () => {
  const a = bytes(32, 7);
  const b = new Uint8Array(a);
  b[31] = 8;
  assert.equal(ctEqual(a, b), false);
});

test('a length mismatch is false, including a prefix of the other and empty vs non-empty', () => {
  assert.equal(ctEqual(bytes(32), bytes(31)), false);
  assert.equal(ctEqual(bytes(31), bytes(32)), false);
  assert.equal(ctEqual(new Uint8Array(0), bytes(1)), false);
  assert.equal(ctEqual(bytes(1), new Uint8Array(0)), false);
});

test('inputs are never modified', () => {
  const a = Uint8Array.from([1, 2, 3]);
  const b = Uint8Array.from([1, 2, 4]);
  ctEqual(a, b);
  assert.deepEqual([...a], [1, 2, 3]);
  assert.deepEqual([...b], [1, 2, 4]);
});

test('GUARD: the three callers import the shared helper and keep no private copy of the loop', () => {
  const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');
  const receipt = read('./receipt-mac.ts');
  const ratchet = read('./message-ratchet.ts');
  const epochNote = read('../trust/psi-epoch-note.ts');
  assert.match(receipt, /import \{ ctEqual \} from '\.\/ct-equal'/);
  assert.match(ratchet, /import \{ ctEqual \} from '\.\/ct-equal'/);
  assert.match(epochNote, /import \{ ctEqual \} from '\.\.\/crypto\/ct-equal'/);
  for (const [name, src] of [['receipt-mac', receipt], ['message-ratchet', ratchet], ['psi-epoch-note', epochNote]] as const) {
    assert.doesNotMatch(src, /\^ b\[i\]/, `${name} still has an inline byte-compare loop`);
    assert.doesNotMatch(src, /function (ctEqual|bytesEq)\(/, `${name} still defines a private compare`);
  }
  assert.match(receipt, /ctEqual\(receiptTag\(rk, noteId, code\), got\)/, 'the receipt tag is compared with the shared helper');
  assert.match(ratchet, /ctEqual\(parsed\.dh, this\.theirDh\)/, 'the ratchet DH is compared with the shared helper');
  assert.match(epochNote, /ctEqual\(tagOf\(ctx, epoch, know, trust\), got\)/, 'the epoch-note tag is compared with the shared helper');
  assert.match(epochNote, /function sameBytes\(a: Uint8Array, b: Uint8Array\): boolean \{\s*return ctEqual\(a, b\);/, 'sameBytes is the shared helper');
});
