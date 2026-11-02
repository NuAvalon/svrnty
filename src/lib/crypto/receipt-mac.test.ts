// src/lib/crypto/receipt-mac.test.ts
// S62 A5-d receipt MAC (Flint ruling 36b079e8). The VECTORS below come from an INDEPENDENT stdlib-only Python reference written from the spec
// (outbox s62_receipt_mac_v1/reference.py); the TypeScript must reproduce them byte for byte.
// Run: npx tsx --test src/lib/crypto/receipt-mac.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  RECEIPT_CODES,
  RECEIPT_KEY_BYTES,
  newReceiptKey,
  receiptKeyFromHex,
  receiptKeyToHex,
  receiptTag,
  verifyReceiptTag,
  type ReceiptCode,
} from './receipt-mac';

const VECTORS: Array<{ rk: string; note_id: string; code: ReceiptCode; tag: string }> = [
  { rk: "0000000000000000000000000000000000000000000000000000000000000000", note_id: "note_1", code: "delivered", tag: "8767842e63c809723d91a3c29d29214c0ec179b6dde093705d9f2c71ce3bf5be" },
  { rk: "0000000000000000000000000000000000000000000000000000000000000000", note_id: "note_1", code: "read", tag: "399c255ad126f15be93040bb6973e2702a7eced62f5e7695754f4b0bb5657465" },
  { rk: "0000000000000000000000000000000000000000000000000000000000000000", note_id: "note_1", code: "couldnt_verify", tag: "ca5e9279733be9c170fdaa60ed715f805fd15da22f2dc0d0a1136eafbcc13b6c" },
  { rk: "0000000000000000000000000000000000000000000000000000000000000000", note_id: "note_2", code: "delivered", tag: "ee81a3d557b298ff883aaba0600789852dc821fcce7a258ff602bf6d3c2a841d" },
  { rk: "0101010101010101010101010101010101010101010101010101010101010101", note_id: "note_1", code: "delivered", tag: "09f79e1c42e43a9dca2632abd69a94cfc22e406602e62619a150a18cb490369d" },
  { rk: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", note_id: "note_8f3a-ünï-💬", code: "delivered", tag: "094a8d87a1d695a6eaae93a0eec387162bd4aca70669560abd0db7a013bba15c" },
  { rk: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", note_id: "x", code: "read", tag: "5ab90bf4854185384fae9819c0cd3320c1fdf577e7cdc15b5b8f9ab9e3ca18e0" },
  { rk: "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", note_id: "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn", code: "delivered", tag: "a120756d41e6b61a8a52f022657e66b7ad2bde6937233b95e0d0455a5f80e732" }
];
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const rkOf = (h: string) => receiptKeyFromHex(h)!;
const RK = rkOf('00'.repeat(32));

test('R1 every independent-reference vector is reproduced byte for byte (incl. unicode/emoji and a 300-char note id)', () => {
  assert.equal(VECTORS.length, 8);
  for (const v of VECTORS) assert.equal(hex(receiptTag(rkOf(v.rk), v.note_id, v.code)), v.tag, `${v.note_id.slice(0, 12)} ${v.code}`);
  assert.equal(new Set(VECTORS.map((v) => v.tag)).size, VECTORS.length, 'all vectors distinct');
});

test('R2 a correct tag verifies, as bytes and as hex (either case)', () => {
  const v = VECTORS[0];
  const t = receiptTag(RK, v.note_id, v.code);
  assert.equal(verifyReceiptTag(RK, v.note_id, v.code, t), true);
  assert.equal(verifyReceiptTag(RK, v.note_id, v.code, v.tag), true);
  assert.equal(verifyReceiptTag(RK, v.note_id, v.code, v.tag.toUpperCase()), true);
});

test('R3 the CODE is inside the MAC: a delivered tag is refused as read / couldnt_verify, and unknown codes are refused', () => {
  const t = receiptTag(RK, 'note_1', 'delivered');
  assert.equal(verifyReceiptTag(RK, 'note_1', 'read', t), false);
  assert.equal(verifyReceiptTag(RK, 'note_1', 'couldnt_verify', t), false);
  for (const bad of ['', 'Delivered', 'DELIVERED', 'delivered ', 'ack', undefined, null, 1, {}]) assert.equal(verifyReceiptTag(RK, 'note_1', bad, t), false, JSON.stringify(bad));
  // every ordered pair of distinct codes yields a different tag
  for (const a of RECEIPT_CODES) for (const b of RECEIPT_CODES) if (a !== b) assert.notEqual(hex(receiptTag(RK, 'note_1', a)), hex(receiptTag(RK, 'note_1', b)));
});

test('R4 the NOTE is bound: a tag for one note id is refused for another (no cross-note replay)', () => {
  const t = receiptTag(RK, 'note_1', 'delivered');
  assert.equal(verifyReceiptTag(RK, 'note_2', 'delivered', t), false);
  assert.equal(verifyReceiptTag(RK, 'note_1 ', 'delivered', t), false);
  assert.equal(verifyReceiptTag(RK, 'Note_1', 'delivered', t), false);
});

test('R5 the KEY is bound: another rk is refused; a wrong-length rk is `false` on verify (never a throw) and a throw on emit', () => {
  const t = receiptTag(RK, 'note_1', 'delivered');
  assert.equal(verifyReceiptTag(rkOf('01'.repeat(32)), 'note_1', 'delivered', t), false);
  for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0), 'x' as never, null as never]) {
    assert.equal(verifyReceiptTag(bad as Uint8Array, 'note_1', 'delivered', t), false);
    assert.throws(() => receiptTag(bad as Uint8Array, 'note_1', 'delivered'));
  }
  assert.throws(() => receiptTag(RK, '', 'delivered'));
  assert.throws(() => receiptTag(RK, 'n', 'nope' as never));
});

test('R6 flipping ANY single bit of the tag is refused (all 256 positions)', () => {
  const t = receiptTag(RK, 'note_1', 'delivered');
  for (let bit = 0; bit < 256; bit++) {
    const x = new Uint8Array(t);
    x[bit >> 3] ^= 1 << (bit & 7);
    assert.equal(verifyReceiptTag(RK, 'note_1', 'delivered', x), false, `bit ${bit}`);
  }
});

test('R7 malformed tags are `false`, never a throw: wrong length, non-hex, 63/65 hex chars, empty, wrong types', () => {
  const good = hex(receiptTag(RK, 'note_1', 'delivered'));
  const bads: unknown[] = ['', good.slice(1), good + '0', 'zz'.repeat(32), good.slice(0, 62) + 'g0', ' ' + good, good + '\n', null, undefined, 5, {}, [], new Uint8Array(31), new Uint8Array(33), new Uint8Array(0)];
  for (const bad of bads) assert.equal(verifyReceiptTag(RK, 'note_1', 'delivered', bad as never), false, JSON.stringify(bad));
});

test('R8 done_when C1 NEG: receipt keys are 32 bytes from the CSPRNG and never repeat (two notes never share rk)', () => {
  const seen = new Set<string>();
  for (let i = 0; i < 1000; i++) {
    const k = newReceiptKey();
    assert.equal(k.length, RECEIPT_KEY_BYTES);
    seen.add(hex(k));
  }
  assert.equal(seen.size, 1000);
  assert.notEqual(hex(newReceiptKey()), '00'.repeat(32));
});

test('R9 hex form: strict 64 hex chars both ways; round trip; anything else is null', () => {
  const k = newReceiptKey();
  assert.deepEqual(receiptKeyFromHex(receiptKeyToHex(k)), k);
  assert.deepEqual(receiptKeyFromHex(receiptKeyToHex(k).toUpperCase()), k);
  for (const bad of ['', '00'.repeat(31), '00'.repeat(33), 'zz'.repeat(32), ' ' + '00'.repeat(32), '0x' + '00'.repeat(31), null, undefined, 7, {}]) assert.equal(receiptKeyFromHex(bad), null, JSON.stringify(bad));
  assert.throws(() => receiptKeyToHex(new Uint8Array(31)));
});

test('R10 domain separation: the same inputs under another domain or without the per-note HKDF info give a different tag', () => {
  const enc = new TextEncoder();
  const lp = (b: Uint8Array) => { const o = new Uint8Array(4 + b.length); new DataView(o.buffer).setUint32(0, b.length, false); o.set(b, 4); return o; };
  const cat = (...p: Uint8Array[]) => { const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };
  const mac = (domain: string, info: string) => hex(hmac(sha256, hkdf(sha256, RK, enc.encode(domain), enc.encode(info), 32), cat(lp(enc.encode(domain)), lp(enc.encode('note_1')), lp(enc.encode('delivered')))));
  const real = hex(receiptTag(RK, 'note_1', 'delivered'));
  assert.equal(mac('svrnty:receipt:v2', 'note_1'), real, 'my re-derivation matches the module');
  assert.notEqual(mac('svrnty:receipt:v1', 'note_1'), real, 'the old v1 domain is not accepted');
  assert.notEqual(mac('svrnty:receipt:v2', ''), real, 'the per-note HKDF info matters');
});

test('R11 NO SIGNATURE, NO PUBLIC KEY (A5-d): the verify API takes rk and nothing else; the module imports only hash primitives', () => {
  assert.equal(verifyReceiptTag.length, 4, '(rk, noteId, code, tag): no card, no public key, no signature parameter');
  const src = readFileSync(new URL('./receipt-mac.ts', import.meta.url), 'utf8');
  const imports = [...src.matchAll(/^import .* from '([^']+)';/gm)].map((m) => m[1]).sort();
  assert.deepEqual(imports, ['@noble/hashes/hkdf.js', '@noble/hashes/hmac.js', '@noble/hashes/sha2.js']);
  assert.doesNotMatch(src.replace(/\/\/.*$/gm, ''), /ed25519|ml-?dsa|openpgp|signWithEnvelope|verifyWithEnvelope|fingerprint|public_?key/i);
});

test('R12 static: the tag comparison is the constant-time helper (no early return in its loop, no === / equals on tag bytes)', () => {
  const src = readFileSync(new URL('./receipt-mac.ts', import.meta.url), 'utf8');
  const ct = src.slice(src.indexOf('function ctEqual'));
  const loop = ct.slice(ct.indexOf('for ('), ct.indexOf(';', ct.indexOf('diff |=')) + 1);
  assert.match(loop, /^for \(let i = 0; i < a\.length; i\+\+\) diff \|= a\[i\] \^ b\[i\];$/, 'the loop accumulates the difference over every byte');
  assert.doesNotMatch(loop, /return|break|throw|continue/, 'no early exit inside the comparison loop');
  const verify = src.slice(src.indexOf('export function verifyReceiptTag'));
  assert.match(verify, /ctEqual\(receiptTag\(/);
  assert.doesNotMatch(verify, /===\s*got|got\s*===|\.equals\(|Buffer\.compare|timingSafe/);
});

test('R13 truncation / zero-padding cannot pass: a tag whose last byte is 0x00 is refused as a 31-byte prefix and as a 33-byte padded copy', () => {
  let found = '';
  for (let i = 0; i < 20000 && !found; i++) {
    const id = `note_${i}`;
    if (receiptTag(RK, id, 'delivered')[31] === 0) found = id;
  }
  assert.ok(found, 'a note id whose tag ends in 0x00 exists within the search (about 1 in 256)');
  const t = receiptTag(RK, found, 'delivered');
  assert.equal(verifyReceiptTag(RK, found, 'delivered', t), true, 'control: the full tag verifies');
  assert.equal(verifyReceiptTag(RK, found, 'delivered', t.slice(0, 31)), false, '31-byte prefix');
  const padded = new Uint8Array(33);
  padded.set(t);
  assert.equal(verifyReceiptTag(RK, found, 'delivered', padded), false, '33-byte zero-padded');
  assert.equal(verifyReceiptTag(RK, found, 'delivered', hex(t.slice(0, 31))), false, '62-hex prefix');
});
