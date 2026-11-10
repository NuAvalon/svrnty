// src/lib/crypto/lp-reader.test.ts — task #809: the shared strict reader.
// Run: npx tsx --test src/lib/crypto/lp-reader.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LpReader, LpParseError } from './lp-reader';
import { lpBin, u64be } from './lp-tlv';

const reason = (f: () => unknown) => { try { f(); } catch (e) { return e instanceof LpParseError ? e.reason : 'other'; } return 'ok'; };

test('R1 reads exactly what lp-tlv writes (round trip, KAT)', () => {
  const bytes = new Uint8Array([...lpBin(new Uint8Array([0xab])), ...u64be(258), 0x07]);
  assert.equal(Buffer.from(bytes).toString('hex'), '00000001ab' + '0000000000000102' + '07', 'the writer side is unchanged');
  const r = new LpReader(bytes);
  assert.deepEqual([...r.readLp(8)], [0xab]);
  assert.equal(r.readU64(), 258);
  assert.equal(r.readU8(), 7);
  r.finish();
});

test('R2 a length that points past the end is refused BEFORE any byte is taken', () => {
  assert.equal(reason(() => new LpReader(new Uint8Array([0, 0, 0, 9, 1, 2])).readLp(100)), 'length-overrun');
  assert.equal(reason(() => new LpReader(new Uint8Array([0, 0, 0, 3, 1, 2, 3])).readLp(2)), 'length-over-max', 'the declared maximum is checked first');
  assert.equal(reason(() => new LpReader(new Uint8Array([0xff, 0xff, 0xff, 0xff])).readLp(0xffffffff)), 'length-overrun', 'no allocation from a 4 GiB prefix');
});

test('R3 fixed reads are exact, trailing bytes are refused, integers must be safe', () => {
  assert.equal(reason(() => new LpReader(new Uint8Array(3)).readFixed(4)), 'truncated');
  assert.equal(reason(() => { const r = new LpReader(new Uint8Array(3)); r.readFixed(2); r.finish(); }), 'trailing-bytes');
  const big = new Uint8Array(8); new DataView(big.buffer).setBigUint64(0, BigInt('9007199254740992'), false);
  assert.equal(reason(() => new LpReader(big).readU64()), 'unsafe-integer');
  const ok = new Uint8Array(8); new DataView(ok.buffer).setBigUint64(0, BigInt(Number.MAX_SAFE_INTEGER), false);
  assert.equal(new LpReader(ok).readU64(), Number.MAX_SAFE_INTEGER);
});

test('R4 text is decoded strictly; the result is a copy, never an alias of the input', () => {
  assert.equal(reason(() => new LpReader(new Uint8Array([0, 0, 0, 1, 0xff])).readLpUtf8(8)), 'bad-utf8');
  assert.equal(new LpReader(lpBin(new TextEncoder().encode('é'))).readLpUtf8(8), 'é');
  const input = new Uint8Array([1, 2, 3]);
  const out = new LpReader(input).readFixed(3);
  out[0] = 99;
  assert.equal(input[0], 1, 'mutating the output does not change the input');
});

test('R5 a refusal is the reason and nothing else', () => {
  try { new LpReader(new Uint8Array([0, 0, 0, 9, 0xde, 0xad])).readLp(100); } catch (e) {
    assert.equal((e as Error).message, 'binary object refused (length-overrun)');
    assert.ok(!(e as Error).message.includes('de') && !(e as Error).message.includes('9'));
  }
});

test('R6 a Node Buffer input is copied once: changing it after, or during, the parse changes nothing', () => {
  const buf = Buffer.from([1, 2, 3, 4, 5, 6]);
  const r = new LpReader(buf);
  buf[2] = 99; buf[5] = 77;
  const a = r.readFixed(3);
  const b = r.readFixed(3);
  assert.deepEqual([...a, ...b], [1, 2, 3, 4, 5, 6]);
  a[0] = 42; // and what it returns is a copy of the private copy
  assert.equal(new LpReader(buf).readFixed(1)[0], 1);
});

test('R7 a leading BOM in a text field is KEPT, so a field means exactly its bytes', () => {
  assert.equal(new LpReader(new Uint8Array([0, 0, 0, 4, 0xef, 0xbb, 0xbf, 0x41])).readLpUtf8(8), '\uFEFFA');
});

test('R8 a maximum that is not a safe non-negative integer is refused, never skipped', () => {
  const bytes = new Uint8Array([0, 0, 0, 1, 7]);
  for (const bad of [NaN, undefined as unknown as number, -1, 1.5, Infinity]) assert.equal(reason(() => new LpReader(bytes).readLp(bad)), 'bad-field');
});
