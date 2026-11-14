/* eslint-disable @typescript-eslint/no-explicit-any -- test doubles and deliberately wrong inputs */
// src/lib/crypto/beacon-artifacts.test.ts
// #588 piece F (pin guards): the client must refuse proving files that are not byte-for-byte the pinned ones, BEFORE they reach the prover.
// Fail closed: a missing pin (no ceremony yet) refuses; the throwaway/prototype keys are just "a hash that is not the pin". Run:
//   npx tsx --test src/lib/crypto/beacon-artifacts.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { loadProvingFiles, ArtifactRefused, PINS, sha256Hex, type ArtifactPins } from './beacon-artifacts';

const sha = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
const bytes = (n: number, fill = 7) => new Uint8Array(n).fill(fill);
const WASM = bytes(1000, 1), ZKEY = bytes(5000, 2);
const pins = (over: Partial<ArtifactPins> = {}): ArtifactPins => ({ wasmSha256: sha(WASM), zkeySha256: sha(ZKEY), ...over });
const server = (map: Record<string, Uint8Array>) => async (url: string) => {
  if (!(url in map)) throw new Error('404 ' + url);
  return map[url];
};
const URLS = { wasm: '/zk/slotbind.wasm', zkey: '/zk/slotbind_final.zkey' };
const good = server({ [URLS.wasm]: WASM, [URLS.zkey]: ZKEY });
const reasonOf = async (p: Promise<unknown>) => { try { await p; return 'NO-THROW'; } catch (e) { return e instanceof ArtifactRefused ? e.reason : 'OTHER:' + (e as Error).message; } };

test('F1 sha256Hex is the standard digest (matches node crypto) as lowercase hex', async () => {
  for (const n of [0, 1, 55, 56, 64, 1000]) { const b = bytes(n, n & 255); assert.equal(await sha256Hex(b), sha(b)); }
});

test('F2 files that equal the pins are returned untouched, and the same bytes', async () => {
  const f = await loadProvingFiles(good, URLS, pins());
  assert.equal(sha(f.wasm), sha(WASM)); assert.equal(sha(f.zkey), sha(ZKEY));
});

test('F3 a wasm that is not the pinned one is refused with reason wasm-hash (one flipped byte is enough)', async () => {
  const bad = new Uint8Array(WASM); bad[500] ^= 1;
  assert.equal(await reasonOf(loadProvingFiles(server({ [URLS.wasm]: bad, [URLS.zkey]: ZKEY }), URLS, pins())), 'wasm-hash');
});

test('F4 a zkey that is not the pinned one is refused with reason zkey-hash (the prototype/throwaway key case)', async () => {
  const proto = bytes(5000, 3);
  assert.equal(await reasonOf(loadProvingFiles(server({ [URLS.wasm]: WASM, [URLS.zkey]: proto }), URLS, pins())), 'zkey-hash');
});

test('F5 NO PIN YET (the ceremony has not run): the zkey is refused as zkey-unpinned, never "accepted because there is nothing to compare to"', async () => {
  assert.equal(await reasonOf(loadProvingFiles(good, URLS, pins({ zkeySha256: null }))), 'zkey-unpinned');
  assert.equal(PINS.zkeySha256, null, 'the shipped pins hold no zkey pin until the ceremony output exists (H7)');
});

test('F6 a malformed pin (wrong length, uppercase, not hex) is refused as pin-format, not silently compared', async () => {
  for (const bad of ['', 'abc', sha(WASM).toUpperCase(), sha(WASM).slice(0, 63), sha(WASM) + '0', 'g'.repeat(64)]) {
    assert.equal(await reasonOf(loadProvingFiles(good, URLS, pins({ wasmSha256: bad }))), 'pin-format', bad.slice(0, 12));
  }
});

test('F7 the shipped wasm pin is the circom 2.2.3 build of slotbind (pins.json wasm_sha256["2.2.3"])', () => {
  assert.equal(PINS.wasmSha256, '3f603c198ba712cb8fb3e34f59bbf75c445ddd8cf3596a305ea57c31000083be');
});

test('F8 size caps: an oversized wasm or zkey is refused BEFORE hashing (reason size)', async () => {
  const huge = { wasm: async () => new Uint8Array(0) };
  void huge;
  const bigWasm = new Uint8Array(8 * 1024 * 1024 + 1);
  assert.equal(await reasonOf(loadProvingFiles(server({ [URLS.wasm]: bigWasm, [URLS.zkey]: ZKEY }), URLS, pins())), 'size');
  const bigKey = new Uint8Array(96 * 1024 * 1024 + 1);
  assert.equal(await reasonOf(loadProvingFiles(server({ [URLS.wasm]: WASM, [URLS.zkey]: bigKey }), URLS, pins())), 'size');
});

test('F9 a fetch failure or a non-bytes answer is a refusal with a fixed reason, never a thrown body', async () => {
  assert.equal(await reasonOf(loadProvingFiles(server({}), URLS, pins())), 'fetch');
  assert.equal(await reasonOf(loadProvingFiles((async () => 'not bytes') as any, URLS, pins())), 'fetch');
});

test('F10 the check order: the cheap pin-format and unpinned refusals happen BEFORE any download', async () => {
  let calls = 0;
  const counting = async (u: string) => { calls++; return good(u); };
  await reasonOf(loadProvingFiles(counting, URLS, pins({ zkeySha256: null })));
  await reasonOf(loadProvingFiles(counting, URLS, pins({ wasmSha256: 'nope' })));
  assert.equal(calls, 0);
});

test('F11 refusal messages are fixed strings: no hash, url or byte of either file appears in them', async () => {
  try { await loadProvingFiles(server({ [URLS.wasm]: bytes(1000, 9), [URLS.zkey]: ZKEY }), URLS, pins()); assert.fail('should refuse'); }
  catch (e: any) { assert.ok(e instanceof ArtifactRefused); assert.equal(e.message, 'refused: wasm-hash'); assert.ok(!e.message.includes(sha(WASM)) && !e.message.includes(URLS.wasm)); assert.equal(e.cause, undefined); }
});
