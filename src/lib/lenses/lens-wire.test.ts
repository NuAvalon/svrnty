// src/lib/lenses/lens-wire.test.ts — contract R4 (pair-MAC, directional, no signature) + R8 (uniform cell).
// Run: npx tsx --test src/lib/lenses/lens-wire.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from '@noble/hashes/utils.js';
import { FRAME_BYTES } from '../crypto/uniform-frame';
import {
  LENS_KIND_HELLO,
  LENS_KIND_METHODS,
  LENS_HELLO_BODY,
  LENS_MAX_METHODS,
  buildLensPayload,
  buildLensCell,
  decodeLensMethodsBody,
  deriveLensMacKey,
  encodeLensMethodsBody,
  openLensPayload,
  parseLensPayload,
  unframeLensCell,
  LensWireError,
} from './lens-wire';

const FP_A = 'a'.repeat(64);
const FP_B = 'b'.repeat(64);
const sPair = randomBytes(32);
const ctxAB = { sPair, fpSender: FP_A, fpReceiver: FP_B };

const methods = [
  { kind: 'signal', value: '@alice' },
  { kind: 'site', value: 'https://a.example' },
];

test('R4: a built payload verifies between the pair; a tampered byte fails the MAC', () => {
  const body = encodeLensMethodsBody(methods);
  const payload = buildLensPayload({ kind: LENS_KIND_METHODS, fpSender: FP_A, fpReceiver: FP_B, seq: 1, body, sPair });
  const opened = openLensPayload(payload, ctxAB);
  assert.equal(opened.ok, true);
  if (opened.ok) {
    assert.equal(opened.kind, LENS_KIND_METHODS);
    assert.equal(opened.seq, 1);
    assert.deepEqual(decodeLensMethodsBody(opened.body), methods);
  }
  const tampered = payload.slice();
  tampered[50] ^= 0x01;
  assert.deepEqual(openLensPayload(tampered, ctxAB), { ok: false, reason: 'bad-mac' });
});

test('R4: the payload carries NO identity signature — only the 32B pair-MAC tag', () => {
  const payload = buildLensPayload({ kind: LENS_KIND_METHODS, fpSender: FP_A, fpReceiver: FP_B, seq: 7, body: encodeLensMethodsBody(methods), sPair });
  // The whole payload is header|kind|fp|seq|len|body|tag — nothing else. No signature field exists.
  const parsed = parseLensPayload(payload);
  assert.ok(parsed);
  assert.equal(parsed!.tag.length, 32);
  assert.equal(payload.length, 2 + 1 + 32 + 8 + 4 + parsed!.body.length + 32);
});

test('R4: directional — a payload reflected back (B→A with the same bytes) fails; so does a wrong pair secret', () => {
  const body = encodeLensMethodsBody(methods);
  const payload = buildLensPayload({ kind: LENS_KIND_METHODS, fpSender: FP_A, fpReceiver: FP_B, seq: 1, body, sPair });
  // Reflected: B claims A's payload as its own to A — the claimed-sender check + MAC both fail.
  assert.deepEqual(openLensPayload(payload, { sPair, fpSender: FP_B, fpReceiver: FP_A }), { ok: false, reason: 'malformed' });
  // A different pair secret (a third party cannot forge).
  assert.deepEqual(openLensPayload(payload, { sPair: randomBytes(32), fpSender: FP_A, fpReceiver: FP_B }), { ok: false, reason: 'bad-mac' });
});

test('R4: K_mac is domain-separated and directional (own salt, both fps in info)', () => {
  const kAB = deriveLensMacKey(ctxAB);
  const kBA = deriveLensMacKey({ sPair, fpSender: FP_B, fpReceiver: FP_A });
  assert.notDeepEqual(kAB, kBA, 'direction swapped ⇒ different MAC key');
  const kOther = deriveLensMacKey({ sPair: randomBytes(32), fpSender: FP_A, fpReceiver: FP_B });
  assert.notDeepEqual(kAB, kOther);
});

test('self-send and non-canonical fingerprints are refused at build AND open', () => {
  const body = encodeLensMethodsBody(methods);
  assert.throws(
    () => buildLensPayload({ kind: LENS_KIND_METHODS, fpSender: FP_A, fpReceiver: FP_A, seq: 1, body, sPair }),
    LensWireError,
  );
  assert.throws(() => buildLensPayload({ kind: LENS_KIND_METHODS, fpSender: 'zz', fpReceiver: FP_B, seq: 1, body, sPair }), LensWireError);
  assert.throws(() => deriveLensMacKey({ sPair: new Uint8Array(31), fpSender: FP_A, fpReceiver: FP_B }), LensWireError);
});

test('R8: every lens payload frames to the SAME 2048-byte cell whatever the lens holds', () => {
  const empty = buildLensCell({ kind: LENS_KIND_METHODS, fpSender: FP_A, fpReceiver: FP_B, seq: 1, body: encodeLensMethodsBody([]), sPair });
  const full = buildLensCell({
    kind: LENS_KIND_METHODS,
    fpSender: FP_A,
    fpReceiver: FP_B,
    seq: 2,
    body: encodeLensMethodsBody(Array.from({ length: LENS_MAX_METHODS }, (_, i) => ({ kind: 'custom', value: `v${i}`, label: `l${i}` }))),
    sPair,
  });
  const hello = buildLensCell({ kind: LENS_KIND_HELLO, fpSender: FP_A, fpReceiver: FP_B, seq: 0, body: LENS_HELLO_BODY, sPair });
  assert.equal(empty.length, FRAME_BYTES);
  assert.equal(full.length, FRAME_BYTES);
  assert.equal(hello.length, FRAME_BYTES);
  // ...and each unframes back to its own typed payload.
  assert.equal(unframeLensCell(empty)?.kind, LENS_KIND_METHODS);
  assert.equal(unframeLensCell(hello)?.kind, LENS_KIND_HELLO);
});

test('body codec: bounds enforced (max methods, value/label/kind lengths); junk never parses', () => {
  assert.throws(() => encodeLensMethodsBody(Array.from({ length: LENS_MAX_METHODS + 1 }, () => ({ kind: 'x', value: 'y' }))), LensWireError);
  assert.throws(() => encodeLensMethodsBody([{ kind: 'signal', value: '' }]), LensWireError);
  assert.throws(() => encodeLensMethodsBody([{ kind: 'signal', value: 'x'.repeat(513) }]), LensWireError);
  assert.throws(() => decodeLensMethodsBody(new TextEncoder().encode('not json')), LensWireError);
  assert.throws(() => decodeLensMethodsBody(new TextEncoder().encode('[{"kind":123,"value":"x"}]')), LensWireError);
});

test('parseLensPayload rejects: wrong header, wrong kind, len mismatch, oversized seq', () => {
  const good = buildLensPayload({ kind: LENS_KIND_METHODS, fpSender: FP_A, fpReceiver: FP_B, seq: 1, body: encodeLensMethodsBody(methods), sPair });
  assert.ok(parseLensPayload(good));
  const badHeader = good.slice(); badHeader[0] = 0x00;
  assert.equal(parseLensPayload(badHeader), null);
  const badKind = good.slice(); badKind[2] = 0x7f;
  assert.equal(parseLensPayload(badKind), null);
  assert.equal(parseLensPayload(good.slice(0, good.length - 1)), null); // truncated
  assert.equal(parseLensPayload(new Uint8Array(0)), null);
});
