// src/lib/trust/beacon-pair-id.test.ts: #822 (a) P1. The local beacon pair id: HMAC(indexKey, label || LP(durableId)), hex. The known-answer test pins the derivation INPUTS against an
// INDEPENDENT implementation (node:crypto), so changing any input (label, framing, byte order, key) fails here instead of silently orphaning every stored pair and latch row.
// Run: npx tsx --test src/lib/trust/beacon-pair-id.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beaconPairId } from './beacon-pair-id';
import { blindFingerprint } from '../identity/contact-crypto';

const ID = /^[A-Za-z0-9._-]{1,128}$/; // the rule createBeaconStore / createBeaconLatch enforce on a pairId
const KEY_BYTES = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const OTHER_BYTES = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);
const D1 = 'a'.repeat(64);
const D2 = ('0123456789abcdef'.repeat(4)).slice(0, 64);
const ROOT = fileURLToPath(new URL('../../../', import.meta.url));

const hmacKey = (raw: Uint8Array) => crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
const u32be = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); return b; };
/** The independent reference: label bytes, then a 4-byte big-endian length, then the id bytes. */
const reference = (keyBytes: Uint8Array, id: string) =>
  createHmac('sha256', Buffer.from(keyBytes)).update(Buffer.concat([Buffer.from('svrnty:beacon-pair:v1', 'utf8'), u32be(Buffer.byteLength(id)), Buffer.from(id, 'utf8')])).digest('hex');

test('P1 KNOWN ANSWER: the id equals an independent HMAC over label || 4-byte big-endian length || id, for two ids and two keys', async () => {
  const k1 = await hmacKey(KEY_BYTES), k2 = await hmacKey(OTHER_BYTES);
  for (const [k, bytes] of [[k1, KEY_BYTES], [k2, OTHER_BYTES]] as const) {
    for (const d of [D1, D2]) assert.equal(await beaconPairId(k, d), reference(bytes, d), `key ${bytes[0]} id ${d.slice(0, 6)}`);
  }
});

test('P2 the id is 64 lowercase hex and passes the ports\' id rule (no + / = : or space)', async () => {
  const p = await beaconPairId(await hmacKey(KEY_BYTES), D1);
  assert.match(p, /^[0-9a-f]{64}$/);
  assert.match(p, ID);
});

test('P3 deterministic; a different durable id gives a different pair; a different index key (another identity) gives a different pair', async () => {
  const k1 = await hmacKey(KEY_BYTES), k2 = await hmacKey(OTHER_BYTES);
  assert.equal(await beaconPairId(k1, D1), await beaconPairId(k1, D1));
  assert.notEqual(await beaconPairId(k1, D1), await beaconPairId(k1, D2));
  assert.notEqual(await beaconPairId(k1, D1), await beaconPairId(k2, D1), 'per-identity: the same contact id must not correlate across identities');
});

test('P4 FAIL-CLOSED: anything that is not 64 lowercase hex is refused (case, length, punctuation, whitespace, non-strings)', async () => {
  const k = await hmacKey(KEY_BYTES);
  const bad: unknown[] = ['', 'a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), `${'a'.repeat(63)}g`, ` ${'a'.repeat(63)}`, `${'a'.repeat(63)}\n`, `${'a'.repeat(32)}:${'a'.repeat(31)}`, 7, null, undefined, {}];
  for (const b of bad) await assert.rejects(beaconPairId(k, b as string), /64 lowercase hex/, JSON.stringify(b));
});

test('P5 DOMAIN SEPARATION: the pair id cannot be matched to the contact row index of the same contact (even with the same key)', async () => {
  const k = await hmacKey(KEY_BYTES);
  const pair = await beaconPairId(k, D1);
  const rowIdx = await blindFingerprint(k, D1);                              // what the contacts store keys that contact by (base64)
  const plainHex = createHmac('sha256', Buffer.from(KEY_BYTES)).update(D1).digest('hex'); // the same HMAC without the label and framing
  assert.notEqual(pair, rowIdx);
  assert.notEqual(pair, plainHex);
});

function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    if (n === 'node_modules' || n === '.next' || n === '.git') continue;
    const p = join(dir, n);
    if (statSync(p).isDirectory()) walk(p, out); else out.push(p);
  }
  return out;
}

test('P6 [static] the label is named in exactly one non-test source file, and the file states the re-key rule (a passphrase change must re-key every beacon_* row in ONE transaction)', () => {
  const files = walk(join(ROOT, 'src')).filter((p) => /\.(ts|tsx)$/.test(p) && !/\.test\./.test(p) && readFileSync(p, 'utf8').includes('svrnty:beacon-pair:v1'));
  assert.deepEqual(files.map((p) => p.slice(ROOT.length)), ['src/lib/trust/beacon-pair-id.ts']);
  const src = readFileSync(join(ROOT, 'src/lib/trust/beacon-pair-id.ts'), 'utf8');
  assert.match(src, /MUST re-key every beacon_\* row in the SAME transaction/);
  assert.match(src, /DURABLE id/);
});
