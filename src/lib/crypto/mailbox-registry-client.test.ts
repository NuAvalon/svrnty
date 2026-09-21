// src/lib/crypto/mailbox-registry-client.test.ts
// Behavioral pins for the satellite mailbox registry client (KB#90104 items 2-3).
//   node --import tsx --test src/lib/crypto/mailbox-registry-client.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { base64ToUint8 } from './pq.js';
import { mailboxRegPreimage } from '../identity/raw-sign.js';
import { deriveMailboxFp } from './mailbox-envelope.js';
import { generateMailboxKeypair } from './mailbox-keys.js';
import {
  buildMailboxRegisterFields,
  fetchMailbox,
  httpMailboxRegistry,
  type MailboxRecord,
} from './mailbox-registry-client.js';

const IDENTITY_SEED = new Uint8Array(32).fill(0x42);
const IDENTITY_PUB = ed25519.getPublicKey(IDENTITY_SEED);
const OWNER_FP = 'a'.repeat(64);

function mockFetch(handler: (url: string, init?: any) => { ok: boolean; status: number; body: unknown }): typeof fetch {
  return (async (url: unknown, init?: unknown) => {
    const { ok, status, body } = handler(String(url), init);
    return { ok, status, json: async () => body } as unknown as Response;
  }) as unknown as typeof fetch;
}

test('buildMailboxRegisterFields — wire shape + owner_sig verifies vs the reg preimage', () => {
  const kp = generateMailboxKeypair();
  const epoch = 3;
  const f = buildMailboxRegisterFields(kp, OWNER_FP, epoch, IDENTITY_SEED);
  assert.equal(f.mailbox_fp, deriveMailboxFp(kp.x25519Pub, kp.mlkem1024Pub));
  assert.equal(f.x25519_pk.length, 64);
  assert.equal(f.mlkem1024_pk.length, 3136);
  assert.equal(f.owner_identity_fp, OWNER_FP);
  assert.equal(f.epoch, epoch);
  // owner_sig (base64) must Ed25519-verify against the identity key over the byte-exact preimage
  const sig = base64ToUint8(f.owner_sig);
  const preimage = mailboxRegPreimage(OWNER_FP, f.mailbox_fp, epoch);
  assert.ok(ed25519.verify(sig, preimage, IDENTITY_PUB), 'owner_sig must verify over the reg preimage');
});

test('register — POSTs the exact fields to /mailbox/register, returns epoch on 200', async () => {
  const kp = generateMailboxKeypair();
  const fields = buildMailboxRegisterFields(kp, OWNER_FP, 5, IDENTITY_SEED);
  let captured: unknown = null;
  const registry = httpMailboxRegistry('https://sat.example/', mockFetch((url, init) => {
    assert.equal(url, 'https://sat.example/mailbox/register');
    captured = JSON.parse((init as { body: string }).body);
    return { ok: true, status: 200, body: { status: 'registered', mailbox_fp: fields.mailbox_fp, epoch: 5 } };
  }));
  const res = await registry.register(fields);
  assert.equal(res.ok, true);
  assert.equal(res.epoch, 5);
  assert.deepEqual(captured, fields); // exact body, no drift
});

test('register — surfaces the satellite error detail on non-2xx', async () => {
  const registry = httpMailboxRegistry('https://sat.example', mockFetch(() => ({
    ok: false, status: 403, body: { detail: 'invalid owner_sig' },
  })));
  const res = await registry.register({} as never);
  assert.equal(res.ok, false);
  assert.equal(res.status, 403);
  assert.equal(res.error, 'invalid owner_sig');
});

test('fetchMailbox — happy path returns the pubkeys', async () => {
  const kp = generateMailboxKeypair();
  const fp = deriveMailboxFp(kp.x25519Pub, kp.mlkem1024Pub);
  const rec: MailboxRecord = {
    mailbox_fp: fp, x25519_pk: bytesToHex(kp.x25519Pub), mlkem1024_pk: bytesToHex(kp.mlkem1024Pub), epoch: 1,
  };
  const registry = httpMailboxRegistry('https://sat.example', mockFetch((url) => {
    assert.ok(url.endsWith(`/mailbox/${fp}`));
    return { ok: true, status: 200, body: rec };
  }));
  const keys = await fetchMailbox(registry, fp);
  assert.ok(keys);
  assert.equal(bytesToHex(keys!.x25519Pub), bytesToHex(kp.x25519Pub));
  assert.equal(bytesToHex(keys!.mlkem1024Pub), bytesToHex(kp.mlkem1024Pub));
});

test('fetchMailbox — ANTI-SUBSTITUTION: relay returns keys not matching the requested fp -> null', async () => {
  const honest = generateMailboxKeypair();
  const attacker = generateMailboxKeypair();
  const honestFp = deriveMailboxFp(honest.x25519Pub, honest.mlkem1024Pub);
  // a lying relay returns ATTACKER pubkeys under the HONEST fp — must be rejected before any seal
  const registry = httpMailboxRegistry('https://sat.example', mockFetch(() => ({
    ok: true, status: 200,
    body: { mailbox_fp: honestFp, x25519_pk: bytesToHex(attacker.x25519Pub), mlkem1024_pk: bytesToHex(attacker.mlkem1024Pub), epoch: 1 },
  })));
  assert.equal(await fetchMailbox(registry, honestFp), null);
});

test('fetchMailbox — 404 and malformed records -> null (never throws)', async () => {
  const notFound = httpMailboxRegistry('https://sat.example', mockFetch(() => ({ ok: false, status: 404, body: { detail: 'Unknown mailbox' } })));
  assert.equal(await fetchMailbox(notFound, 'a'.repeat(64)), null);
  const malformed = httpMailboxRegistry('https://sat.example', mockFetch(() => ({ ok: true, status: 200, body: { mailbox_fp: 'x', x25519_pk: 'zz', mlkem1024_pk: 'zz', epoch: 1 } })));
  assert.equal(await fetchMailbox(malformed, 'a'.repeat(64)), null);
});
