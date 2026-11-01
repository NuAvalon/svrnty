// src/lib/sync/ack-header-budget-730.test.ts
// #730 (Flint #2537): a size budget for the owner-auth header on the poll and on every ack.
// Why: the v1 classical owner signature is an ATTACHED OpenPGP message (sign-envelope.ts), so x-svrnty-owner-auth carries the
// signed input, every acked envelope id included (~72 B per id). Node's http.maxHeaderSize is 16384: one ack of ~85+ ids is
// refused with 431 (the relay logs it behind Caddy as "connection reset by peer"), nothing is deleted, and the mailbox
// redelivers forever (Athena lane #2535, ~2,400 resets on dev since 10-23). The 20-id ack chunks (#307) are what keep it
// under the limit. This pins that, with a real PQ identity, so a chunk-size bump or a bigger key format goes RED here first.
// Run: npx tsx --test src/lib/sync/ack-header-budget-730.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { generatePQKeypairBundle, uint8ToBase64 } from '@/lib/crypto/pq';
import { mintCanonicalFingerprint } from '@/lib/identity/fingerprint';
import { OWNER_AUTH_HEADER, signMailboxAckRequest, deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { consumeInboundContactUpdates, type ConsumeDeps, type DeadLetterSink, type OwnerIdentity } from './consume-mailbox';

/** The budget: well under Node's 16384 header limit, leaving room for the browser's and the proxies' own headers. */
const HEADER_BUDGET = 12 * 1024;
const NODE_MAX_HEADER = 16384;

let OWNER: OwnerIdentity;
before(async () => {
  const passphrase = 'pw-730';
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime.
    curve: 'ed25519',
    userIDs: [{ name: 'budget', email: 'budget@x.test' }],
    passphrase,
    format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase });
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  OWNER = {
    fingerprint,
    publicKeyArmored: publicKey,
    privateKeyArmored: privateKey,
    passphrase,
    kemPublicKey: uint8ToBase64(pq.kem.publicKey),
    sigPublicKey: uint8ToBase64(pq.signing.publicKey),
  };
});

const NOW = '2026-10-31T12:00:00.000Z';

/** A relay that records the owner-auth header length of every poll and every ack. Envelope ids are UUIDs, as the relay mints them. */
function relay(n: number) {
  const envs = Array.from({ length: n }, (_, i) => ({ envelope_id: randomUUID(), blob: `junk-${i}` }));
  const polls: number[] = [];
  const acks: Array<{ ids: number; header: number }> = [];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const auth = new Headers(init?.headers).get(OWNER_AUTH_HEADER) ?? '';
    if (String(url).includes('/queue')) {
      polls.push(auth.length);
      return new Response(JSON.stringify(envs), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (String(url).includes('/ack')) {
      const ids = JSON.parse(String(init?.body ?? '{}')).envelope_ids as string[];
      acks.push({ ids: ids.length, header: auth.length });
      return new Response(JSON.stringify({ deleted: ids.length }), { status: 200 });
    }
    return new Response('nf', { status: 404 });
  }) as unknown as typeof fetch;
  return { fetchImpl, polls, acks };
}

const sink: DeadLetterSink = { record: async (row) => row, clear: async () => {} };

function deps(over: Partial<ConsumeDeps>): ConsumeDeps {
  return { owner: OWNER, decrypt: async () => null, store: { lookup: async () => null, persist: async () => {} }, relayBase: 'http://relay.test/api/relay', now: () => NOW, deadLetter: sink, ...over };
}

test('B1 #730: a 116-envelope backlog (Peter\'s dev mailbox) drains in acks whose owner-auth header each stays under the 12 KB budget', async () => {
  const r = relay(116);
  const s = await consumeInboundContactUpdates(deps({ fetchImpl: r.fetchImpl }));
  assert.equal(s.acked, 116, 'every envelope acked');
  assert.ok(r.acks.length >= 2, `more than one ack call (got ${r.acks.length})`);
  for (const a of r.acks) assert.ok(a.header > 0 && a.header < HEADER_BUDGET, `ack of ${a.ids} ids: header ${a.header} B must be < ${HEADER_BUDGET}`);
});

test('B2 #730: the poll\'s owner-auth header stays under the 12 KB budget', async () => {
  const r = relay(1);
  await consumeInboundContactUpdates(deps({ fetchImpl: r.fetchImpl }));
  assert.equal(r.polls.length, 1);
  assert.ok(r.polls[0] > 0 && r.polls[0] < HEADER_BUDGET, `poll header ${r.polls[0]} B must be < ${HEADER_BUDGET}`);
});

test('B3 #730 (why the budget exists): ONE v1 ack of all 116 ids, as the pre-#307 build sends it, has a header over Node\'s 16384 limit', async () => {
  const ids = Array.from({ length: 116 }, () => randomUUID());
  const h = await signMailboxAckRequest({ ...OWNER, mailboxId: deriveMailboxId(OWNER.fingerprint), envelopeIds: ids, now: Date.parse(NOW) });
  assert.ok(h[OWNER_AUTH_HEADER].length > NODE_MAX_HEADER, `116-id header ${h[OWNER_AUTH_HEADER].length} B: if this stops exceeding ${NODE_MAX_HEADER}, the signature no longer carries the ids and this budget can be revisited`);
});
