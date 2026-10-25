// #704 D-S51 option (A) done_when 1–4 + 6 (contract svrnty_704A_distress_rides_resync_v3.md, e9ee6307…).
// REAL path (F-1): drives syncMutualTrust with a stubbed fetch and opens the POSTed bodies as the satellite
// would, then peels the slot and tries it as the guardian device would.
// Run: npx tsx --test src/lib/trust/psi-resync-slot.test.ts
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateMailboxKeypair, toPublicKeys, toSecretKeys, mailboxFpOf } from '@/lib/crypto/mailbox-keys';
import { openPsiFromSatellite } from '@/lib/crypto/psi-wire-seal';
import { peelOnion, openOnionInner } from '@/lib/crypto/onion-envelope';
import { unframeUniform } from '@/lib/crypto/uniform-frame';
import type { MailboxEnvelopePackage } from '@/lib/crypto/mailbox-envelope';
import { syncMutualTrust, type OrchestratorDeps, type PSISyncOptions } from './mutual-trust-sync';
import {
  ResyncSlotSource,
  PSI_BLINDED_BUCKET_N as N,
  PSI_REQUESTS_PER_TICK_K as K,
  PSI_INITIATE_BODY_BYTES,
} from './psi-resync-slot';

const sat = generateMailboxKeypair();
const guardian = generateMailboxKeypair();
const ME = 'ab'.repeat(32);
const ROUTE = 'c0'.repeat(16);
const fpN = (i: number) => i.toString(16).padStart(64, '0');

type Post = { url: string; raw: string; body: Record<string, unknown> };
let posts: Post[] = [];
const realFetch = globalThis.fetch;

beforeEach(() => {
  posts = [];
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    const u = String(url);
    if (init?.method === 'POST' && u.endsWith('/trust/psi/initiate')) {
      const raw = String(init.body);
      const opened = await openPsiFromSatellite(
        JSON.parse(raw) as MailboxEnvelopePackage, toSecretKeys(sat), mailboxFpOf(sat),
      );
      posts.push({ url: u, raw, body: opened as Record<string, unknown> });
      return new Response(JSON.stringify({ session_id: `s${posts.length}` }), { status: 200 });
    }
    if (u.includes('/trust/psi/pending/')) return new Response(JSON.stringify({ sessions: [] }), { status: 200 });
    return new Response('unexpected', { status: 500 });
  }) as typeof fetch;
});
afterEach(() => { globalThis.fetch = realFetch; });

/** A book of `n` trusted peers; `pending` tracks peers with a saved session (what savePsiInitiated does). */
function book(n: number) {
  const peers = Array.from({ length: n }, (_, i) => fpN(i + 1));
  const pending = new Set<string>();
  const deps: OrchestratorDeps = {
    getTrustedPeers: async () => peers.map(fingerprint => ({ fingerprint, lastSync: null, pending: pending.has(fingerprint) })),
    getKnownPeers: async () => peers.map(fingerprint => ({ fingerprint, lastSync: null })),
    applyMutualResult: async () => {},
  };
  return { peers, pending, deps };
}

function options(slots: ResyncSlotSource): PSISyncOptions {
  return {
    satelliteUrl: 'http://sat.test',
    myFingerprint: ME,
    signFn: () => new Uint8Array(64),
    pqWrap: { satelliteKeys: toPublicKeys(sat) },
    slots,
  };
}

async function tick(b: ReturnType<typeof book>, slots: ResyncSlotSource, layer: 'know' | 'trust' = 'trust') {
  const r = await syncMutualTrust(b.deps, options(slots), layer);
  for (const s of r.initiated) b.pending.add(s.peerFingerprint);
  return r;
}

/** What the guardian device gets from a slot: the frame type if it can open it, else null. */
async function guardianOpens(slot: unknown): Promise<string | null> {
  const peeled = await peelOnion(slot as MailboxEnvelopePackage, toSecretKeys(sat), mailboxFpOf(sat));
  assert.ok(peeled, 'the satellite must be able to peel every slot');
  const cell = await openOnionInner(peeled.inner, toSecretKeys(guardian), mailboxFpOf(guardian));
  if (!cell) return null;
  return unframeUniform(cell)?.type ?? null;
}

function queueCry(slots: ResyncSlotSource) {
  slots.enqueueCry({
    payload: new TextEncoder().encode('distress-cell-under-test'),
    guardianDevice: toPublicKeys(guardian),
    guardianSatellite: toPublicKeys(sat),
    routeIdAt: () => ROUTE,
  });
}

test('done_when 1: sealed initiate length is constant for blinded-set size 0, 1, 5, 20, N, N+1', async () => {
  const lengths = new Set<number>();
  const plain = new Set<number>();
  for (const size of [0, 1, 5, 20, N, N + 1]) {
    posts = [];
    await tick(book(size), new ResyncSlotSource(toPublicKeys(sat)));
    assert.equal(posts.length, K, `size ${size}: K requests`);
    for (const p of posts) {
      lengths.add(p.raw.length);
      plain.add(new TextEncoder().encode(JSON.stringify(p.body)).length);
      assert.equal((p.body.blinded_set as unknown[]).length, N, `size ${size}: blinded set padded to N`);
    }
  }
  assert.equal(lengths.size, 1, `sealed lengths differ: ${[...lengths]}`);
  assert.deepEqual([...plain], [PSI_INITIATE_BODY_BYTES]);
});

test('done_when 2 / D-7: K requests per tick for 0, 1, 5, 20, N+1, 3N peers due; overflow goes out later, in order', async () => {
  for (const n of [0, 1, 5, 20, N + 1, 3 * N]) {
    posts = [];
    await tick(book(n), new ResyncSlotSource(toPublicKeys(sat)));
    assert.equal(posts.length, K, `${n} peers due: exactly K requests`);
  }
  // Order kept: 5 due peers go out one per tick (K=1) in book order, then the tick is cover.
  const b = book(5);
  const slots = new ResyncSlotSource(toPublicKeys(sat));
  const sentTo: string[] = [];
  for (let t = 0; t < 6; t++) {
    posts = [];
    await tick(b, slots);
    assert.equal(posts.length, K);
    if (posts[0].body.cover === false) sentTo.push(posts[0].body.responder_fingerprint as string);
    else assert.equal(t, 5, 'cover only once every due peer has a live session');
  }
  assert.deepEqual(sentTo, b.peers);
});

test('done_when 2 / D-7: a set larger than N is not synced (cover + loud error), never truncated', async () => {
  const r = await tick(book(N + 1), new ResyncSlotSource(toPublicKeys(sat)));
  assert.equal(r.initiated.length, 0);
  assert.equal(posts[0].body.cover, true);
  assert.ok(r.errors.some(e => e.includes(`over the bucket N=${N}`)), r.errors.join(' | '));
});

test('done_when 3: every request carries one slot; distress onion with a cry queued, else same-length cover', async () => {
  const b = book(3);
  const slots = new ResyncSlotSource(toPublicKeys(sat));
  await tick(b, slots); // no cry
  const coverSlot = posts[0].body.slot;
  assert.ok(coverSlot, 'slot present without a cry');
  assert.equal(await guardianOpens(coverSlot), null, 'a cover slot opens for no guardian');

  posts = [];
  queueCry(slots);
  await tick(b, slots);
  const crySlot = posts[0].body.slot;
  assert.equal(await guardianOpens(crySlot), 'distress');
  assert.equal(JSON.stringify(crySlot).length, JSON.stringify(coverSlot).length, 'cover and distress slot lengths equal');
});

test('done_when 3: no guardian / no cry still sends a slot (G1), including a tick with zero peers', async () => {
  await tick(book(0), new ResyncSlotSource(toPublicKeys(sat)));
  assert.equal(posts.length, K);
  assert.ok(posts[0].body.slot);
  assert.equal(posts[0].body.cover, true);
});

test('done_when 4: a cry rides exactly 3 consecutive ticks with distinct ciphertexts, then stops', async () => {
  const b = book(2);
  const slots = new ResyncSlotSource(toPublicKeys(sat));
  queueCry(slots);
  const seen: string[] = [];
  const types: Array<string | null> = [];
  for (let t = 0; t < 5; t++) {
    posts = [];
    await tick(b, slots);
    seen.push(JSON.stringify(posts[0].body.slot));
    types.push(await guardianOpens(posts[0].body.slot));
  }
  assert.deepEqual(types, ['distress', 'distress', 'distress', null, null]);
  assert.equal(new Set(seen.slice(0, 3)).size, 3, 'each tick re-seals the cry fresh');
});

test('done_when 6 (D-6, R6): queueing a cry sends NOTHING until the next scheduled tick', async () => {
  const b = book(2);
  const slots = new ResyncSlotSource(toPublicKeys(sat));
  queueCry(slots);
  for (let i = 0; i < 5; i++) await new Promise(r => setImmediate(r));
  await new Promise(r => setTimeout(r, 50));
  assert.equal(posts.length, 0, 'no request on enqueue');
  await tick(b, slots);
  assert.equal(posts.length, K);
  assert.equal(await guardianOpens(posts[0].body.slot), 'distress', 'the cry rides the scheduled tick');
});

test('a slot never rides a plaintext wire: slots without pqWrap send nothing and keep the cry', async () => {
  const b = book(2);
  const slots = new ResyncSlotSource(toPublicKeys(sat));
  queueCry(slots);
  const r = await syncMutualTrust(b.deps, { ...options(slots), pqWrap: undefined }, 'trust');
  assert.equal(posts.length, 0);
  assert.ok(r.errors.some(e => e.includes('requires the PQ wire-wrap')));
  // Not one of the cry's 3 ticks was spent: all 3 still ride once the wire is sealed.
  const types: Array<string | null> = [];
  for (let t = 0; t < 4; t++) {
    posts = [];
    await tick(b, slots);
    types.push(await guardianOpens(posts[0].body.slot));
  }
  assert.deepEqual(types, ['distress', 'distress', 'distress', null]);
});
