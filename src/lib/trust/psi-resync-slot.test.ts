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
import { randomBytes } from '@noble/hashes/utils.js';
import * as ed from '@noble/curves/ed25519.js';
import { syncMutualTrust, blindFingerprints, generatePSIKeypair, type OrchestratorDeps, type PSISyncOptions } from './mutual-trust-sync';
import {
  padBlindedSet,
  ResyncSlotSource,
  PSI_BLINDED_BUCKET_N as N,
  PSI_REQUESTS_PER_TICK_K as K,
  PSI_INITIATE_BODY_BYTES,
} from './psi-resync-slot';

const sat = generateMailboxKeypair();
const guardian = generateMailboxKeypair();
const ME = 'ab'.repeat(32);
import { sha256 } from '@noble/hashes/sha2.js';
import { currentWindowIndex, subRoutePollSet } from '@/lib/crypto/route-ratchet';
// Wall clock under test: starts on a window boundary, each tick advances one 5-min sub-route.
let clock = Date.UTC(2026, 9, 25, 9, 0, 0);
const TICK_MS = 5 * 60 * 1000;
const newSource = () => new ResyncSlotSource(toPublicKeys(sat), () => clock);
/** The guardian-direction rk_W for a window (a stand-in for the real ratchet: one fixed key per window). */
const rkFor = (w: number) => sha256(new TextEncoder().encode(`rk-under-test-${w}`));
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
  clock += TICK_MS;
  return r;
}

/** What the satellite sees after peeling a slot: the route. */
async function satelliteRoute(slot: unknown): Promise<string> {
  const peeled = await peelOnion(slot as MailboxEnvelopePackage, toSecretKeys(sat), mailboxFpOf(sat));
  assert.ok(peeled, 'the satellite must be able to peel every slot');
  return peeled.route;
}

/** What the guardian device gets from a slot: {type, payload text} if it can open it, else null. */
async function guardianReads(slot: unknown): Promise<{ type: string; text: string } | null> {
  const peeled = await peelOnion(slot as MailboxEnvelopePackage, toSecretKeys(sat), mailboxFpOf(sat));
  assert.ok(peeled, 'the satellite must be able to peel every slot');
  const cell = await openOnionInner(peeled.inner, toSecretKeys(guardian), mailboxFpOf(guardian));
  if (!cell) return null;
  const f = unframeUniform(cell);
  return f ? { type: f.type, text: new TextDecoder().decode(f.payload) } : null;
}
async function guardianOpens(slot: unknown): Promise<string | null> {
  return (await guardianReads(slot))?.type ?? null;
}

function queueCry(slots: ResyncSlotSource, text = 'distress-cell-under-test') {
  slots.enqueueCry({
    payload: new TextEncoder().encode(text),
    guardianDevice: toPublicKeys(guardian),
    guardianSatellite: toPublicKeys(sat),
    routeKeyAt: (now) => rkFor(currentWindowIndex(now)),
  });
}

test('done_when 1: sealed initiate length is constant for blinded-set size 0, 1, 5, 20, N, N+1', async () => {
  const lengths = new Set<number>();
  const plain = new Set<number>();
  for (const size of [0, 1, 5, 20, N, N + 1]) {
    posts = [];
    await tick(book(size), newSource());
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
    await tick(book(n), newSource());
    assert.equal(posts.length, K, `${n} peers due: exactly K requests`);
  }
  // Order kept: 5 due peers go out one per tick (K=1) in book order, then the tick is cover.
  const b = book(5);
  const slots = newSource();
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
  const r = await tick(book(N + 1), newSource());
  assert.equal(r.initiated.length, 0);
  assert.equal(posts[0].body.cover, true);
  assert.ok(r.errors.some(e => e.includes(`over the bucket N=${N}`)), r.errors.join(' | '));
});

test('done_when 3: every request carries one slot; distress onion with a cry queued, else same-length cover', async () => {
  const b = book(3);
  const slots = newSource();
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
  await tick(book(0), newSource());
  assert.equal(posts.length, K);
  assert.ok(posts[0].body.slot);
  assert.equal(posts[0].body.cover, true);
});

test('done_when 4: a cry rides exactly 3 consecutive ticks with distinct ciphertexts, then stops', async () => {
  const b = book(2);
  const slots = newSource();
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
  const slots = newSource();
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
  const slots = newSource();
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

// F-4 (Apollo #1282): a dummy must be indistinguishable from a real blinded entry to whoever opens the seal.
// classify() lifted from Apollo's probe (shared/outbox/apollo/psi_dummy_probe_v0, sha256 ee9bd483…).
const E: any = (ed as any).ed25519;
const [B0, B1, B2, B8, B19, B255] = [0, 1, 2, 8, 19, 255].map(BigInt);
const BFF = BigInt(0xff);
const P = (B1 << B255) - B19;
const le = (b: Uint8Array) => { let x = B0; for (let i = b.length - 1; i >= 0; i--) x = (x << B8) | BigInt(b[i]); return x; };
const pw = (b: bigint, e: bigint) => { let r = B1; b %= P; while (e > B0) { if (e & B1) r = (r * b) % P; b = (b * b) % P; e >>= B1; } return r; };
function classify(u32: Uint8Array): 'twist' | 'torsion-free' | 'HAS-torsion' {
  const u = le(u32) & ((B1 << B255) - B1);
  const den = (u + B1) % P; if (den === B0) return 'twist';
  const y = ((u - B1 + P) % P) * pw(den, P - B2) % P;
  const yb = new Uint8Array(32); let t = y; for (let i = 0; i < 32; i++) { yb[i] = Number(t & BFF); t >>= B8; }
  try { return E.Point.fromBytes(yb).isTorsionFree() ? 'torsion-free' : 'HAS-torsion'; } catch { return 'twist'; }
}
function profile(entries: string[]) {
  const xs = entries.map(b => Buffer.from(b, 'base64'));
  const c = { top: 0, torsion: 0, twist: 0 };
  for (const x of xs) {
    if (x[31] & 0x80) c.top++;
    const k = classify(x);
    if (k === 'HAS-torsion') c.torsion++;
    if (k === 'twist') c.twist++;
  }
  return { top: c.top / xs.length, torsion: c.torsion / xs.length, twist: c.twist / xs.length };
}

test('F-4: dummy blinded entries match real ones on the top-bit and subgroup tests (>= 2000 dummies)', () => {
  const dummies: string[] = [];
  for (let i = 0; i < 32; i++) { // bounded: an unpadded set must FAIL, not hang
    const sk = generatePSIKeypair().privateKey;
    const one = padBlindedSet([], [], a => a, sk).blinded;
    assert.equal(new Set(one).size, one.length, 'G-2: dummies of one request are pairwise distinct');
    dummies.push(...one);
  }
  assert.ok(dummies.length >= 2000, `only ${dummies.length} dummies produced`);
  const sk = generatePSIKeypair().privateKey;
  const real = blindFingerprints(Array.from({ length: 2048 }, () => Buffer.from(randomBytes(16)).toString('hex')), sk);
  const d = profile(dummies);
  const r = profile(real);
  assert.equal(r.top, 0); assert.equal(r.torsion, 0); // sanity: the real side
  assert.equal(d.top, 0, `dummies with the top bit set: ${d.top}`);
  assert.equal(d.torsion, 0, `dummies with a torsion component: ${d.torsion}`);
  assert.ok(Math.abs(d.twist - r.twist) < 0.08, `twist share differs: dummy ${d.twist} vs real ${r.twist}`);
});

test('F-5 / DW10 (across ticks): a cry\'s 3 routes are pairwise distinct and all in the guardian\'s poll set', async () => {
  const b = book(2);
  const slots = newSource();
  queueCry(slots);
  const routes: string[] = [];
  const windows: number[] = [];
  for (let t = 0; t < 3; t++) {
    posts = [];
    windows.push(currentWindowIndex(clock));
    await tick(b, slots);
    assert.equal(await guardianOpens(posts[0].body.slot), 'distress');
    routes.push(await satelliteRoute(posts[0].body.slot));
  }
  assert.equal(new Set(routes).size, 3, `cry routes repeat: ${routes}`);
  for (let t = 0; t < 3; t++) {
    const w = windows[t];
    assert.ok(subRoutePollSet(rkFor(w), rkFor(w - 1)).includes(routes[t]), 'the guardian polls this route');
  }
});

test('G-4 / DW10 (across ticks): cover routes are pairwise distinct over 24 ticks', async () => {
  const b = book(0);
  const slots = newSource();
  const routes: string[] = [];
  for (let t = 0; t < 24; t++) {
    posts = [];
    await tick(b, slots);
    routes.push(await satelliteRoute(posts[0].body.slot));
  }
  assert.equal(new Set(routes).size, 24);
  assert.ok(routes.every(r => /^[0-9a-f]{32}$/.test(r)));
});

test('G-1 / DW11: dummies are shuffled with the real entries (a real entry lands on many positions)', () => {
  const sk = generatePSIKeypair().privateKey;
  const real = blindFingerprints(['fp-under-test'], sk)[0];
  const positions = new Set<number>();
  for (let i = 0; i < 200; i++) {
    const { blinded, fpOrder } = padBlindedSet([real], ['fp-under-test'], arr => {
      const a = arr.slice();
      for (let j = a.length - 1; j > 0; j--) { const k = Math.floor(Math.random() * (j + 1)); [a[j], a[k]] = [a[k], a[j]]; }
      return a;
    }, sk);
    const at = blinded.indexOf(real);
    assert.equal(fpOrder[at], 'fp-under-test', 'fp order stays aligned with the blinded entry');
    positions.add(at);
  }
  assert.ok(positions.size > 20, `real entry seen at only ${positions.size} positions`);
});

test('G-1 / DW11 (real path): the request shuffles: one real peer is not always at the same index', async () => {
  const positions = new Set<number>();
  for (let i = 0; i < 12; i++) {
    posts = [];
    const b = book(1);
    const r = await tick(b, newSource());
    const order = r.initiated[0].fpOrder;
    positions.add(order.indexOf(b.peers[0]));
  }
  assert.ok(positions.size > 3, `positions: ${[...positions]}`);
});

test('G-3 / DW12: a new cry replaces an unfinished one and rides its own 3 ticks', async () => {
  const b = book(2);
  const slots = newSource();
  queueCry(slots, 'cry-A');
  posts = [];
  await tick(b, slots);
  assert.equal((await guardianReads(posts[0].body.slot))?.text, 'cry-A');
  queueCry(slots, 'cry-B');
  const seen: Array<string | null> = [];
  for (let t = 0; t < 4; t++) {
    posts = [];
    await tick(b, slots);
    seen.push((await guardianReads(posts[0].body.slot))?.text ?? null);
  }
  assert.deepEqual(seen, ['cry-B', 'cry-B', 'cry-B', null]);
});
