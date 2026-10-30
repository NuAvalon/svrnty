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

/** A book of `n` trusted peers; `pending` tracks peers with a saved session (what savePsiInitiated does).
 * `trustVisible` = the trust-PSI opt-in subset (#697 getTrustVisiblePeers); default: every peer. */
function book(n: number, trustVisible?: (fp: string, i: number) => boolean) {
  const peers = Array.from({ length: n }, (_, i) => fpN(i + 1));
  const pending = new Set<string>();
  const visible = peers.filter((fp, i) => (trustVisible ? trustVisible(fp, i) : true));
  const deps: OrchestratorDeps = {
    getTrustedPeers: async () => peers.map(fingerprint => ({ fingerprint, lastSync: null, pending: pending.has(fingerprint) })),
    getKnownPeers: async () => peers.map(fingerprint => ({ fingerprint, lastSync: null })),
    getTrustVisiblePeers: async () => visible.map(fingerprint => ({ fingerprint, lastSync: null })),
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

// ── v6: F-6 / DW10 (unique per cry), DW13 (boundary poll), DW14 (known-answer vectors) ─────────────────────────────
import { deriveSubRouteId, deriveRouteId, currentSubRouteIndex } from '@/lib/crypto/route-ratchet';

async function cryRoutesAt(sealTimesMs: number[]): Promise<string[]> {
  const b = book(2);
  let t = 0;
  const slots = new ResyncSlotSource(toPublicKeys(sat), () => sealTimesMs[t]);
  queueCry(slots);
  const routes: string[] = [];
  for (t = 0; t < sealTimesMs.length; t++) {
    posts = [];
    await syncMutualTrust(b.deps, options(slots), 'trust');
    routes.push(await satelliteRoute(posts[0].body.slot));
  }
  return routes;
}

test('F-6 / DW10: seals 299 s apart in ONE 5-min bucket still get distinct routes', async () => {
  const base = Date.UTC(2026, 9, 25, 9, 0, 0); // bucket 0 of window
  const routes = await cryRoutesAt([base, base + 299_000]);
  assert.equal(currentSubRouteIndex(base), currentSubRouteIndex(base + 299_000), 'precondition: same bucket');
  assert.equal(new Set(routes).size, 2, `repeated route: ${routes}`);
});

test('F-6 / DW10: 3 seals inside one bucket get 3 distinct routes, all in the guardian poll set', async () => {
  const base = Date.UTC(2026, 9, 25, 9, 10, 0);
  const times = [base, base + 1_000, base + 2_000];
  const routes = await cryRoutesAt(times);
  assert.equal(new Set(routes).size, 3, `repeated route: ${routes}`);
  const w = currentWindowIndex(base);
  for (const r of routes) assert.ok(subRoutePollSet(rkFor(w), rkFor(w - 1)).includes(r));
});

test('F-6 / DW13: a cry across a window boundary: distinct routes, each polled (seal before, poll after)', async () => {
  const end = Date.UTC(2026, 9, 25, 9, 59, 59);
  const times = [end, end + 1_000, end + 300_000]; // :59:59 of W, :00:00 and :04:59 of W+1
  const routes = await cryRoutesAt(times);
  assert.equal(new Set(routes).size, 3);
  // DW13: the route sealed at :59:59 of W is found by a guardian polling just AFTER the boundary (current = W+1).
  const wNext = currentWindowIndex(end + 1_000);
  assert.equal(wNext, currentWindowIndex(end) + 1, 'precondition: crossed a window');
  assert.ok(subRoutePollSet(rkFor(wNext), rkFor(wNext - 1)).includes(routes[0]), 'previous-window route is polled');
  for (const r of routes.slice(1)) assert.ok(subRoutePollSet(rkFor(wNext), rkFor(wNext - 1)).includes(r));
});

test('DW14: known-answer vectors for the sub-route label, index and the untouched route-id-v1', () => {
  // Computed independently with RFC 5869 HKDF-SHA256 in Python (salt = 32 zero bytes, info = label || u8(i)).
  const rk = Uint8Array.from({ length: 32 }, (_, i) => i);
  assert.equal(deriveSubRouteId(rk, 0), 'a2c2a05c95c7ce6b1f29ccf3da9d7925');
  assert.equal(deriveSubRouteId(rk, 1), 'daf0c479258b1e4c07ec7e789955dc61');
  assert.equal(deriveSubRouteId(rk, 11), '2a74e04d77b978dc485153e39a6979e7');
  assert.equal(deriveRouteId(rk), '19551f05041fce7f25e99cbb97ee71ab', 'route-id-v1 unchanged');
  assert.equal(currentSubRouteIndex(1792922399000), 11); // 2026-10-25T09:59:59Z
  assert.equal(currentSubRouteIndex(1792922699000), 0); //  2026-10-25T10:04:59Z
  assert.equal(currentSubRouteIndex(1792922700000), 1); //  2026-10-25T10:05:00Z
  assert.throws(() => deriveSubRouteId(rk, 12));
});

// ── F-7 / DW15: uniqueness per DEVICE per window (across cries); never a zero-request tick ──────────────────────
/** Drive ticks at the given seal times; `cryAt` = tick indexes where a (new) cry is enqueued just before the tick. */
async function ticksAt(sealTimesMs: number[], cryAt: number[]) {
  const b = book(2);
  let t = 0;
  const slots = new ResyncSlotSource(toPublicKeys(sat), () => sealTimesMs[t]);
  const out: Array<{ requests: number; route: string; type: string | null }> = [];
  for (t = 0; t < sealTimesMs.length; t++) {
    if (cryAt.includes(t)) queueCry(slots, `cry-${t}`);
    posts = [];
    await syncMutualTrust(b.deps, options(slots), 'trust');
    out.push({ requests: posts.length, route: await satelliteRoute(posts[0].body.slot), type: await guardianOpens(posts[0].body.slot) });
  }
  return { out, slots };
}

test('F-7 / DW15: a REPLACEMENT cry 299 s later in the same bucket does not reuse the first cry\'s route', async () => {
  const base = Date.UTC(2026, 9, 25, 9, 20, 0);
  const { out } = await ticksAt([base, base + 299_000], [0, 1]);
  assert.deepEqual(out.map(o => o.type), ['distress', 'distress']);
  assert.notEqual(out[0].route, out[1].route, 'replacement cry repeated the route');
});

test('DW10 start index = the clock\'s index (N3), and a taken bucket-11 index wraps to 0 (N4)', async () => {
  const w = currentWindowIndex(Date.UTC(2026, 9, 25, 9, 0, 0));
  const b5 = Date.UTC(2026, 9, 25, 9, 25, 0); // bucket 5
  const r5 = await ticksAt([b5], [0]);
  assert.equal(r5.out[0].route, deriveSubRouteId(rkFor(w), 5));
  const b11 = Date.UTC(2026, 9, 25, 9, 56, 0); // bucket 11, two seals inside it
  const r11 = await ticksAt([b11, b11 + 60_000], [0]);
  assert.equal(r11.out[0].route, deriveSubRouteId(rkFor(w), 11));
  assert.equal(r11.out[1].route, deriveSubRouteId(rkFor(w), 0), 'wraps to 0, never throws');
});

test('DW15: 13 cry ticks in one window → a request EVERY tick; the 13th is cover and the cry stays pending', async () => {
  const base = Date.UTC(2026, 9, 25, 9, 0, 0);
  const times = Array.from({ length: 13 }, (_, i) => base + i * 1_000); // all inside one window
  const cryAt = [0, 3, 6, 9, 12]; // re-triggered cries keep a cry riding on every tick (12 = one more while exhausted)
  const { out, slots } = await ticksAt(times, cryAt);
  assert.ok(out.every(o => o.requests === K), 'a tick sent no request');
  assert.equal(out.slice(0, 12).filter(o => o.type === 'distress').length, 12);
  assert.equal(new Set(out.slice(0, 12).map(o => o.route)).size, 12, 'all 12 indices distinct');
  assert.equal(out[12].type, null, '13th tick = cover (indices exhausted)');
  assert.ok(slots.hasPendingCry(), 'the cry is still pending, not dropped');
});

test('DW17 (Apollo W8): an exhausted tick does not burn the cry\'s ticks; it rides its FULL 3 ticks next window', async () => {
  const base = Date.UTC(2026, 9, 25, 9, 0, 0);
  const inW = Array.from({ length: 13 }, (_, i) => base + i * 1_000); // 12 indices used, the 13th tick exhausted
  const next = Array.from({ length: 4 }, (_, i) => base + 3_600_000 + i * 1_000); // the next window
  assert.equal(currentWindowIndex(next[0]), currentWindowIndex(base) + 1, 'precondition: next window');
  const { out, slots } = await ticksAt([...inW, ...next], [0, 3, 6, 9, 12]); // the cry at tick 12 meets exhaustion
  assert.equal(out[12].type, null, 'tick 12 = cover (exhausted)');
  assert.deepEqual(out.slice(13).map(o => o.type), ['distress', 'distress', 'distress', null],
    'the pending cry must ride all 3 of its ticks after the exhausted one, then stop');
  assert.ok(out.every(o => o.requests === K), 'a tick sent no request');
  assert.equal(slots.hasPendingCry(), false);
});

test('blind-until-mutual (#697 consent gate x slots): a trusted peer NOT in trust_visibility never gets a real trust-PSI initiate', async () => {
  // Only peer 1 opted into trust visibility; peers 2 and 3 are trusted one-way. A real initiate naming 2 or 3
  // would tell them (and the satellite) "this fingerprint runs trust-PSI with you": a one-way trust revealed.
  const b = book(3, (_fp, i) => i === 0);
  const slots = newSource();
  const real: string[] = [];
  const lengths = new Set<number>();
  for (let t = 0; t < 6; t++) {
    posts = [];
    await tick(b, slots, 'trust');
    assert.equal(posts.length, K, 'exactly K requests per tick, whatever the gate decides');
    for (const p of posts) {
      lengths.add(p.raw.length);
      if (p.body.cover === false) real.push(p.body.responder_fingerprint as string);
    }
  }
  assert.ok(!real.includes(fpN(2)) && !real.includes(fpN(3)), `real initiates went to non-visible peers: ${real.join(',')}`);
  assert.deepEqual([...new Set(real)], [fpN(1)], 'the opted-in peer still syncs');
  assert.equal(lengths.size, 1, 'gated-out ticks are cover of the same sealed length');
});
