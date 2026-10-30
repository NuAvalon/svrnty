// #704 (A) on #697: the consent gates around the resync slot, per layer and per role (Apollo's probes on
// 704A-on-295 @41c8691, Q1-Q12, folded in by Flint). Q9-Q11 pin the #697 RESPONDER and INITIATOR gates for the
// TRUST layer, which no other test exercised; Q12 pins the bucket boundary (exactly N syncs real, N+1 is cover).
// REAL path: drives syncMutualTrust / respondToTrustSync / initiateTrustSync with a stubbed fetch and opens the
// POSTed bodies as the satellite would.
// Run: npx tsx --test src/lib/trust/psi-resync-slot.consent.test.ts
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateMailboxKeypair, toPublicKeys, toSecretKeys, mailboxFpOf } from '@/lib/crypto/mailbox-keys';
import { openPsiFromSatellite } from '@/lib/crypto/psi-wire-seal';
import type { MailboxEnvelopePackage } from '@/lib/crypto/mailbox-envelope';
import { syncMutualTrust, respondToTrustSync, initiateTrustSync, type OrchestratorDeps, type PSISyncOptions } from './mutual-trust-sync';
import {
  ResyncSlotSource,
  PSI_BLINDED_BUCKET_N as N,
  PSI_REQUESTS_PER_TICK_K as K,
} from './psi-resync-slot';

const sat = generateMailboxKeypair();
const ME = 'ab'.repeat(32);
// Wall clock under test: starts on a window boundary, each tick advances one 5-min sub-route.
let clock = Date.UTC(2026, 9, 25, 9, 0, 0);
const TICK_MS = 5 * 60 * 1000;
const newSource = () => new ResyncSlotSource(toPublicKeys(sat), () => clock);
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

// ---- Apollo independent probes (704A-on-295 @41c8691: R1 send-time gate, R2 due ∩ consent) ----
type Run = { real: string[]; covers: number; perTick: number[]; lengths: Set<number>; errors: string[] };
async function run(b: ReturnType<typeof book>, ticks: number, layer: 'know' | 'trust' = 'trust', between?: (t: number) => void): Promise<Run> {
  const slots = newSource(); const r: Run = { real: [], covers: 0, perTick: [], lengths: new Set(), errors: [] };
  for (let t = 0; t < ticks; t++) {
    between?.(t); posts = [];
    const res = await tick(b, slots, layer);
    r.errors.push(...res.errors);
    r.perTick.push(posts.length);
    for (const p of posts) { r.lengths.add(p.raw.length); if (p.body.cover === false) r.real.push(p.body.responder_fingerprint as string); else r.covers++; }
  }
  return r;
}

test('Q1 live posture: EMPTY trust opt-in set (reciprocal has no writer) -> 0 real initiates over 12 ticks, exactly K per tick, one sealed length', async () => {
  const b = book(4, () => false);
  const r = await run(b, 12);
  assert.deepEqual(r.real, []); assert.ok(r.perTick.every((n) => n === K), r.perTick.join(','));
  assert.equal(r.lengths.size, 1);
});
test('Q2 window property (D5): 6 trusted, 2 visible -> across 12 ticks every real initiate is to a visible peer; K per tick; one length; both visible peers get synced', async () => {
  const vis = new Set([fpN(2), fpN(5)]);
  const b = book(6, (fp) => vis.has(fp));
  const r = await run(b, 12);
  assert.ok(r.real.every((fp) => vis.has(fp)), r.real.join(','));
  assert.ok(r.perTick.every((n) => n === K)); assert.equal(r.lengths.size, 1);
  assert.deepEqual([...new Set(r.real)].sort(), [...vis].sort());
});
test('Q3 consent withdrawn mid-window: after peer 1 is removed from the opt-in set at tick 4, NO real initiate names peer 1 from tick 4 on', async () => {
  const b = book(3); let revoked = false; const all = b.peers;
  b.deps.getTrustVisiblePeers = async () => all.filter((fp) => !(revoked && fp === fpN(1))).map((fingerprint) => ({ fingerprint, lastSync: null }));
  const seen: Array<{ t: number; fp: string }> = [];
  const slots = newSource();
  for (let t = 0; t < 10; t++) {
    if (t === 4) revoked = true; posts = []; await tick(b, slots, 'trust');
    for (const p of posts) if (p.body.cover === false) seen.push({ t, fp: p.body.responder_fingerprint as string });
  }
  assert.ok(seen.filter((x) => x.t >= 4).every((x) => x.fp !== fpN(1)), JSON.stringify(seen.filter((x) => x.fp === fpN(1))));
});
test('Q4 a visible fp that is NOT in the trusted/due list (stale opt-in row) is never contacted', async () => {
  const b = book(2); const ghost = fpN(9);
  b.deps.getTrustVisiblePeers = async () => [...b.peers, ghost].map((fingerprint) => ({ fingerprint, lastSync: null }));
  const r = await run(b, 8);
  assert.ok(!r.real.includes(ghost), r.real.join(','));
});
test('Q5 unknown/future layer fails closed: 0 real initiates, K per tick', async () => {
  const b = book(3);
  const r = await run(b, 4, 'future' as unknown as 'trust');
  assert.deepEqual(r.real, []); assert.ok(r.perTick.every((n) => n === K), r.perTick.join(','));
});
test('Q6 KNOW layer: the same property (peers trusted but not open-visible never get a real KNOW initiate)', async () => {
  const b = book(3);
  b.deps.getKnownPeers = async () => [{ fingerprint: fpN(1), lastSync: null }];
  const r = await run(b, 8, 'know');
  assert.ok(r.real.every((fp) => fp === fpN(1)), r.real.join(','));
  assert.ok(r.perTick.every((n) => n === K));
});
test('Q7 a set over the bucket N is not synced as real (cover), still K per tick', async () => {
  const b = book(N + 1);
  const r = await run(b, 3);
  assert.deepEqual(r.real, []); assert.ok(r.perTick.every((n) => n === K));
});
test('Q8 INFO: when the opt-in dependency THROWS, what does the tick do? (request still goes out? error surfaced?)', async () => {
  const b = book(2);
  b.deps.getTrustVisiblePeers = async () => { throw new Error('store locked'); };
  const slots = newSource(); posts = [];
  const r = await tick(b, slots, 'trust');
  console.log('Q8 posts=' + posts.length + ' real=' + posts.filter((p) => p.body.cover === false).length + ' errors=' + JSON.stringify(r.errors));
  assert.equal(posts.filter((p) => p.body.cover === false).length, 0, 'no real initiate when the consent source fails');
});

// Responder / initiator gates (#697 code in the merged tree) and the N boundary.
function pendingFrom(initiators: string[]) {
  const prev = globalThis.fetch; const touched: string[] = [];
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    const u = String(url);
    if (u.includes('/trust/psi/pending/')) return new Response(JSON.stringify({ sessions: initiators.map((i, k) => ({ session_id: `sess-${k}-${i.slice(-2)}`, initiator_fingerprint: i, created_at: Math.floor(Date.now() / 1000) })) }), { status: 200 });
    touched.push(`${init?.method ?? 'GET'} ${u}`);
    return new Response('nope', { status: 500 });
  }) as typeof fetch;
  return { touched, restore: () => { globalThis.fetch = prev; } };
}
test('Q9 RESPONDER gate (trust): a pending session from a trusted-but-not-opted-in initiator is never touched (no blinded fetch, no response); the opted-in one is', async () => {
  const b = book(3, (_fp, i) => i === 0); // only peer 1 visible
  const f = pendingFrom([fpN(2), fpN(1), fpN(3)]);
  try { await respondToTrustSync(b.deps, options(newSource()), 'trust'); } finally { f.restore(); }
  assert.ok(f.touched.some((t) => t.includes('sess-1-01')), 'the visible initiator was not even attempted: ' + f.touched.join(' | '));
  assert.ok(!f.touched.some((t) => t.includes('sess-0-02') || t.includes('sess-2-03')), 'a non-visible initiator was touched: ' + f.touched.join(' | '));
});
test('Q10 RESPONDER gate (know): same property on the KNOW layer', async () => {
  const b = book(3); b.deps.getKnownPeers = async () => [{ fingerprint: fpN(1), lastSync: null }];
  const f = pendingFrom([fpN(2), fpN(1)]);
  try { await respondToTrustSync(b.deps, options(newSource()), 'know'); } finally { f.restore(); }
  assert.ok(!f.touched.some((t) => t.includes('sess-0-02')), f.touched.join(' | '));
  assert.ok(f.touched.some((t) => t.includes('sess-1-01')));
});
test('Q11 INITIATOR gate (trust, non-resync path): initiateTrustSync to a trusted-but-not-visible peer refuses and makes NO request', async () => {
  const b = book(3, (_fp, i) => i === 0);
  const f = pendingFrom([]);
  let res: unknown;
  try { res = await initiateTrustSync(b.deps, fpN(2), options(newSource()), 'trust'); } finally { f.restore(); }
  assert.ok(res && typeof res === 'object' && 'error' in (res as object), JSON.stringify(res)?.slice(0, 120));
  assert.deepEqual(f.touched, []);
});
test('Q12 boundary: a visible set of EXACTLY N contacts is synced as a real initiate (not cover); N+1 is cover', async () => {
  const b = book(N);
  const r = await run(b, 2);
  assert.ok(r.real.length > 0, 'exactly N contacts must still sync (real initiate)');
  const b2 = book(N + 1); const r2 = await run(b2, 2);
  assert.deepEqual(r2.real, []);
});
