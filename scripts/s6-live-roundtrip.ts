// scripts/s6-live-roundtrip.ts
//
// LIVE S6 consent-delta (go-private reversibility) round-trip against the DEPLOYED dev satellite
// (https://dev.svrnty.is) /onion + /route proxy (PR #180). Security-reviewer-facing artifact — NOT
// production code; it drives the UNMODIFIED crypto/transport leaves (consent-delta-emit.ts +
// consent-delta-transport.ts) against the real wire, modifies nothing.
//   Run: npx tsx scripts/s6-live-roundtrip.ts
//
// MIRRORS the in-memory (ROUND TRIP) positive-control in consent-delta-transport.test.ts, with the
// mockBlindRelay swapped for httpOnionRelay(dev) and the generated satellite key swapped for the REAL
// fetched dev satellite routing key. The ONLY new thing vs the unit test is the deploy-integration proof:
// that the real client → /api/satellite/onion (deposit) → S1 peel+bucket → /api/satellite/route/{id}
// (poll) path actually CARRIES the sealed cell (no envelope-strip) and DELIVERS. That path is exactly the
// S6 flip-gate leg (Archie/Flint/Hypatia: a go-private that can't deposit reaches nobody = the
// survivor-safety silent-failure).
//
// WHAT IT PROVES, IN ORDER:
//   0. Fetch the live satellite routing key (seal the onion OUTER to it).
//   A. SAME-WINDOW round-trip: C (alice) go-private → deposit to live /onion → P (bob) polls his route
//      (horizon 0) → opens with his DEVICE keys → unframes → verifies C's sig → applies. The sealed inner
//      must come back VERBATIM (no strip) and the disclosed_circle-clear must reach the apply sink.
//   B. OFFLINE CATCH-UP (★ offline-poll-depth, Flint seal-req #1/#2): deposit at window W while bob is
//      "offline", then bob returns at W+k and RANGE-polls [W+k-horizon, W+k] → finds the W deposit → applies.
//      Proves a while-offline go-private is not silently missed on the live relay.
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { generateMailboxKeypair, toPublicKeys, toSecretKeys, mailboxFpOf } from '../src/lib/crypto/mailbox-keys.js';
import type { MailboxPublicKeys } from '../src/lib/crypto/mailbox-envelope.js';
import type { ApplyConsentDeltaDeps, EmitPeerTarget } from '../src/lib/sync/consent-delta-emit.js';
import {
  httpOnionRelay,
  depositConsentDeltas,
  consumeConsentDeltas,
  deriveRotatingRouteId,
  createInMemoryRouteRatchetCache,
  epochWeekToAnchorWindow,
  ANCHOR_EPOCH_WEEK,
  HORIZON_WINDOWS,
  type ConsumeContactCandidate,
} from '../src/lib/sync/consent-delta-transport.js';

const DEV_BASE = 'https://dev.svrnty.is';
const API = `${DEV_BASE}/api/satellite`;
const HOUR_MS = 3600 * 1000;

function hr(t: string) { console.log(`\n${'='.repeat(78)}\n${t}\n${'='.repeat(78)}`); }

function recordingDeps(): ApplyConsentDeltaDeps & { calls: Array<[string, 'know' | 'trust', string[]]> } {
  const calls: Array<[string, 'know' | 'trust', string[]]> = [];
  return { calls, applyMutualResult: async (fp, layer, disclosed) => { calls.push([fp, layer, disclosed]); } };
}

// Wrap global fetch so every /onion + /route request/response is on the record (the deploy-level proof —
// shows {deposited:true} / {inners:[...]} and that the inner comes back verbatim).
function installWireTrace(): () => void {
  const orig = globalThis.fetch;
  let n = 0;
  (globalThis as unknown as { fetch: typeof fetch }).fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const seq = ++n;
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
    const method = init?.method ?? 'GET';
    const body = typeof init?.body === 'string' ? init.body : '';
    const bodyPreview = body.length > 240 ? `${body.slice(0, 240)}…(${body.length}B)` : body;
    console.log(`  [wire ${seq}] -> ${method} ${url}${body ? `  body: ${bodyPreview}` : ''}`);
    const res = await orig(input as RequestInfo, init);
    const text = await res.clone().text();
    const tPreview = text.length > 400 ? `${text.slice(0, 400)}…(${text.length}B)` : text;
    console.log(`  [wire ${seq}] <- HTTP ${res.status}  ${tPreview}`);
    return res;
  }) as typeof fetch;
  return () => { (globalThis as unknown as { fetch: typeof fetch }).fetch = orig; };
}

async function fetchSatelliteKey(): Promise<MailboxPublicKeys | null> {
  const res = await fetch(`${API}/trust/psi/satellite-key`);
  if (!res.ok) { console.log(`satellite-key fetch HTTP ${res.status}`); return null; }
  const rec = (await res.json()) as { x25519_pk?: string; mlkem1024_pk?: string; mailbox_fp?: string };
  if (typeof rec.x25519_pk !== 'string' || typeof rec.mlkem1024_pk !== 'string') { console.log('satellite-key: unexpected shape'); return null; }
  console.log(`satellite key: mailbox_fp=${rec.mailbox_fp ?? '(none)'} x25519=${rec.x25519_pk.slice(0, 16)}… mlkem=${rec.mlkem1024_pk.slice(0, 16)}…`);
  return { x25519Pub: hexToBytes(rec.x25519_pk), mlkem1024Pub: hexToBytes(rec.mlkem1024_pk) };
}

// A fresh C (alice, consent-changer) + P (bob, recipient device) pair, per scenario, so buckets don't
// collide across scenarios/re-runs. fp = SHA256(identity pubkey) as hex (stable 32-byte binding).
function pair() {
  const cSeed = ed25519.utils.randomSecretKey();
  const cSignPub = ed25519.getPublicKey(cSeed);
  const pSeed = ed25519.utils.randomSecretKey();
  const pPub = ed25519.getPublicKey(pSeed);
  return {
    cSeed, cSignPub, cFp: bytesToHex(sha256(cSignPub)),
    pSeed, pPub, pFp: bytesToHex(sha256(pPub)),
    device: generateMailboxKeypair(),
  };
}

async function scenario(
  label: string,
  satellite: MailboxPublicKeys,
  depositNow: number,
  pollNow: number,
  horizonWindows: number,
): Promise<boolean> {
  hr(label);
  const relay = httpOnionRelay(API);
  const p = pair();

  const routeId = deriveRotatingRouteId({
    myEdPriv: p.cSeed, myFp: p.cFp, peerEdPub: p.pPub, peerFp: p.pFp,
    direction: 'outbound', cache: createInMemoryRouteRatchetCache(), now: depositNow,
  });
  console.log(`C(alice) fp=${p.cFp.slice(0, 12)}…  P(bob) fp=${p.pFp.slice(0, 12)}…  depositWindow routeId=${routeId}`);

  const peer: EmitPeerTarget = { fingerprint: p.pFp, deviceMailbox: toPublicKeys(p.device), epoch: 7, route: routeId };
  console.log('\n-- DEPOSIT: C go-private -> POST /onion --');
  const dep = await depositConsentDeltas({
    relay, withdrawal: { kind: 'go-private' }, peers: [peer], signerSeed: p.cSeed, satellite,
  });
  console.log(`deposit result: deposited=${JSON.stringify(dep.deposited)} failed=${JSON.stringify(dep.failed)} skipped=${JSON.stringify(dep.skipped)}`);
  if (dep.deposited.length !== 1) {
    console.log('DEPOSIT FAILED — the /onion peel rejected the cell (wrong satellite key?) or the deposit POST failed. See wire above.');
    return false;
  }

  console.log(`\n-- CONSUME: P range-polls [${horizonWindows} windows back] GET /route/{id} --`);
  const deps = recordingDeps();
  const contacts: ConsumeContactCandidate[] = [{ peerFingerprint: p.cFp, signerSignPub: p.cSignPub, lastSeenEpoch: -1 }];
  const consume = await consumeConsentDeltas({
    relay, contacts,
    myEdPriv: p.pSeed, myFp: p.pFp,
    myDeviceSecrets: toSecretKeys(p.device), myDeviceMailboxFpHex: mailboxFpOf(p.device),
    myRecipientBinding: Uint8Array.from(Buffer.from(p.pFp, 'hex')),
    deps, horizonWindows, now: pollNow,
  });
  console.log(`consume result: applied=${JSON.stringify(consume.applied)} skipped=${JSON.stringify(consume.skipped)}`);
  console.log(`apply sink calls: ${JSON.stringify(deps.calls)}`);

  const delivered =
    consume.applied.length === 1 &&
    consume.applied[0]!.peerFingerprint === p.cFp &&
    consume.applied[0]!.epoch === 7 &&
    deps.calls.length === 1 &&
    deps.calls[0]![0] === p.cFp &&
    deps.calls[0]![1] === 'know' &&
    JSON.stringify(deps.calls[0]![2]) === '[]';
  console.log(delivered ? `${label}: PASS — go-private DELIVERED cross the live relay + applied (disclosed_circle cleared)` : `${label}: FAIL — not delivered/applied as expected`);
  return delivered;
}

async function main() {
  hr('STEP 0 — fetch the live satellite routing key (seal the onion OUTER to it)');
  const satellite = await fetchSatelliteKey();
  if (!satellite) { console.log('No satellite key — cannot run a real live round-trip. Aborting.'); return; }

  const restore = installWireTrace();
  let a = false, b = false;
  try {
    const base = (epochWeekToAnchorWindow(ANCHOR_EPOCH_WEEK) + 500) * HOUR_MS;
    // A: same-window (horizon 0) — isolates "live deposit+poll delivers at all".
    a = await scenario('SCENARIO A — SAME-WINDOW live round-trip (horizon 0)', satellite, base, base, 0);
    // B: offline catch-up — deposit at W, bob returns 3 windows later, range-polls a modest horizon (6)
    // that covers the gap. (Prod default is HORIZON_WINDOWS=336=2wk; a small live range proves the
    // mechanism without hammering the rate-limited dev relay with 336 sequential GETs.)
    b = await scenario('SCENARIO B — OFFLINE CATCH-UP (deposit W, poll W+3, horizon 6)', satellite, base, base + 3 * HOUR_MS, 6);
  } finally {
    restore();
  }

  hr('SUMMARY');
  console.log(`A same-window live deposit→deliver: ${a ? 'PASS' : 'FAIL'}`);
  console.log(`B offline catch-up range-poll deliver: ${b ? 'PASS' : 'FAIL'}`);
  console.log(`Prod offline horizon default = ${HORIZON_WINDOWS} windows (${HORIZON_WINDOWS / 168} weeks).`);
  console.log(a && b ? '\nS6 LIVE ROUND-TRIP: GREEN (deposit→/onion→peel→bucket→/route→open→verify→apply, verbatim, cross-session).' : '\nS6 LIVE ROUND-TRIP: NOT green — see scenarios above.');
}

main().catch((e) => { console.error('HARNESS CRASHED:', e); process.exitCode = 1; });
