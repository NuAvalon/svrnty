// allowed-sync — client /allowed ADD/DELETE signing + reconcile-by-invariant (AND-gate b, #572).
// Run: node --import tsx --test src/lib/sync/allowed-sync.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { psiAuthPreimage } from '@/lib/identity/raw-sign';
import {
  addAllowedSender,
  removeAllowedSender,
  reconcileAllowedForPeer,
  allowedRowShouldExist,
  allowedRowDecision,
  listAllowedSenders,
  MAX_LISTED,
  type PeerConsent,
} from './allowed-sync';

const OWNER = 'aa'.repeat(32); // 64 lowercase-hex
const SENDER = 'bb'.repeat(32);
const SEED = ed25519.utils.randomSecretKey(); // 32B bound sig seed (self-bind)
const PUB = ed25519.getPublicKey(SEED);
const FIXED_UNIX = 1_700_000_000;
const ALLOWED: PeerConsent = { trusted: true, openVisibility: true, blocked: false, perContactPrivate: false };   // a row exists for this peer
const NEVER: PeerConsent = { trusted: false, openVisibility: false, blocked: false, perContactPrivate: false };    // the fresh-import default: no row, never had one

function b64ToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64'));
}

interface Captured {
  url: string;
  method: string;
  body: Record<string, unknown>;
  xsig: string | null;
}
function capturingFetch(status = 200): { fetchImpl: typeof fetch; calls: Captured[] } {
  const calls: Captured[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    calls.push({
      url: String(input),
      method: init?.method || 'GET',
      body: init?.body && typeof init.body === 'string' ? JSON.parse(init.body) : {},
      xsig: headers.get('X-Signature'),
    });
    return new Response('{}', { status });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

test('addAllowedSender POSTs /{owner} with a signed svrnty-allowed-add wire that verifies', async () => {
  const { fetchImpl, calls } = capturingFetch(200);
  const ok = await addAllowedSender({
    ownerFp: OWNER,
    senderFp: SENDER,
    seed: SEED,
    fetchImpl,
    nowUnixSeconds: FIXED_UNIX,
  });
  assert.equal(ok, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, 'POST');
  assert.equal(calls[0].url, `/api/satellite/allowed/${OWNER}`);
  assert.equal(calls[0].body.sender_fingerprint, SENDER);
  const [unixStr, b64sig] = String(calls[0].body.signature).split(':');
  assert.equal(unixStr, String(FIXED_UNIX)); // wire = {unix}:{b64sig}
  const preimage = new TextEncoder().encode(`svrnty-allowed-add:${OWNER}:${SENDER}:${FIXED_UNIX}`);
  assert.equal(ed25519.verify(b64ToBytes(b64sig), preimage, PUB), true); // bound-sig-key signed the exact preimage
});

test('removeAllowedSender DELETEs /{owner}/{sender} with X-Signature svrnty-allowed-remove that verifies', async () => {
  const { fetchImpl, calls } = capturingFetch(200);
  const ok = await removeAllowedSender({
    ownerFp: OWNER,
    senderFp: SENDER,
    seed: SEED,
    fetchImpl,
    nowUnixSeconds: FIXED_UNIX,
  });
  assert.equal(ok, true);
  assert.equal(calls[0].method, 'DELETE');
  assert.equal(calls[0].url, `/api/satellite/allowed/${OWNER}/${SENDER}`);
  const [unixStr, b64sig] = String(calls[0].xsig).split(':');
  assert.equal(unixStr, String(FIXED_UNIX));
  const preimage = new TextEncoder().encode(`svrnty-allowed-remove:${OWNER}:${SENDER}:${FIXED_UNIX}`);
  assert.equal(ed25519.verify(b64ToBytes(b64sig), preimage, PUB), true);
  // domain-separation: the remove sig must NOT verify as an add
  const addPre = new TextEncoder().encode(`svrnty-allowed-add:${OWNER}:${SENDER}:${FIXED_UNIX}`);
  assert.equal(ed25519.verify(b64ToBytes(b64sig), addPre, PUB), false);
});

// piece-1 (Flint seal #158892): KNOWN reveal = open_vis ∩ !blocked ∩ !per_contact_private — the trusted
// term DROPPED to the trust layer (piece-2). So untrust is NO LONGER a known-exit; the exits are
// go-private, block, and per_contact_private (new). Was: 'ADD iff trusted∩open_vis∩!blocked'.
test('reconcileAllowedForPeer: ADD iff open_vis∩!blocked∩!pcp (piece-1; trusted dropped), else DELETE', async () => {
  const cases: Array<{ consent: PeerConsent; action: 'add' | 'delete'; method: string }> = [
    { consent: { trusted: true, openVisibility: true, blocked: false, perContactPrivate: false }, action: 'add', method: 'POST' }, // full invariant → ADD
    { consent: { trusted: false, openVisibility: true, blocked: false, perContactPrivate: false }, action: 'add', method: 'POST' }, // untrust: NO LONGER a known-exit (trusted→trust layer, piece-2) → ADD
    { consent: { trusted: true, openVisibility: false, blocked: false, perContactPrivate: false }, action: 'delete', method: 'DELETE' }, // go-private exit
    { consent: { trusted: true, openVisibility: true, blocked: true, perContactPrivate: false }, action: 'delete', method: 'DELETE' }, // block exit
    { consent: { trusted: true, openVisibility: true, blocked: false, perContactPrivate: true }, action: 'delete', method: 'DELETE' }, // per_contact_private exit (new, piece-1)
  ];
  for (const c of cases) {
    const { fetchImpl, calls } = capturingFetch(200);
    const r = await reconcileAllowedForPeer({
      ownerFp: OWNER,
      senderFp: SENDER,
      seed: SEED,
      rowAtRelay: true,

      consent: c.consent,
      fetchImpl,
      nowUnixSeconds: FIXED_UNIX,
    });
    assert.equal(r.action, c.action, JSON.stringify(c.consent));
    assert.equal(r.ok, true);
    assert.equal(calls[0].method, c.method, JSON.stringify(c.consent));
  }
});

test('fail-closed: non-2xx → false, network throw → false', async () => {
  const { fetchImpl: f403 } = capturingFetch(403);
  assert.equal(
    await addAllowedSender({ ownerFp: OWNER, senderFp: SENDER, seed: SEED, fetchImpl: f403, nowUnixSeconds: FIXED_UNIX }),
    false,
  );
  const throwing = (async () => {
    throw new Error('network down');
  }) as unknown as typeof fetch;
  assert.equal(
    await removeAllowedSender({ ownerFp: OWNER, senderFp: SENDER, seed: SEED, fetchImpl: throwing, nowUnixSeconds: FIXED_UNIX }),
    false,
  );
});

test('allowedRowShouldExist = open_vis ∩ !blocked ∩ !pcp (piece-1, Flint seal #158892; trusted dropped)', () => {
  assert.equal(allowedRowShouldExist({ trusted: true, openVisibility: true, blocked: false, perContactPrivate: false }), true);
  // untrusted + open_vis + !blocked + !pcp → NOW TRUE (the trusted term moved to the trust layer, piece-2)
  assert.equal(allowedRowShouldExist({ trusted: false, openVisibility: true, blocked: false, perContactPrivate: false }), true);
  assert.equal(allowedRowShouldExist({ trusted: true, openVisibility: false, blocked: false, perContactPrivate: false }), false);
  assert.equal(allowedRowShouldExist({ trusted: true, openVisibility: true, blocked: true, perContactPrivate: false }), false);
});

// ── piece-1 (§F case 2): KNOWN reveal = open_vis ∩ !blocked ∩ !per_contact_private. trusted DROPPED;
// per_contact_private is a TRUTHY-exclusion AND-term (fail-closed). ──────────────────────────────────
test('piece-1 allowedRowShouldExist: trusted DROPPED; per_contact_private truthy-excludes (fail-closed)', () => {
  // untrusted but open-visible ∩ !blocked ∩ !pcp → NOW TRUE (the trusted term moved to the trust layer)
  assert.equal(
    allowedRowShouldExist({ trusted: false, openVisibility: true, blocked: false, perContactPrivate: false }),
    true,
  );
  // per_contact_private set → row must NOT exist (excluded from the reveal set)
  assert.equal(
    allowedRowShouldExist({ trusted: false, openVisibility: true, blocked: false, perContactPrivate: true }),
    false,
  );
  // LOAD-BEARING: a MALFORMED TRUTHY pcp must fail-CLOSED (exclude). `!c.perContactPrivate` returns false
  // here; a `=== true` check would have wrongly fail-OPENed (included it).
  assert.equal(
    allowedRowShouldExist({
      trusted: true,
      openVisibility: true,
      blocked: false,
      perContactPrivate: 'yes' as unknown as boolean,
    }),
    false,
  );
});

// ── piece-1 (§F case 3): the pcp toggle is a reveal-set entry/exit — clearing pcp ADDs, setting pcp
// DELETEs (when open_vis ∩ !blocked). ────────────────────────────────────────────────────────────────
test('piece-1 reconcile: pcp true→false → ADD (open_vis∩!blocked); false→true → DELETE', async () => {
  // pcp cleared (false) while open-visible ∩ !blocked → becomes revealable → ADD (POST)
  {
    const { fetchImpl, calls } = capturingFetch(200);
    const r = await reconcileAllowedForPeer({
      ownerFp: OWNER,
      senderFp: SENDER,
      seed: SEED,
      rowAtRelay: true,

      consent: { trusted: true, openVisibility: true, blocked: false, perContactPrivate: false },
      fetchImpl,
      nowUnixSeconds: FIXED_UNIX,
    });
    assert.equal(r.action, 'add');
    assert.equal(r.ok, true);
    assert.equal(calls[0].method, 'POST');
  }
  // pcp set (true) → goes private → DELETE (the #111-style revoke leg)
  {
    const { fetchImpl, calls } = capturingFetch(200);
    const r = await reconcileAllowedForPeer({
      ownerFp: OWNER,
      senderFp: SENDER,
      seed: SEED,
      rowAtRelay: true,

      consent: { trusted: true, openVisibility: true, blocked: false, perContactPrivate: true },
      fetchImpl,
      nowUnixSeconds: FIXED_UNIX,
    });
    assert.equal(r.action, 'delete');
    assert.equal(r.ok, true);
    assert.equal(calls[0].method, 'DELETE');
  }
});

// ── piece-1 (§F case 5): re-importing a pcp'd contact must NOT re-add it to the reveal set. ────────────
test('piece-1 import-preserve: a re-imported pcp survivor is NOT re-added to the reveal set (DELETE)', async () => {
  // ImportContactsDialog (§D3) builds consent from up.survivor.per_contact_private; a survivor still
  // carrying pcp → allowedRowShouldExist=false → reconcile DELETE, never a re-ADD.
  assert.equal(
    allowedRowShouldExist({ trusted: true, openVisibility: true, blocked: false, perContactPrivate: true }),
    false,
  );
  const { fetchImpl, calls } = capturingFetch(200);
  const r = await reconcileAllowedForPeer({
    ownerFp: OWNER,
    senderFp: SENDER,
    seed: SEED,
    rowAtRelay: true,

    consent: { trusted: true, openVisibility: true, blocked: false, perContactPrivate: true },
    fetchImpl,
    nowUnixSeconds: FIXED_UNIX,
  });
  assert.equal(r.action, 'delete'); // re-import of a pcp'd peer → DELETE, not ADD
  assert.equal(r.ok, true);
  assert.equal(calls[0].method, 'DELETE');
  // NOTE: the record-level PRESERVE (updateContact's shallow merge leaving
  // metadata.share_settings.per_contact_private untouched so up.survivor carries it) is a client-store
  // property confirmed by inspection in PATCH §D3 — outside this sync unit layer, so not unit-tested here.
});

// ── #959: ONE rule. A DELETE is sent only for a peer that MAY HAVE a row (it is in the owner's local allowed set) and whose consent no longer allows one. ──────────────────────────
test('ARV1 the decision, at its thresholds: ADD whenever the consent allows a row; DELETE only for a peer that may have a row and is not allowed; otherwise NOTHING', () => {
  const exits: Array<[string, PeerConsent]> = [
    ['go private', { ...ALLOWED, openVisibility: false }],
    ['block', { ...ALLOWED, blocked: true }],
    ['per-contact private', { ...ALLOWED, perContactPrivate: true }],
    ['never opened', NEVER],
  ];
  for (const [label, after] of exits) assert.equal(allowedRowDecision(true, after), 'delete', `a peer that may have a row, ${label}`);
  for (const [label, after] of exits) assert.equal(allowedRowDecision(false, after), 'none', `a peer that never had a row, ${label}: nothing to revoke`);
  assert.equal(allowedRowDecision(false, ALLOWED), 'add', 'a grant');
  assert.equal(allowedRowDecision(true, ALLOWED), 'add', 'no change while allowed: an idempotent re-add, as before');
});

test('ARV2 reconcileAllowedForPeer: a peer that never had a row sends 0 requests; one that may have a row and is not allowed sends EXACTLY ONE signed DELETE; a grant sends one POST', async () => {
  const none = capturingFetch(200);
  const r0 = await reconcileAllowedForPeer({ ownerFp: OWNER, senderFp: SENDER, seed: SEED, rowAtRelay: false, consent: NEVER, fetchImpl: none.fetchImpl, nowUnixSeconds: FIXED_UNIX });
  assert.deepEqual(r0, { action: 'none' });
  assert.equal(none.calls.length, 0, 'nothing was sent');
  const del = capturingFetch(200);
  const r2 = await reconcileAllowedForPeer({ ownerFp: OWNER, senderFp: SENDER, seed: SEED, rowAtRelay: true, consent: { ...ALLOWED, blocked: true }, fetchImpl: del.fetchImpl, nowUnixSeconds: FIXED_UNIX });
  assert.deepEqual(r2, { action: 'delete', ok: true });
  assert.equal(del.calls.length, 1);
  assert.equal(del.calls[0].method, 'DELETE');
  assert.ok(del.calls[0].xsig, 'and it is signed');
  const add = capturingFetch(200);
  const r3 = await reconcileAllowedForPeer({ ownerFp: OWNER, senderFp: SENDER, seed: SEED, rowAtRelay: false, consent: ALLOWED, fetchImpl: add.fetchImpl, nowUnixSeconds: FIXED_UNIX });
  assert.deepEqual(r3, { action: 'add', ok: true });
  assert.equal(add.calls.length, 1);
  assert.equal(add.calls[0].method, 'POST');
});

test('ARV3 (source shape) nothing reaches removeAllowedSender except through reconcileAllowedForPeer: the ONLY non-test call is inside that function', async () => {
  const { readFileSync, readdirSync, statSync } = await import('node:fs');
  const { join } = await import('node:path');
  const files: string[] = [];
  const walk = (d: string) => { for (const n of readdirSync(d)) { const p = join(d, n); if (statSync(p).isDirectory()) walk(p); else if (/\.(ts|tsx)$/.test(n) && !/\.test\.(ts|tsx)$/.test(n)) files.push(p); } };
  walk(join(process.cwd(), 'src')); walk(join(process.cwd(), 'app'));
  const calls: string[] = []; let defs = 0;
  for (const f of files) {
    const src = readFileSync(f, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
    defs += (src.match(/function removeAllowedSender\s*\(/g) ?? []).length;
    for (const m of src.matchAll(/\bremoveAllowedSender\s*\(/g)) { if (!src.slice(Math.max(0, m.index! - 20), m.index!).includes('function ')) calls.push(f.replace(process.cwd() + '/', '')); }
  }
  assert.equal(defs, 1, 'CONTROL: the walker found the one definition');
  assert.deepEqual(calls, ['src/lib/sync/allowed-sync.ts'], 'the only call is in allowed-sync.ts (src/ and app/ both walked)');
  const body = readFileSync(join(process.cwd(), 'src/lib/sync/allowed-sync.ts'), 'utf8');
  const fn = body.slice(body.indexOf('export async function reconcileAllowedForPeer'));
  assert.match(fn, /removeAllowedSender\s*\(/, 'and it sits inside reconcileAllowedForPeer');
});

// ── #959: the relay's own list is the truth about who may have a row (retire this with #540; the revoke check moves client-side with it) ──────────────────────────────────────────
function replyingFetch(reply: () => Response | Promise<Response>): { fetchImpl: typeof fetch; calls: Captured[] } {
  const calls: Captured[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), method: init?.method || 'GET', body: {}, xsig: new Headers(init?.headers).get('X-Signature') });
    return reply();
  }) as typeof fetch;
  return { fetchImpl, calls };
}
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

test('ALS1 listAllowedSenders: a signed GET /allowed/{owner} whose X-Signature is the psi-auth tag the relay verifies, answered with the list', async () => {
  const { fetchImpl, calls } = replyingFetch(() => json(200, { owner_fingerprint: OWNER, allowed: [SENDER, 'cc'.repeat(32)], count: 2 }));
  const r = await listAllowedSenders({ ownerFp: OWNER, senderFp: '', seed: SEED, fetchImpl, nowUnixSeconds: FIXED_UNIX });
  assert.deepEqual(r, { status: 'ok', fps: [SENDER, 'cc'.repeat(32)] });
  assert.equal(calls.length, 1, 'ONE request');
  assert.equal(calls[0].method, 'GET');
  assert.ok(calls[0].url.endsWith(`/api/satellite/allowed/${OWNER}`), calls[0].url);
  const [unix, sig] = calls[0].xsig!.split(':');
  assert.equal(Number(unix), FIXED_UNIX);
  assert.ok(ed25519.verify(b64ToBytes(sig), psiAuthPreimage(OWNER, FIXED_UNIX), PUB), 'the signature is svrnty-psi-auth:{owner}:{unix} by the bound key');
});

test('ALS2 EVERY failure is UNKNOWN, never an empty list: 403, 429, 500, 502, a network throw, a body that is not JSON, and a body with no list or a damaged one', async () => {
  const bad: Array<[string, () => Response | Promise<Response>]> = [
    ['403', () => json(403, { detail: 'Invalid signature' })], ['429', () => json(429, {})], ['500', () => json(500, {})], ['502', () => json(502, {})],
    ['network', () => { throw new TypeError('Failed to fetch'); }],
    ['not json', () => new Response('<html>', { status: 200 })],
    ['no list', () => json(200, { owner_fingerprint: OWNER })],
    ['list is a string', () => json(200, { allowed: 'x' })],
    ['a non-string member', () => json(200, { allowed: [SENDER, 5] })],
    ['an empty-string member', () => json(200, { allowed: [''] })],
    ['null body', () => json(200, null)],
    ['a junk entry among good ones (the WHOLE list is unknown)', () => json(200, { allowed: [SENDER, 'x:y'] })],
    ['a path-like entry', () => json(200, { allowed: ['../../etc'] })],
    ['an entry one character short of a fingerprint', () => json(200, { allowed: ['a'.repeat(63)] })],
    ['an entry one character past a fingerprint', () => json(200, { allowed: ['a'.repeat(65)] })],
    ['a non-hex entry of the right length', () => json(200, { allowed: ['g'.repeat(64)] })],
  ];
  for (const [label, reply] of bad) {
    const { fetchImpl } = replyingFetch(reply);
    const r = await listAllowedSenders({ ownerFp: OWNER, senderFp: '', seed: SEED, fetchImpl, nowUnixSeconds: FIXED_UNIX });
    assert.deepEqual(r, { status: 'unknown' }, label);
  }
});

test('ALS3 410 is the ONE exception: the relay keeps no list (#540), so nothing is owed; and a real EMPTY list is an ok answer, not unknown (so unknown means something)', async () => {
  const gone = replyingFetch(() => json(410, { detail: 'gone' }));
  assert.deepEqual(await listAllowedSenders({ ownerFp: OWNER, senderFp: '', seed: SEED, fetchImpl: gone.fetchImpl, nowUnixSeconds: FIXED_UNIX }), { status: 'gone' });
  const empty = replyingFetch(() => json(200, { owner_fingerprint: OWNER, allowed: [], count: 0 }));
  assert.deepEqual(await listAllowedSenders({ ownerFp: OWNER, senderFp: '', seed: SEED, fetchImpl: empty.fetchImpl, nowUnixSeconds: FIXED_UNIX }), { status: 'ok', fps: [] });
});

test('ALS4 the list request carries cache: "no-store" itself, so a failure cannot be answered from a browser or proxy cache as a stale 200 whatever a deploy\'s defaults or headers are', async () => {
  let init: RequestInit | undefined;
  const fetchImpl = (async (_i: RequestInfo | URL, i?: RequestInit) => { init = i; return json(200, { allowed: [] }); }) as typeof fetch;
  await listAllowedSenders({ ownerFp: OWNER, senderFp: '', seed: SEED, fetchImpl, nowUnixSeconds: FIXED_UNIX });
  assert.equal(init?.method, 'GET');
  assert.equal(init?.cache, 'no-store');
});

test('ALS5 THE BOUND: MAX_LISTED entries is an answer; one more is UNKNOWN as a whole, never a partial use', async () => {
  const fp = (i: number) => i.toString(16).padStart(64, '0');
  const at = replyingFetch(() => json(200, { allowed: Array.from({ length: MAX_LISTED }, (_, i) => fp(i)) }));
  const ok = await listAllowedSenders({ ownerFp: OWNER, senderFp: '', seed: SEED, fetchImpl: at.fetchImpl, nowUnixSeconds: FIXED_UNIX });
  assert.equal(ok.status, 'ok'); assert.equal(ok.status === 'ok' && ok.fps.length, MAX_LISTED);
  const over = replyingFetch(() => json(200, { allowed: Array.from({ length: MAX_LISTED + 1 }, (_, i) => fp(i)) }));
  assert.deepEqual(await listAllowedSenders({ ownerFp: OWNER, senderFp: '', seed: SEED, fetchImpl: over.fetchImpl, nowUnixSeconds: FIXED_UNIX }), { status: 'unknown' });
});

test('ALS6 a fingerprint is 40 or 64 hex digits in either case, and the relay\'s OWN string is returned as it came (the caller compares case-insensitively and revokes with that string)', async () => {
  const upper = 'AB'.repeat(32), mixed = 'aB'.repeat(20);
  const { fetchImpl } = replyingFetch(() => json(200, { allowed: [upper, mixed] }));
  assert.deepEqual(await listAllowedSenders({ ownerFp: OWNER, senderFp: '', seed: SEED, fetchImpl, nowUnixSeconds: FIXED_UNIX }), { status: 'ok', fps: [upper, mixed] });
});
