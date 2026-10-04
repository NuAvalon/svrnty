// allowed-sync — client /allowed ADD/DELETE signing + reconcile-by-invariant (AND-gate b, #572).
// Run: node --import tsx --test src/lib/sync/allowed-sync.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  addAllowedSender,
  removeAllowedSender,
  reconcileAllowedForPeer,
  allowedRowShouldExist,
  type PeerConsent,
} from './allowed-sync';

const OWNER = 'aa'.repeat(32); // 64 lowercase-hex
const SENDER = 'bb'.repeat(32);
const SEED = ed25519.utils.randomSecretKey(); // 32B bound sig seed (self-bind)
const PUB = ed25519.getPublicKey(SEED);
const FIXED_UNIX = 1_700_000_000;

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
