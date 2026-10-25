// src/lib/crypto/distress-resync-view.test.ts
// #704 / D-S51 (D3 gate): at the GUARDIAN-SATELLITE's view, can a distress emission be told apart from the routine,
// ack-less PSI know-layer resync it is meant to hide in (Peter Q(iii); m10 ack-exempt clause)?
// Design decided (Archie task:704 #1185): (A) distress RIDES THE RESYNC, one fixed-size sealed slot per resync
// request (cover or cry, sealed to the guardian device), same endpoint, same 5-min tick, no extra request, no ack.
//
// At dev 374d31e (A) is NOT built, so the indistinguishability tests below are `todo`: they RUN and REPORT the gap
// (NEG-first: they fail today) without breaking CI. They must turn into plain tests, passing, when (A) lands; until
// then C9 stays OPEN and no copy may claim deniability or that a cry is sent (claim registry NV-6 / H-5).
// Facts pinned (Flint task:704 #1182/#1189): F1 sendDistress is an empty stub with no non-test caller; F2 the PSI
// resync is sealPsiToSatellite → POST /trust/psi on a fixed setInterval, while a distress cell rides the onion
// mailbox path.
// Run: npx tsx --test src/lib/crypto/distress-resync-view.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateMailboxKeypair, toPublicKeys } from './mailbox-keys.js';
import { sealToMailbox } from './mailbox-envelope.js';
import { sealOnion } from './onion-envelope.js';
import { sealPsiToSatellite } from './psi-wire-seal.js';
import { frameUniform } from './uniform-frame.js';
import { buildCoverPayload } from './distress-mark.js';
import * as distressApi from '../trust/distress.js';

const fill = (byte: number, n: number) => new Uint8Array(n).fill(byte);
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');

/** A distress-sized cell on the onion path exactly as distress-mark.test.ts puts it on the wire. */
async function distressOuter() {
  const device = generateMailboxKeypair();
  const satellite = generateMailboxKeypair();
  const cell = frameUniform(buildCoverPayload(1), 'cover'); // same FRAME_BYTES cell size as a distress cell
  const inner = await sealToMailbox(cell, toPublicKeys(device));
  return sealOnion(inner, toPublicKeys(satellite), 'r'.repeat(64));
}

/** A representative PSI know-layer resync request body with `n` blinded points (shape per mutual-trust-sync.ts). */
async function resyncRequest(n: number) {
  const satellite = generateMailboxKeypair();
  const body = {
    v: 1,
    op: 'initiate',
    blinded: Array.from({ length: n }, (_, i) => b64(fill(i & 0xff, 32))),
    response_pub: { x25519_pub_b64: b64(fill(1, 32)), mlkem1024_pub_b64: b64(fill(2, 1568)), mailbox_fp: 'f'.repeat(64) },
  };
  return sealPsiToSatellite(body, toPublicKeys(satellite));
}

// ── PASSING: what (A) can build on ────────────────────────────────────────────────────────────────
test('both ride the SAME envelope schema to the satellite (MailboxEnvelopePackage field set)', async () => {
  const d = await distressOuter();
  const r = await resyncRequest(4);
  assert.deepEqual(Object.keys(d).sort(), Object.keys(r).sort(), 'identical top-level field set');
  for (const f of ['epk', 'kem_ct', 'nonce'] as const) assert.equal(d[f].length, r[f].length, `${f} length identical`);
});

test('F1 pinned: sendDistress emits nothing (no request, no receipt) at this ref', async () => {
  const calls: unknown[] = [];
  const orig = globalThis.fetch;
  globalThis.fetch = (async (...a: unknown[]) => {
    calls.push(a);
    throw new Error('no network in this test');
  }) as typeof fetch;
  try {
    const out = await distressApi.sendDistress({ recipientFingerprints: ['aa'] });
    assert.equal(out, undefined, 'no receipt returned');
    assert.equal(calls.length, 0, 'no request made: the cry is NOT sent anywhere at this ref');
  } finally {
    globalThis.fetch = orig;
  }
});

// ── TODO until (A): the D3 property itself (NEG-first: these FAIL at dev 374d31e) ─────────────────
const GAP = 'F2: distress cover not built; (A) "distress rides the resync" pending (task:704)';

test('(A) size: a resync request and a distress emission have the SAME ct length at the satellite', { todo: GAP }, async () => {
  const d = await distressOuter();
  const r = await resyncRequest(4);
  assert.equal(r.ct.length, d.ct.length, `resync ct ${r.ct.length} vs distress ct ${d.ct.length}`);
});

test('(A) size: the resync request length does not depend on how many peers are being checked', { todo: GAP }, async () => {
  const a = await resyncRequest(1);
  const b = await resyncRequest(20);
  assert.equal(a.ct.length, b.ct.length, `1 peer → ${a.ct.length}, 20 peers → ${b.ct.length}: set size leaks`);
});

test('(A) channel: distress is emitted INSIDE the resync request (a fixed slot), not on its own path', { todo: GAP }, () => {
  // When (A) lands, the resync body builder exposes the slot and sendDistress fills it for the next tick.
  const slot = (distressApi as Record<string, unknown>).queueDistressForNextResync;
  assert.equal(typeof slot, 'function', 'no resync slot exists for a cry to ride');
});
