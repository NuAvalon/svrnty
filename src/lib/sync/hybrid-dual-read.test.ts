// src/lib/sync/hybrid-dual-read.test.ts
// Run: npx tsx --test src/lib/sync/hybrid-dual-read.test.ts
//
// Proves the L7 consume dual-read (Apollo's seam) holds the two load-bearing invariants with the crypto
// INJECTED (stub openEnvelope): NO-SILENT-LOSS (every hybrid failure mode falls through to the classical
// fallback) and NO-CROSS-SWALLOW (a hybrid package whose inner wire is another type returns null, so the
// consume demux falls through — the envelope shape is not the discriminator, the inner wire-type is).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { asMailboxEnvelopePackage, makeHybridOpener, dualReadOpener } from './hybrid-dual-read';

type FakeWire = { type: 'fake-note'; body: string };
const parseFakeNote = (s: string): FakeWire | null => {
  try {
    const o = JSON.parse(s);
    return o?.type === 'fake-note' && typeof o.body === 'string' ? (o as FakeWire) : null;
  } catch {
    return null;
  }
};

function pkg(): string {
  return JSON.stringify({ v: 1, alg: 'x25519-mlkem1024-aesgcm', mailbox_fp: 'ff'.repeat(32), epk: 'ZQ==', kem_ct: 'ZQ==', nonce: 'ZQ==', ct: 'ZQ==' });
}
const ARMORED = '-----BEGIN PGP MESSAGE-----\nwcBMA...\n-----END PGP MESSAGE-----';
const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));

// ── shape discriminator ──
test('asMailboxEnvelopePackage: a hybrid package parses; armored PGP + non-JSON + missing fields → null', () => {
  assert.ok(asMailboxEnvelopePackage(pkg()));
  assert.equal(asMailboxEnvelopePackage(ARMORED), null, 'armored PGP is NOT a package → classical');
  assert.equal(asMailboxEnvelopePackage('not json at all'), null);
  assert.equal(asMailboxEnvelopePackage(JSON.stringify({ v: 1, epk: 'x' })), null, 'missing kem_ct/nonce/ct → null');
  assert.equal(asMailboxEnvelopePackage(JSON.stringify({ v: 2, mailbox_fp: 'a', epk: 'a', kem_ct: 'a', nonce: 'a', ct: 'a' })), null, 'wrong version → null');
});

// ── hybrid opener: happy path + the failure modes that MUST fall through ──
test('makeHybridOpener: package + right-type inner → wire', async () => {
  const open = makeHybridOpener<FakeWire>(async () => enc({ type: 'fake-note', body: 'hi' }), parseFakeNote);
  const out = await open(pkg());
  assert.deepEqual(out, { type: 'fake-note', body: 'hi' });
});

test('makeHybridOpener: package but inner is ANOTHER type → null (NO-CROSS-SWALLOW)', async () => {
  const open = makeHybridOpener<FakeWire>(async () => enc({ type: 'fake-affirm', trusts: true }), parseFakeNote);
  assert.equal(await open(pkg()), null, 'a hybrid package carrying a non-note inner must NOT be eaten by the note opener');
});

test('makeHybridOpener: non-package blob (armored PGP) → null (→ classical fallback)', async () => {
  let opened = false;
  const open = makeHybridOpener<FakeWire>(async () => { opened = true; return enc({ type: 'fake-note', body: 'x' }); }, parseFakeNote);
  assert.equal(await open(ARMORED), null);
  assert.equal(opened, false, 'openEnvelope not even called for a non-package blob');
});

test('makeHybridOpener: wrong-key open → null; throwing open → null (both fall through, no strand)', async () => {
  const openNull = makeHybridOpener<FakeWire>(async () => null, parseFakeNote);
  assert.equal(await openNull(pkg()), null, 'openEnvelope null (wrong keys) → null');
  const openThrow = makeHybridOpener<FakeWire>(async () => { throw new Error('corrupt'); }, parseFakeNote);
  assert.equal(await openThrow(pkg()), null, 'a throwing open is swallowed → null (classical fallback still runs)');
});

// ── dual-read: hybrid-first, classical-fallback, no silent-loss ──
test('dualReadOpener: hybrid hit → classical NOT called', async () => {
  let classicalCalls = 0;
  const dual = dualReadOpener<FakeWire>(async () => ({ type: 'fake-note', body: 'hybrid' }), async () => { classicalCalls++; return { type: 'fake-note', body: 'classical' }; });
  assert.deepEqual(await dual('blob'), { type: 'fake-note', body: 'hybrid' });
  assert.equal(classicalCalls, 0);
});

test('dualReadOpener: hybrid null → falls back to classical (in-flight OpenPGP blob still opens)', async () => {
  const dual = dualReadOpener<FakeWire>(async () => null, async () => ({ type: 'fake-note', body: 'classical' }));
  assert.deepEqual(await dual(ARMORED), { type: 'fake-note', body: 'classical' });
});

test('dualReadOpener: hybrid THROWS → still falls back to classical (NO SILENT-LOSS)', async () => {
  const dual = dualReadOpener<FakeWire>(async () => { throw new Error('hybrid parse blew up'); }, async () => ({ type: 'fake-note', body: 'classical' }));
  assert.deepEqual(await dual('blob'), { type: 'fake-note', body: 'classical' }, 'a hybrid failure must never strand an in-flight classical blob');
});

test('dualReadOpener: both null → null (demux falls through to next type — no-cross-swallow)', async () => {
  const dual = dualReadOpener<FakeWire>(async () => null, async () => null);
  assert.equal(await dual('blob'), null);
});

// ── end-to-end composition: a real-shaped hybrid note round-trips through makeHybridOpener+dualRead ──
test('composition: hybrid note → dualRead(makeHybridOpener, classical) opens it; classical note falls back', async () => {
  const hybridNote = makeHybridOpener<FakeWire>(async () => enc({ type: 'fake-note', body: 'over hybrid' }), parseFakeNote);
  const classicalNote = async (blob: string): Promise<FakeWire | null> => (blob === ARMORED ? { type: 'fake-note', body: 'over classical' } : null);
  const verify = dualReadOpener(hybridNote, classicalNote);
  assert.deepEqual(await verify(pkg()), { type: 'fake-note', body: 'over hybrid' }, 'hybrid path');
  assert.deepEqual(await verify(ARMORED), { type: 'fake-note', body: 'over classical' }, 'classical in-flight path');
});
