// src/lib/lenses/lens-consume.test.ts — contract R7 (old-client safety + the hello signal), the
// receive-side apply (R4 MAC on the way in, R6 keep-what-you-have), review-1 items 4/5/7.
// Run: npx tsx --test src/lib/lenses/lens-consume.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from '@noble/hashes/utils.js';
import { applyLensMethods, makeLensSeam, type LensSeamDeps } from './lens-consume';
import { LENS_KIND_HELLO, LENS_KIND_METHODS, LENS_HELLO_BODY, LENS_MAX_METHODS, buildLensCell, encodeLensMethodsBody, lensMethodKey, openLensPayload, unframeLensCell } from './lens-wire';
import type { LensGrantBook } from './lens-grants';
import { sealLivingBookHybrid } from '../crypto/living-book-sleeve';
import { mintHybridRecipient } from '../sync/hybrid-test-fixture';
import { parseContactUpdateWire } from '../sync/contact-update-envelope';
import type { StoredContact } from '../contacts/apply-contact-update';

const SENDER = 'a'.repeat(64);
const sPair = randomBytes(32);
const NOW = 1_800_000_000;

const contact = (over: Partial<StoredContact> = {}): StoredContact => ({
  id: 'c1',
  fingerprint: SENDER,
  name: 'Sender',
  email: '',
  public_key: 'x',
  trust_level: 'known',
  added_at: '2026-01-01T00:00:00Z',
  ...over,
});

function seamFor(r: Awaited<ReturnType<typeof mintHybridRecipient>>, opts: { store?: Partial<LensSeamDeps['store']>; book?: LensGrantBook; persisted?: StoredContact[]; savedBooks?: LensGrantBook[]; nowSeconds?: () => number }) {
  const book = opts.book ?? { v: 1 as const, grants: {} };
  const savedBooks: LensGrantBook[] = opts.savedBooks ?? [];
  const persisted: StoredContact[] = opts.persisted ?? [];
  const known = contact();
  const store: LensSeamDeps['store'] = {
    lookup: async (fp) => (fp === SENDER ? { known: {} as never, current: known } : null),
    persist: async (_id, changes) => { persisted.push(changes as StoredContact); },
    ...opts.store,
  };
  const seam = makeLensSeam({
    store,
    hybridSecrets: r.hybrid,
    ownerFingerprint: r.fingerprint,
    sPairFor: () => sPair,
    loadGrants: () => book,
    saveGrants: (b) => { savedBooks.push(b); },
    now: () => '2026-11-10T00:00:00Z',
    nowSeconds: opts.nowSeconds ?? (() => NOW),
  });
  return { seam, savedBooks, persisted, known };
}

async function sealCell(cell: Uint8Array, r: Awaited<ReturnType<typeof mintHybridRecipient>>): Promise<string> {
  return sealLivingBookHybrid(cell, r.publicKeyArmored, r.pqKemPublicKey);
}

test('R7: an OLD client (no seam) treats a lens blob as a terminal drop — no crash, no partial card', async () => {
  const r = await mintHybridRecipient();
  const cell = buildLensCell({ kind: LENS_KIND_METHODS, fpSender: SENDER, fpReceiver: r.fingerprint, seq: 1, body: encodeLensMethodsBody([{ kind: 'signal', value: '@s' }]), sPair });
  const blob = await sealCell(cell, r);
  const pkg = JSON.parse(blob);
  const { openMailboxEnvelope } = await import('../crypto/mailbox-envelope');
  const plaintext = await openMailboxEnvelope(pkg, r.hybrid.secrets, r.hybrid.myFp);
  assert.ok(plaintext);
  assert.equal(parseContactUpdateWire(new TextDecoder().decode(plaintext!)), null, 'old client: not a contact.update — dropped, never shown as a card');
});

test('R7: verify() catches a lens blob for a lens-capable client; a non-lens blob falls through', async () => {
  const r = await mintHybridRecipient();
  const { seam } = seamFor(r, {});
  const cell = buildLensCell({ kind: LENS_KIND_HELLO, fpSender: SENDER, fpReceiver: r.fingerprint, seq: 0, body: LENS_HELLO_BODY, sPair });
  const wire = await seam.verify(await sealCell(cell, r));
  assert.ok(wire instanceof Uint8Array);
  const notLens = await sealLivingBookHybrid(new TextEncoder().encode('{"envelope":{"fingerprint":"x"}}'), r.publicKeyArmored, r.pqKemPublicKey);
  assert.equal(await seam.verify(notLens), null);
});

test('R7: a verified HELLO marks the peer capable — a forged one does not', async () => {
  const r = await mintHybridRecipient();
  const { seam, savedBooks } = seamFor(r, {});
  const hello = buildLensCell({ kind: LENS_KIND_HELLO, fpSender: SENDER, fpReceiver: r.fingerprint, seq: 0, body: LENS_HELLO_BODY, sPair });
  const wire = await seam.verify(await sealCell(hello, r));
  const res = await seam.accept(wire!);
  assert.deepEqual(res, { hello: true });
  assert.equal(savedBooks[0].grants[SENDER]?.capable, true);
  const forged = buildLensCell({ kind: LENS_KIND_HELLO, fpSender: SENDER, fpReceiver: r.fingerprint, seq: 0, body: LENS_HELLO_BODY, sPair: randomBytes(32) });
  const res2 = await seam.accept((await seam.verify(await sealCell(forged, r)))!);
  assert.equal(res2, null);
});

test('item 5: a lens payload NEVER overwrites primary fields — values live only in lens_methods', async () => {
  const r = await mintHybridRecipient();
  // The SIGNED path already delivered a phone + signal handle.
  const signed = contact({
    phone: '+15550001',
    phones: ['+15550001'],
    contact_info: { handles: { signal: '@real' }, emails: ['real@x.example'] },
  });
  const savedBooks: LensGrantBook[] = [];
  const persisted: StoredContact[] = [];
  const store: LensSeamDeps['store'] = {
    lookup: async (fp) => (fp === SENDER ? { known: {} as never, current: signed } : null),
    persist: async (_id, changes) => { persisted.push(changes as StoredContact); },
  };
  const seam = makeLensSeam({
    store, hybridSecrets: r.hybrid, ownerFingerprint: r.fingerprint, sPairFor: () => sPair,
    loadGrants: () => ({ v: 1 as const, grants: {} }),
    saveGrants: (b) => { savedBooks.push(b); },
    now: () => '2026-11-10T00:00:00Z', nowSeconds: () => NOW,
  });
  // A lens payload with DIFFERENT values for the same slots.
  const cell = buildLensCell({
    kind: LENS_KIND_METHODS, fpSender: SENDER, fpReceiver: r.fingerprint, seq: NOW,
    body: encodeLensMethodsBody([
      { kind: 'phone', value: '+19990002' },
      { kind: 'signal', value: '@swapped' },
      { kind: 'email', value: 'lens@x.example' },
    ]),
    sPair,
  });
  const res = await seam.accept((await seam.verify(await sealCell(cell, r)))!);
  assert.ok(res && 'applied' in res);
  const diff = persisted[0] as Record<string, unknown>;
  // The persist diff carries NO top-level primary key — apply only ever writes contact_info.lens_methods.
  for (const k of ['phone', 'phones', 'email', 'emails', 'urls', 'handles']) {
    assert.equal(k in diff, false, `primary field ${k} must not be written`);
  }
  const next = { ...signed, ...diff } as StoredContact;
  // Primary fields: EXACTLY as the signed path left them — the fraud surface stays closed.
  assert.equal(next.phone, '+15550001');
  assert.deepEqual(next.phones, ['+15550001']);
  const ci = next.contact_info as Record<string, unknown>;
  assert.deepEqual(ci.handles, { signal: '@real' });
  assert.deepEqual(ci.emails, ['real@x.example']);
  assert.equal(next.email, '');
  // The lens values are held separately in lens_methods.
  const lm = ci.lens_methods as Record<string, { value: string }>;
  assert.equal(lm[lensMethodKey({ kind: 'phone' })].value, '+19990002');
  assert.equal(lm[lensMethodKey({ kind: 'signal' })].value, '@swapped');
  assert.equal(lm[lensMethodKey({ kind: 'email' })].value, 'lens@x.example');
});

test('methods: MAC-verified payload applies to the record + bumps the seq floor; a replay goes stale', async () => {
  const r = await mintHybridRecipient();
  const { seam, persisted, savedBooks } = seamFor(r, {});
  const cell = buildLensCell({
    kind: LENS_KIND_METHODS,
    fpSender: SENDER,
    fpReceiver: r.fingerprint,
    seq: NOW - 3600,
    body: encodeLensMethodsBody([{ kind: 'signal', value: '@s' }, { kind: 'email', value: 's@x.example' }]),
    sPair,
  });
  const res = await seam.accept((await seam.verify(await sealCell(cell, r)))!);
  assert.ok(res && 'applied' in res);
  const ci = persisted[0].contact_info as Record<string, unknown>;
  const lm = ci.lens_methods as Record<string, { kind: string; value: string }>;
  assert.equal(lm[lensMethodKey({ kind: 'signal' })].value, '@s');
  assert.equal(savedBooks.at(-1)!.inSeq![SENDER], NOW - 3600);
  const { seam: seam2 } = seamFor(r, { book: { v: 1, grants: {}, inSeq: { [SENDER]: NOW - 3600 } } });
  const res2 = await seam2.accept((await seam2.verify(await sealCell(cell, r)))!);
  assert.deepEqual(res2, { stale: true });
});

test('item 4: a far-future seq is REFUSED — and a wiped sender book still resumes above the floor', async () => {
  const r = await mintHybridRecipient();
  const { seam } = seamFor(r, {});
  const farFuture = buildLensCell({
    kind: LENS_KIND_METHODS, fpSender: SENDER, fpReceiver: r.fingerprint,
    seq: NOW + 86400 + 1, // more than a day ahead of the receiver's clock
    body: encodeLensMethodsBody([{ kind: 'signal', value: '@poison' }]),
    sPair,
  });
  assert.deepEqual(await seam.accept((await seam.verify(await sealCell(farFuture, r)))!), { stale: true });
  // The paired send-side case: sender's book was wiped after N sends — the seq anchors to wall
  // time, which sits ABOVE the receiver's floor, so the update still lands.
  const { seam: seam2, persisted } = seamFor(r, { book: { v: 1, grants: {}, inSeq: { [SENDER]: 7 } } });
  const wipedSeq = buildLensCell({
    kind: LENS_KIND_METHODS, fpSender: SENDER, fpReceiver: r.fingerprint,
    seq: NOW, // what nextLensSeq stamps on a wiped book at NOW — far above 7
    body: encodeLensMethodsBody([{ kind: 'email', value: 'w@x' }]),
    sPair,
  });
  const res = await seam2.accept((await seam2.verify(await sealCell(wipedSeq, r)))!);
  assert.ok(res && 'applied' in res);
  assert.equal(persisted.length, 1);
});

test('item 7: a payload that would grow lens_methods past the cap is refused WHOLE — record unchanged', async () => {
  const r = await mintHybridRecipient();
  // Seed the record near the cap, then a payload that pushes past it.
  const seed: Record<string, { kind: string; value: string; label?: string }> = {};
  for (let i = 0; i < LENS_MAX_METHODS - 1; i++) seed[`k${i}\x00`] = { kind: 'custom', value: `v${i}`, label: `k${i}` };
  const full = contact({ contact_info: { lens_methods: seed } });
  const persisted: StoredContact[] = [];
  const savedBooks: LensGrantBook[] = [];
  const store: LensSeamDeps['store'] = {
    lookup: async (fp) => (fp === SENDER ? { known: {} as never, current: full } : null),
    persist: async (_id, changes) => { persisted.push(changes as StoredContact); },
  };
  const seam = makeLensSeam({
    store, hybridSecrets: r.hybrid, ownerFingerprint: r.fingerprint, sPairFor: () => sPair,
    loadGrants: () => ({ v: 1 as const, grants: {} }),
    saveGrants: (b) => { savedBooks.push(b); },
    now: () => '2026-11-10T00:00:00Z', nowSeconds: () => NOW,
  });
  // First payload: 2 NEW labels would take the record to 33 — over the cap — refused whole.
  const over = buildLensCell({
    kind: LENS_KIND_METHODS, fpSender: SENDER, fpReceiver: r.fingerprint, seq: NOW,
    body: encodeLensMethodsBody([
      { kind: 'custom', value: 'x', label: 'new1' },
      { kind: 'custom', value: 'y', label: 'new2' },
    ]),
    sPair,
  });
  const res = await seam.accept((await seam.verify(await sealCell(over, r)))!);
  assert.deepEqual(res, { refused: 'method-cap' });
  assert.equal(persisted.length, 0, 'record unchanged: nothing was applied');
  assert.equal(savedBooks.at(-1)!.inSeq![SENDER], NOW, 'the seq was still floored — the refusal is terminal, not retried');
});

test('R6 keep-what-you-have: a payload without a method keeps the earlier one (upsert, never delete)', () => {
  const c = contact({ contact_info: {} });
  const first = applyLensMethods(c, [{ kind: 'signal', value: '@old' }, { kind: 'email', value: 'a@x' }], '2026-11-10T00:00:00Z')!;
  const second = applyLensMethods(first, [{ kind: 'signal', value: '@new' }], '2026-11-10T01:00:00Z')!;
  const lm = (second.contact_info as Record<string, unknown>).lens_methods as Record<string, { value: string }>;
  assert.equal(lm[lensMethodKey({ kind: 'signal' })].value, '@new'); // update replaces its key
  assert.equal(lm[lensMethodKey({ kind: 'email' })].value, 'a@x'); // an absent key persists
});

test('custody: a stranger or blocked sender is dropped before the MAC is even checked', async () => {
  const r = await mintHybridRecipient();
  const { seam } = seamFor(r, {});
  const cell = buildLensCell({ kind: LENS_KIND_METHODS, fpSender: 'e'.repeat(64), fpReceiver: r.fingerprint, seq: 1, body: encodeLensMethodsBody([{ kind: 'signal', value: '@x' }]), sPair });
  const wire = await seam.verify(await sealCell(cell, r));
  assert.equal(await seam.accept(wire!), null);
});

test('round-trip: the payload a sender built opens on the receiver side (directional)', () => {
  const receiver = 'd'.repeat(64);
  const cell = buildLensCell({ kind: LENS_KIND_METHODS, fpSender: SENDER, fpReceiver: receiver, seq: 9, body: encodeLensMethodsBody([{ kind: 'site', value: 'https://x' }]), sPair });
  const parsed = unframeLensCell(cell);
  assert.ok(parsed);
  const opened = openLensPayload(cell.slice(6, 6 + new DataView(cell.buffer).getUint32(2, false)), { sPair, fpSender: parsed!.fpSender, fpReceiver: receiver });
  assert.equal(opened.ok, true);
});
