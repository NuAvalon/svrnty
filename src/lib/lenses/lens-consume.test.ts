// src/lib/lenses/lens-consume.test.ts — contract R7 (old-client safety + the hello signal), the
// receive-side apply (R4 MAC on the way in, R6 keep-what-you-have), review-1 items 4/5/7.
// Run: npx tsx --test src/lib/lenses/lens-consume.test.ts
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { applyLensMethods, makeLensSeam, type LensAcceptResult, type LensSeamDeps } from './lens-consume';
import { LENS_KIND_HELLO, LENS_KIND_METHODS, LENS_HELLO_BODY, LENS_MAX_METHODS, buildLensCell, deriveLensMacKey, encodeLensMethodsBody, lensMethodKey, openLensPayload, unframeLensCell } from './lens-wire';
import type { LensGrantBook } from './lens-grants';
import { sealLivingBookHybrid } from '../crypto/living-book-sleeve';
import { mintHybridRecipient } from '../sync/hybrid-test-fixture';
import { parseContactUpdateWire } from '../sync/contact-update-envelope';
import type { StoredContact } from '../contacts/apply-contact-update';

const SENDER = 'a'.repeat(64);
const sPair = randomBytes(32);
const MAC_KAT = 'ca236474439d205717c154f5c7af52610093cc95ac95a96c9ff68f839029ca2c'; // fixed sPair=0x07*32, sender='a'*64, receiver='b'*64
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
  assert.deepEqual(res, { refused: 'method-cap', fingerprint: SENDER });
  assert.equal(persisted.length, 1, 'the R8a stopped state is written — the refusal is VISIBLE, never silent');
  assert.equal((persisted[0].contact_info as Record<string, unknown>).lens_stopped, true);
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

test('R8a: a payload with two values in ONE slot is refused whole — own reason, floor advances', async () => {
  const r = await mintHybridRecipient();
  const { seam, persisted, savedBooks } = seamFor(r, {});
  const dup = buildLensCell({
    kind: LENS_KIND_METHODS, fpSender: SENDER, fpReceiver: r.fingerprint, seq: NOW,
    body: encodeLensMethodsBody([
      { kind: 'phone', value: '+111' },
      { kind: 'phone', value: '+222' }, // same kind AND slot — the codec bounds pass, the slot rule refuses
    ]),
    sPair,
  });
  const res = await seam.accept((await seam.verify(await sealCell(dup, r)))!);
  assert.deepEqual(res, { refused: 'shared-slot', fingerprint: SENDER });
  assert.equal(persisted.length, 0, 'nothing applied — the whole payload is refused');
  assert.equal(savedBooks.at(-1)!.inSeq![SENDER], NOW, 'terminal refusal: the seq floor still advances');
});

test('R6a: lens value A then B for one custom key shows CHANGED with "Was: A" (no signed home)', () => {
  const c = contact({ contact_info: {} });
  const first = applyLensMethods(c, [{ kind: 'custom', value: 'A', label: 'pgp' }], '2026-11-10T00:00:00Z')!;
  const second = applyLensMethods(first, [{ kind: 'custom', value: 'B', label: 'pgp' }], '2026-11-10T01:00:00Z')!;
  const lm = (second.contact_info as Record<string, unknown>).lens_methods as Record<string, { value: string; was?: string }>;
  const key = lensMethodKey({ kind: 'custom', label: 'pgp' });
  assert.equal(lm[key].value, 'B');
  assert.equal(lm[key].was, 'A', 'the previous LENS value is kept for "Was:" — not just the signed value');
});

test('R6b relabel-swap: held Home dropped + Mobile added ⇒ kind-named changed, Was = dropped value', () => {
  const c = contact({ contact_info: {} });
  const first = applyLensMethods(c, [{ kind: 'phone', value: 'A', label: 'Home' }], '2026-11-10T00:00:00Z')!;
  const second = applyLensMethods(first, [{ kind: 'phone', value: 'B', label: 'Mobile' }], '2026-11-10T01:00:00Z')!;
  const lm = (second.contact_info as Record<string, unknown>).lens_methods as Record<string, { value: string; was?: string; wasKind?: boolean }>;
  const mobile = lm[lensMethodKey({ kind: 'phone', label: 'Mobile' })];
  assert.equal(mobile.was, 'A', '"Was:" shows the DROPPED held value');
  assert.equal(mobile.wasKind, true, 'the line names the KIND — the label changed');
  // Home itself stays held (never dropped) — the change mark lives on the added value.
  assert.equal(lm[lensMethodKey({ kind: 'phone', label: 'Home' })].value, 'A');
  // And a payload that KEEPS every held value of the kind marks nothing changed.
  const third = applyLensMethods(first, [
    { kind: 'phone', value: 'A', label: 'Home' },
    { kind: 'phone', value: 'B', label: 'Mobile' },
  ], '2026-11-10T02:00:00Z')!;
  const lm3 = (third.contact_info as Record<string, unknown>).lens_methods as Record<string, { was?: string }>;
  assert.equal(lm3[lensMethodKey({ kind: 'phone', label: 'Mobile' })].was, undefined, 'every held value still held ⇒ new slot shows as given');
});

test('F1: a KNOWN but BLOCKED sender is dropped — accept returns null and nothing is written', async () => {
  const r = await mintHybridRecipient();
  const blocked = contact({ blocked: true } as Partial<StoredContact>);
  const persisted: StoredContact[] = [];
  const savedBooks: LensGrantBook[] = [];
  const store: LensSeamDeps['store'] = {
    lookup: async (fp) => (fp === SENDER ? { known: {} as never, current: blocked } : null),
    persist: async (_id, changes) => { persisted.push(changes as StoredContact); },
  };
  const seam = makeLensSeam({
    store, hybridSecrets: r.hybrid, ownerFingerprint: r.fingerprint, sPairFor: () => sPair,
    loadGrants: () => ({ v: 1 as const, grants: {} }),
    saveGrants: (b) => { savedBooks.push(b); },
    now: () => '2026-11-10T00:00:00Z', nowSeconds: () => NOW,
  });
  const cell = buildLensCell({ kind: LENS_KIND_METHODS, fpSender: SENDER, fpReceiver: r.fingerprint, seq: NOW, body: encodeLensMethodsBody([{ kind: 'signal', value: '@x' }]), sPair });
  assert.equal(await seam.accept((await seam.verify(await sealCell(cell, r)))!), null, 'blocked ⇒ silent drop before the MAC is even checked');
  assert.equal(persisted.length, 0);
  assert.equal(savedBooks.length, 0, 'no grant row written for a blocked sender');
  // Mutant-guard: the admitContact check is the only thing between a blocked sender and a write.
  const dir = fileURLToPath(new URL('.', import.meta.url));
  const src = readFileSync(`${dir}/lens-consume.ts`, 'utf8');
  assert.match(src, /admitContact\(contact\.current\)/, 'removing the admit check must go red');
});

test('F2: the pair-MAC key is a fixed-point (known-answer) — another salt does not pass', () => {
  const fixedSPair = new Uint8Array(32).fill(7);
  const key = deriveLensMacKey({ sPair: fixedSPair, fpSender: SENDER, fpReceiver: 'b'.repeat(64) });
  assert.equal(bytesToHex(key), MAC_KAT, 'fixed pair secret + fingerprints must give the fixed key');
});

test('F3: self-send at open — a payload whose sender IS the receiver refuses "self"', () => {
  const fp = 'c'.repeat(64);
  // Hand-build a payload the BUILDER would refuse (sender == receiver): header || kind || fp ||
  // seq || bodyLen || body || tag. The 'self' check precedes the MAC compare, so a zero tag is fine.
  const body = encodeLensMethodsBody([{ kind: 'signal', value: '@x' }]);
  const raw = new Uint8Array(2 + 1 + 32 + 8 + 4 + body.length + 32);
  raw.set([0x4c, 0x01, LENS_KIND_METHODS], 0);
  raw.set(hexToBytes(fp), 3);
  new DataView(raw.buffer).setBigUint64(35, BigInt(1), false);
  new DataView(raw.buffer).setUint32(43, body.length, false);
  raw.set(body, 47);
  const opened = openLensPayload(raw, { sPair, fpSender: fp, fpReceiver: fp });
  assert.deepEqual(opened, { ok: false, reason: 'self' });
});

test('R3-E2: a payload that LANDS clears the stopped state — updates resume', () => {
  const stopped = contact({ contact_info: { lens_stopped: true, lens_methods: { [lensMethodKey({ kind: 'email' })]: { kind: 'email', value: 'a@x' } } } });
  const next = applyLensMethods(stopped, [{ kind: 'email', value: 'b@y' }], '2026-11-10T00:00:00Z')!;
  const ci = next.contact_info as Record<string, unknown>;
  assert.equal(ci.lens_stopped, undefined, 'a landing payload clears the R8a stopped state');
  assert.equal((ci.lens_methods as Record<string, { value: string }>)[lensMethodKey({ kind: 'email' })].value, 'b@y');
});

test('R3-E3: re-sending the SAME value keeps the earlier changed mark and its "Was:"', () => {
  const c = contact({ contact_info: {} });
  const first = applyLensMethods(c, [{ kind: 'custom', value: 'A', label: 'pgp' }], '2026-11-10T00:00:00Z')!;
  const second = applyLensMethods(first, [{ kind: 'custom', value: 'B', label: 'pgp' }], '2026-11-10T01:00:00Z')!;
  const third = applyLensMethods(second, [{ kind: 'custom', value: 'B', label: 'pgp' }], '2026-11-10T02:00:00Z')!;
  const lm = (third.contact_info as Record<string, unknown>).lens_methods as Record<string, { value: string; was?: string }>;
  const key = lensMethodKey({ kind: 'custom', label: 'pgp' });
  assert.equal(lm[key].value, 'B');
  assert.equal(lm[key].was, 'A', 'the changed mark stands across a re-send of the new value');
});

// ---------- lenses v1.9 review-4: R2a (unreadable book = read-only) + R2b (held bounds) ----------

import { LENS_HELD_MAX_SENDERS } from './lens-consume';

const S2 = 'd'.repeat(64);

/** A seam whose grant-book reads and contact lookup the test controls (heal = flip the loader).
 *  persist writes back into the contact map and onSave mirrors a real book store — a drain's
 *  floor save is visible to the next read, as in production. */
function seamHarness(r: Awaited<ReturnType<typeof mintHybridRecipient>>, opts: {
  contacts?: Map<string, StoredContact>;
  loadGrants: () => LensGrantBook;
  onSave?: (b: LensGrantBook) => void;
}) {
  const savedBooks: LensGrantBook[] = [];
  const persisted: Array<{ id: string; changes: StoredContact }> = [];
  const contacts = opts.contacts ?? new Map([[SENDER, contact()]]);
  const store: LensSeamDeps['store'] = {
    lookup: async (fp) => {
      const c = contacts.get(fp);
      return c ? { known: {} as never, current: c } : null;
    },
    persist: async (id, changes) => {
      persisted.push({ id, changes: changes as StoredContact });
      const c = contacts.get(id);
      if (c) contacts.set(id, { ...c, ...(changes as StoredContact) });
    },
  };
  const seam = makeLensSeam({
    store, hybridSecrets: r.hybrid, ownerFingerprint: r.fingerprint, sPairFor: () => sPair,
    loadGrants: opts.loadGrants,
    saveGrants: (b) => { savedBooks.push(b); opts.onSave?.(b); },
    now: () => '2026-11-10T00:00:00Z', nowSeconds: () => NOW,
  });
  return { seam, savedBooks, persisted };
}

type Recip = Awaited<ReturnType<typeof mintHybridRecipient>>;
const methodsWire = (r: Recip, fp: string, seq: number, value: string) =>
  buildLensCell({ kind: LENS_KIND_METHODS, fpSender: fp, fpReceiver: r.fingerprint, seq, body: encodeLensMethodsBody([{ kind: 'signal', value }]), sPair });
const helloWire = (r: Recip, fp: string) =>
  buildLensCell({ kind: LENS_KIND_HELLO, fpSender: fp, fpReceiver: r.fingerprint, seq: 0, body: LENS_HELLO_BODY, sPair });
const take = async (seam: { verify: (b: string) => Promise<Uint8Array | null>; accept: (w: Uint8Array) => Promise<LensAcceptResult> }, cell: Uint8Array, r: Recip): Promise<LensAcceptResult> =>
  seam.accept((await seam.verify(await sealCell(cell, r)))!);

test('R2a: with an unreadable book a verified payload is HELD — no write, no apply, no floor save', async () => {
  const r = await mintHybridRecipient();
  const { seam, savedBooks, persisted } = seamHarness(r, { loadGrants: () => ({ v: 1, grants: {}, inSeq: {}, unreadable: true }) });
  const res = await take(seam, methodsWire(r, SENDER, NOW, '@x'), r);
  assert.deepEqual(res, { held: true });
  assert.equal(savedBooks.length, 0, 'nothing writes the book while it is unreadable — not even the replay floor');
  assert.equal(persisted.length, 0, 'the contact record is untouched');
});

test('R2a: a received HELLO while unreadable is held too — no capability mark saved over the book', async () => {
  const r = await mintHybridRecipient();
  const { seam, savedBooks } = seamHarness(r, { loadGrants: () => ({ v: 1, grants: {}, inSeq: {}, unreadable: true }) });
  assert.deepEqual(await take(seam, helloWire(r, SENDER), r), { held: true });
  assert.equal(savedBooks.length, 0, 'the markPeerCapable write must not land on the unreadable stand-in');
});

test('R2a contract case: one transient read error — held payloads retry on the next good read, replay judged vs the REAL floor', async () => {
  const r = await mintHybridRecipient();
  // The REAL stored book: S2's floor is 50 (a replayed seq 10 must never read as fresh against it).
  let stored: LensGrantBook = { v: 1, grants: {}, inSeq: { [S2]: 50 } };
  let bad = true;
  const contacts = new Map([[SENDER, contact()], [S2, contact({ id: 'c2', fingerprint: S2, name: 'Two' })]]);
  const { seam, savedBooks, persisted } = seamHarness(r, {
    contacts,
    loadGrants: () => (bad ? { v: 1, grants: {}, inSeq: {}, unreadable: true } : stored),
    onSave: (b) => { stored = b; },
  });
  // Unreadable window: a replayed payload (seq 10 < real floor 50) and a fresh one (seq 60).
  assert.deepEqual(await take(seam, methodsWire(r, S2, 10, '@old'), r), { held: true });
  assert.deepEqual(await take(seam, methodsWire(r, SENDER, 60, '@new'), r), { held: true });
  assert.equal(savedBooks.length, 0, 'byte-identical: nothing was saved while the book was unreadable');
  assert.equal(persisted.length, 0);
  // Heal + next good read (a hello from S2 triggers it): the held payloads drain first —
  // seq 60 applies, the seq-10 replay is judged STALE against the real floor 50, never saved at 10.
  bad = false;
  const poke = helloWire(r, S2);
  assert.deepEqual(await take(seam, poke, r), { hello: true });
  assert.equal(persisted.length, 1, 'the held fresh payload applied after the good read');
  const lm = (persisted[0].changes.contact_info as Record<string, unknown>).lens_methods as Record<string, { value: string }>;
  assert.equal(lm[lensMethodKey({ kind: 'signal' })].value, '@new');
  const final = savedBooks.at(-1)!;
  assert.equal(final.inSeq![SENDER], 60, 'the held payload floored at its real seq');
  assert.equal(final.inSeq![S2], 50, 'the replayed seq never overwrote the real floor');
  assert.equal(final.grants[S2]?.capable, true, 'the triggering hello marked S2 capable');
});

test('R2a: a held HELLO drains before the same sender’s newer wire — floor order is kept', async () => {
  const r = await mintHybridRecipient();
  let stored: LensGrantBook = { v: 1, grants: {}, inSeq: {} };
  let bad = true;
  const { seam, savedBooks, persisted } = seamHarness(r, {
    loadGrants: () => (bad ? { v: 1, grants: {}, inSeq: {}, unreadable: true } : stored),
    onSave: (b) => { stored = b; },
  });
  assert.deepEqual(await take(seam, helloWire(r, SENDER), r), { held: true });
  bad = false;
  // A newer wire from the same sender: its seq must floor AFTER the held hello applies.
  const res = await take(seam, methodsWire(r, SENDER, NOW, '@x'), r);
  assert.ok(res && 'applied' in res);
  const final = savedBooks.at(-1)!;
  assert.equal(final.grants[SENDER]?.capable, true, 'the held hello applied during the drain — the signal was not lost');
  assert.equal(final.inSeq![SENDER], NOW);
  assert.equal(persisted.length, 1);
});

test('R2b(b): one held payload per contact — the HIGHEST seq is kept', async () => {
  const r = await mintHybridRecipient();
  let stored: LensGrantBook = { v: 1, grants: {}, inSeq: {} };
  let bad = true;
  const contacts = new Map([[SENDER, contact()], [S2, contact({ id: 'c2', fingerprint: S2, name: 'Two' })]]);
  const { seam, savedBooks, persisted } = seamHarness(r, {
    contacts,
    loadGrants: () => (bad ? { v: 1, grants: {}, inSeq: {}, unreadable: true } : stored),
    onSave: (b) => { stored = b; },
  });
  // Unreadable window: seq 10, then a LOWER seq 5, then seq 15 — only seq 15 may survive the hold.
  assert.deepEqual(await take(seam, methodsWire(r, SENDER, 10, 'A'), r), { held: true });
  assert.deepEqual(await take(seam, methodsWire(r, SENDER, 5, 'B'), r), { held: true });
  assert.deepEqual(await take(seam, methodsWire(r, SENDER, 15, 'C'), r), { held: true });
  bad = false;
  await take(seam, helloWire(r, S2), r); // any admitted wire triggers the drain on the good read
  assert.equal(persisted.length, 1, 'exactly one payload applied for the contact — not three');
  const lm = (persisted[0].changes.contact_info as Record<string, unknown>).lens_methods as Record<string, { value: string }>;
  assert.equal(lm[lensMethodKey({ kind: 'signal' })].value, 'C', 'the highest seq wins the single held slot');
  assert.equal(savedBooks.at(-1)!.inSeq![SENDER], 15);
});

test('R2b(b): the hold is bounded ACROSS contacts — a sender cannot grow it past the cap', async () => {
  const r = await mintHybridRecipient();
  let bad = true;
  const contacts = new Map<string, StoredContact>();
  const fps: string[] = [];
  for (let i = 0; i < LENS_HELD_MAX_SENDERS + 1; i++) {
    const fp = i.toString(16).padStart(64, '0');
    fps.push(fp);
    contacts.set(fp, contact({ id: `c${i}`, fingerprint: fp, name: `S${i}` }));
  }
  const { seam, persisted } = seamHarness(r, {
    contacts,
    loadGrants: () => (bad ? { v: 1, grants: {}, inSeq: {}, unreadable: true } : { v: 1, grants: {}, inSeq: {} }),
  });
  for (const fp of fps) {
    assert.deepEqual(await take(seam, methodsWire(r, fp, 1, `@${fps.indexOf(fp)}`), r), { held: true });
  }
  bad = false;
  await take(seam, methodsWire(r, fps[0], 2, '@poke'), r); // trigger the drain
  const appliedIds = new Set(persisted.map((p) => p.id));
  const overflow = `c${LENS_HELD_MAX_SENDERS}`; // the (cap+1)-th sender — dropped at the bound
  assert.equal(appliedIds.has(overflow), false, 'the hold never grows past LENS_HELD_MAX_SENDERS');
  assert.equal(appliedIds.size >= LENS_HELD_MAX_SENDERS, true, 'the bounded hold itself still drains');
});

test('R2a: a drain that fails mid-apply re-holds the payload — nothing is lost, the next good read retries', async () => {
  const r = await mintHybridRecipient();
  let stored: LensGrantBook = { v: 1, grants: {}, inSeq: {} };
  let bad = true;
  let failSave = true;
  const { seam, savedBooks, persisted } = seamHarness(r, {
    loadGrants: () => (bad ? { v: 1, grants: {}, inSeq: {}, unreadable: true } : stored),
    onSave: (b) => { if (failSave) throw new Error('sealed store I/O'); stored = b; },
  });
  assert.deepEqual(await take(seam, methodsWire(r, SENDER, NOW, '@x'), r), { held: true });
  bad = false;
  // First good read: the drain reaches saveGrants and the store throws — retryable.
  await assert.rejects(take(seam, helloWire(r, SENDER), r));
  assert.equal(persisted.length >= 1, true, 'the apply may have persisted before the floor save threw');
  // The envelope is left for retry by the consume loop; the NEXT take drains the re-held wire.
  failSave = false;
  assert.deepEqual(await take(seam, helloWire(r, SENDER), r), { hello: true });
  const final = savedBooks.at(-1)!;
  assert.equal(final.inSeq![SENDER], NOW, 'the held wire applied on the retry — judged against the real floor');
  assert.equal(final.grants[SENDER]?.capable, true);
});

test('R2b(c): a contact blocked AFTER the hold discards the held payload at apply time', async () => {
  const r = await mintHybridRecipient();
  let bad = true;
  const contacts = new Map([[SENDER, contact()], [S2, contact({ id: 'c2', fingerprint: S2, name: 'Two' })]]);
  const { seam, persisted } = seamHarness(r, {
    contacts,
    loadGrants: () => (bad ? { v: 1, grants: {}, inSeq: {}, unreadable: true } : { v: 1, grants: {}, inSeq: {} }),
  });
  assert.deepEqual(await take(seam, methodsWire(r, SENDER, NOW, '@x'), r), { held: true });
  contacts.set(SENDER, contact({ blocked: true } as Partial<StoredContact>)); // blocked after the hold
  bad = false;
  await take(seam, methodsWire(r, S2, NOW, '@ok'), r); // an admitted wire triggers the drain
  assert.equal(persisted.length, 1, 'only the admitted sender applied');
  assert.equal(persisted[0].id, 'c2', 'the blocked contact’s held payload was discarded, not applied');
});
