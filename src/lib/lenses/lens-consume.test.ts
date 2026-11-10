// src/lib/lenses/lens-consume.test.ts — contract R7 (old-client safety + the hello signal) and the
// receive-side apply (R4 MAC on the way in, R6 keep-what-you-have).
// Run: npx tsx --test src/lib/lenses/lens-consume.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from '@noble/hashes/utils.js';
import { applyLensMethods, makeLensSeam, type LensSeamDeps } from './lens-consume';
import { LENS_KIND_HELLO, LENS_KIND_METHODS, LENS_HELLO_BODY, buildLensCell, encodeLensMethodsBody, openLensPayload, unframeLensCell } from './lens-wire';
import type { LensGrantBook } from './lens-grants';
import { sealLivingBookHybrid } from '../crypto/living-book-sleeve';
import { mintHybridRecipient } from '../sync/hybrid-test-fixture';
import { parseContactUpdateWire } from '../sync/contact-update-envelope';
import type { StoredContact } from '../contacts/apply-contact-update';

const SENDER = 'a'.repeat(64);
const sPair = randomBytes(32);

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

function seamFor(r: Awaited<ReturnType<typeof mintHybridRecipient>>, opts: { store?: Partial<LensSeamDeps['store']>; book?: LensGrantBook; persisted?: StoredContact[]; savedBooks?: LensGrantBook[] }) {
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
  // The old path: dual-read opens the blob fine — but the plaintext is a 2048B binary cell, not JSON.
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
  // A non-lens sealed payload → null (falls through to the contact-update path).
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
  // Forged (wrong pair secret) → dropped, nothing recorded.
  const forged = buildLensCell({ kind: LENS_KIND_HELLO, fpSender: SENDER, fpReceiver: r.fingerprint, seq: 0, body: LENS_HELLO_BODY, sPair: randomBytes(32) });
  const res2 = await seam.accept((await seam.verify(await sealCell(forged, r)))!);
  assert.equal(res2, null);
});

test('methods: MAC-verified payload applies to the contact record + bumps the seq floor; a replay goes stale', async () => {
  const r = await mintHybridRecipient();
  const { seam, persisted, savedBooks } = seamFor(r, {});
  const cell = buildLensCell({
    kind: LENS_KIND_METHODS,
    fpSender: SENDER,
    fpReceiver: r.fingerprint,
    seq: 3,
    body: encodeLensMethodsBody([{ kind: 'signal', value: '@s' }, { kind: 'email', value: 's@x.example' }]),
    sPair,
  });
  const res = await seam.accept((await seam.verify(await sealCell(cell, r)))!);
  assert.ok(res && 'applied' in res);
  const ci = persisted[0].contact_info as Record<string, unknown>;
  const lm = ci.lens_methods as Record<string, { kind: string; value: string }>;
  assert.equal(lm['signal '].value, '@s');
  assert.equal((ci.handles as Record<string, string>).signal, '@s');
  assert.equal(persisted[0].email, 's@x.example');
  assert.equal(savedBooks.at(-1)!.inSeq![SENDER], 3);
  // Replay seq 3 → stale (floor holds): a second seam whose grants book already saw seq 3.
  const { seam: seam2 } = seamFor(r, { book: { v: 1, grants: {}, inSeq: { [SENDER]: 3 } } });
  const res2 = await seam2.accept((await seam2.verify(await sealCell(cell, r)))!);
  assert.deepEqual(res2, { stale: true });
});

test('R6 keep-what-you-have: a payload without a method keeps the earlier one (upsert, never delete)', () => {
  const c = contact({ contact_info: {} });
  const first = applyLensMethods(c, [{ kind: 'signal', value: '@old' }, { kind: 'email', value: 'a@x' }], '2026-11-10T00:00:00Z');
  const second = applyLensMethods(first, [{ kind: 'signal', value: '@new' }], '2026-11-10T01:00:00Z');
  const lm = (second.contact_info as Record<string, unknown>).lens_methods as Record<string, { value: string }>;
  assert.equal(lm['signal '].value, '@new'); // update replaces its key
  assert.equal(lm['email '].value, 'a@x'); // an absent key persists — they keep what they have
});

test('custody: a stranger or blocked sender is dropped before the MAC is even checked', async () => {
  const r = await mintHybridRecipient();
  const { seam } = seamFor(r, {});
  const cell = buildLensCell({ kind: LENS_KIND_METHODS, fpSender: 'e'.repeat(64), fpReceiver: r.fingerprint, seq: 1, body: encodeLensMethodsBody([{ kind: 'signal', value: '@x' }]), sPair });
  const wire = await seam.verify(await sealCell(cell, r));
  assert.equal(await seam.accept(wire!), null); // not in book → dropped unread
});

test('round-trip: the payload a sender built opens on the receiver side (directional)', () => {
  const receiver = 'd'.repeat(64);
  const cell = buildLensCell({ kind: LENS_KIND_METHODS, fpSender: SENDER, fpReceiver: receiver, seq: 9, body: encodeLensMethodsBody([{ kind: 'site', value: 'https://x' }]), sPair });
  const parsed = unframeLensCell(cell);
  assert.ok(parsed);
  const opened = openLensPayload(cell.slice(6, 6 + new DataView(cell.buffer).getUint32(2, false)), { sPair, fpSender: parsed!.fpSender, fpReceiver: receiver });
  assert.equal(opened.ok, true);
});
