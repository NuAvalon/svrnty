// src/lib/lenses/lens-send.test.ts — contract R2 (fail-closed filter: no record ⇒ ZERO methods,
// HELD), R3-gap (only sent-or-confirmed keys flow), R5 (the gate), R7 (capability hold),
// R8 (uniform deposit shape), R9 (no signed-update path), review-1 items 4 + 8.
// Run: npx tsx --test src/lib/lenses/lens-send.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { randomBytes } from '@noble/hashes/utils.js';
import type { OwnerCardBag } from '../../components/identity/owner-card';
import { buildLensDeposits, buildLensHelloDeposits, lensForSend, methodsForSend } from './lens-send';
import { markPeerCapable, recordLensKeys, setRecipientLens, type LensGrantBook } from './lens-grants';
import { FRAME_BYTES, unframeUniform } from '../crypto/uniform-frame';
import { openMailboxEnvelope } from '../crypto/mailbox-envelope';
import { mintHybridRecipient } from '../sync/hybrid-test-fixture';
import { LENS_KIND_METHODS, LENS_MAX_BODY, decodeLensMethodsBody, lensMethodKey, openLensPayload, parseLensPayload, unframeLensCell } from './lens-wire';
import { lensTooLargeLine } from './lens-copy';

const OWNER = 'a'.repeat(64);
const sPair = randomBytes(32);
const NOW = 1_800_000_000;

const bag: OwnerCardBag = {
  methods: [
    { id: 'm-email', kind: 'email', value: 'me@work.example' },
    { id: 'm-signal', kind: 'signal', value: '@me' },
    { id: 'm-insta', kind: 'instagram', value: '@me.off' },
  ],
  lenses: [
    { id: 'lens-everyone', name: 'Everyone', methodIds: ['m-email'] },
    { id: 'lens-close', name: 'Close', methodIds: ['m-email', 'm-signal', 'm-insta'] },
    { id: 'lens-min', name: 'Minimal', methodIds: [] },
  ],
  defaultLensId: 'lens-everyone',
};

const bookWith = (grants: LensGrantBook['grants']): LensGrantBook => ({ v: 1, grants });
const admitAll = () => true;
const hybridOf = async () => mintHybridRecipient();
const recip = (r: Awaited<ReturnType<typeof mintHybridRecipient>>) => ({
  fingerprint: r.fingerprint,
  publicKeyArmored: r.publicKeyArmored,
  pqKemPublicKey: r.pqKemPublicKey,
});
/** Decode a deposit the way the recipient would → the wire method list. */
async function depositedMethods(blob: string, r: Awaited<ReturnType<typeof mintHybridRecipient>>) {
  const cell = await openMailboxEnvelope(JSON.parse(blob), r.hybrid.secrets, r.hybrid.myFp);
  const parsed = parseLensPayload(unframeUniform(cell!)!.payload);
  return { parsed: parsed!, methods: decodeLensMethodsBody(parsed!.body) };
}

test('R2 ruling: NO record ⇒ ZERO methods and the update is HELD — no payload, no seq bump', async () => {
  const r = await hybridOf();
  const book = markPeerCapable(bookWith({}), r.fingerprint); // capable, but no grant record at all
  const plan = await buildLensDeposits({
    ownerFingerprint: OWNER, bag, book,
    recipients: [recip(r)],
    admit: admitAll, sPairFor: () => sPair, nowSeconds: () => NOW,
  });
  assert.equal(plan.deposits.length, 0, 'no record ⇒ nothing is built — not even an empty list');
  assert.deepEqual(plan.held, [{ fingerprint: r.fingerprint, reason: 'no-record' }]);
  assert.equal(plan.skipped.length, 0);
  assert.equal(plan.book, book, 'a held update bumps no seq and touches no row');
  assert.equal(lensForSend(bag, book, r.fingerprint), null);
});

test('R2 ruling: an UNREADABLE record holds identically (empty book ⇒ discloses nothing to anyone)', async () => {
  const r = await hybridOf();
  // loadLensGrants reads corrupt rows as the empty book — so this IS the unreadable case: every
  // recipient is held no-record and nothing goes out (the restore-with-empty-book case too).
  const empty = bookWith({});
  const plan = await buildLensDeposits({
    ownerFingerprint: OWNER, bag, book: empty,
    recipients: [recip(r)],
    admit: admitAll, sPairFor: () => sPair, nowSeconds: () => NOW,
  });
  assert.equal(plan.deposits.length, 0);
  assert.deepEqual(plan.held, [{ fingerprint: r.fingerprint, reason: 'no-record' }]);
});

test('R2 ruling: a grant naming a DELETED lens sends zero and holds — never a fallback face', async () => {
  const r = await hybridOf();
  const book = markPeerCapable(bookWith({ [r.fingerprint]: { lens: 'lens-gone', sent: ['m-email'] } }), r.fingerprint);
  const plan = await buildLensDeposits({
    ownerFingerprint: OWNER, bag, book,
    recipients: [recip(r)],
    admit: admitAll, sPairFor: () => sPair, nowSeconds: () => NOW,
  });
  assert.equal(plan.deposits.length, 0);
  assert.deepEqual(plan.held, [{ fingerprint: r.fingerprint, reason: 'no-record' }]);
  assert.equal(plan.book, book);
});

test('R2: methodsForSend carries only the lens methods (value-bearing, resolved)', () => {
  const everyone = bag.lenses[0];
  assert.deepEqual(methodsForSend(bag, everyone), [{ id: 'm-email', kind: 'email', value: 'me@work.example' }]);
  const min = bag.lenses.find((l) => l.id === 'lens-min')!;
  assert.deepEqual(methodsForSend(bag, min), []);
});

test('item 3: a lens edit widens nobody — the new method does not flow until EACH holder confirms', async () => {
  const r1 = await hybridOf();
  const r2 = await hybridOf();
  const emailKey = 'm-email';
  // Both hold lens-everyone and were already sent its email.
  let book = bookWith({
    [r1.fingerprint]: { lens: 'lens-everyone', capable: true, sent: [emailKey] },
    [r2.fingerprint]: { lens: 'lens-everyone', capable: true, sent: [emailKey] },
  });
  // The owner edits lens-everyone to add the signal method (same lens, new exposure).
  const edited: OwnerCardBag = {
    ...bag,
    lenses: bag.lenses.map((l) => (l.id === 'lens-everyone' ? { ...l, methodIds: ['m-email', 'm-signal'] } : l)),
  };
  const plan = await buildLensDeposits({
    ownerFingerprint: OWNER, bag: edited, book,
    recipients: [recip(r1), recip(r2)],
    admit: admitAll, sPairFor: () => sPair, nowSeconds: () => NOW,
  });
  assert.equal(plan.deposits.length, 2);
  // Per-recipient: the payload carries email ONLY — the unconfirmed signal key stays behind
  // (deposits follow recipient order: [0]→r1, [1]→r2).
  const m1 = await depositedMethods(plan.deposits[0].blob, r1);
  assert.deepEqual(m1.methods, [{ kind: 'email', value: 'me@work.example' }]);
  const m2 = await depositedMethods(plan.deposits[1].blob, r2);
  assert.deepEqual(m2.methods, [{ kind: 'email', value: 'me@work.example' }]);
  // And the pending widening is reported per recipient so the view can ask.
  const signalPending = { id: 'm-signal', kind: 'signal', value: '@me' };
  assert.deepEqual(plan.wideningPending, [
    { fingerprint: r1.fingerprint, methods: [signalPending] },
    { fingerprint: r2.fingerprint, methods: [signalPending] },
  ]);
  // r1 confirms (the key lands in their sent set); r2 does not.
  const signalKey = 'm-signal';
  book = recordLensKeys(plan.book, r1.fingerprint, [signalKey]);
  const plan2 = await buildLensDeposits({
    ownerFingerprint: OWNER, bag: edited, book,
    recipients: [recip(r1), recip(r2)],
    admit: admitAll, sPairFor: () => sPair, nowSeconds: () => NOW + 60,
  });
  assert.equal(plan2.deposits.length, 2);
  const m1b = await depositedMethods(plan2.deposits[0].blob, r1);
  assert.deepEqual(m1b.methods, [{ kind: 'email', value: 'me@work.example' }, { kind: 'signal', value: '@me' }], 'r1: confirmed widening flows');
  const m2b = await depositedMethods(plan2.deposits[1].blob, r2);
  assert.deepEqual(m2b.methods, [{ kind: 'email', value: 'me@work.example' }], 'r2: still email only until THEY confirm');
});

test('item 3 mutant-guard: the composer must NEVER send the unfiltered current lens set', () => {
  // Source pin: the sent-set filter runs BEFORE encode; a regression that encodes lensMethods
  // (or methodsForSend output unfiltered) goes red here.
  const dir = fileURLToPath(new URL('.', import.meta.url));
  const src = readFileSync(`${dir}/lens-send.ts`, 'utf8');
  assert.match(src, /lensSentKeys\(book, fp\)/, 'the sent set must be read from the grant');
  assert.match(src, /encodeLensMethodsBody\(allowed\)/, 'only the allowed (sent-or-confirmed) set may be encoded');
  assert.equal(/encodeLensMethodsBody\(lensMethods\)|encodeLensMethodsBody\(methodsForSend/.test(src), false,
    'the unfiltered current set must never reach the encoder');
});

test('item 1: a held update bumps NO seq — the next send still starts where the last real one ended', async () => {
  const r = await hybridOf();
  const emailKey = 'm-email';
  let book = markPeerCapable(setRecipientLens(bookWith({}), r.fingerprint, 'lens-everyone'), r.fingerprint);
  // No sent keys yet ⇒ every lens method is an unconfirmed widening ⇒ held, not a zero-method payload.
  const plan = await buildLensDeposits({
    ownerFingerprint: OWNER, bag, book,
    recipients: [recip(r)],
    admit: admitAll, sPairFor: () => sPair, nowSeconds: () => NOW,
  });
  assert.equal(plan.deposits.length, 0);
  assert.equal(plan.held[0].reason, 'unconfirmed');
  assert.equal(plan.book.grants[r.fingerprint]!.seq, undefined, 'held ⇒ no seq written');
  // After the per-recipient confirm, the send goes — stamped at the wall-clock floor.
  book = recordLensKeys(plan.book, r.fingerprint, [emailKey]);
  const sent = await buildLensDeposits({
    ownerFingerprint: OWNER, bag, book,
    recipients: [recip(r)],
    admit: admitAll, sPairFor: () => sPair, nowSeconds: () => NOW,
  });
  assert.equal(sent.deposits.length, 1);
  assert.equal(sent.book.grants[r.fingerprint]!.seq, NOW, 'seq anchors to whole seconds');
  // And the sent key is recorded as disclosed.
  assert.ok(sent.book.grants[r.fingerprint]!.sent!.includes(emailKey));
});

test('item 4: sender book emptied after N sends ⇒ the next payload is still accepted (wall-clock seq)', async () => {
  const r = await hybridOf();
  const emailKey = 'm-email';
  const granted = markPeerCapable(
    recordLensKeys(setRecipientLens(bookWith({}), r.fingerprint, 'lens-everyone'), r.fingerprint, [emailKey]),
    r.fingerprint,
  );
  // N sends, then the sender's book is wiped (restore/clear): seq restarts anchored to wall time,
  // which is ABOVE the receiver's floor — no silent stall.
  const plan = await buildLensDeposits({
    ownerFingerprint: OWNER, bag, book: granted,
    recipients: [recip(r)],
    admit: admitAll, sPairFor: () => sPair, nowSeconds: () => NOW,
  });
  const wiped = { v: 1 as const, grants: { [r.fingerprint]: { lens: 'lens-everyone', capable: true, sent: [emailKey] } } };
  const plan2 = await buildLensDeposits({
    ownerFingerprint: OWNER, bag, book: wiped,
    recipients: [recip(r)],
    admit: admitAll, sPairFor: () => sPair, nowSeconds: () => NOW + 3600,
  });
  const { parsed: p1 } = await depositedMethods(plan.deposits[0].blob, r);
  const { parsed: p2 } = await depositedMethods(plan2.deposits[0].blob, r);
  assert.equal(p1.seq, NOW);
  assert.equal(p2.seq, NOW + 3600, 'wiped book resumes above the old floor');
});

test('item 8: a lens that cannot fit one cell is skipped too-large — nothing goes out', async () => {
  const r = await hybridOf();
  // Craft a bag whose methods are all codec-valid but whose body exceeds LENS_MAX_BODY in one cell
  // (many small methods — a single oversized VALUE would fail the codec bound first, encode-failed).
  const ids = Array.from({ length: 30 }, (_, i) => `m-big-${i}`);
  const big: OwnerCardBag = {
    methods: ids.map((id, i) => ({ id, kind: 'custom' as const, value: `v-${i}-` + 'x'.repeat(60), label: `lbl-${i}-` + 'y'.repeat(40) })),
    lenses: [{ id: 'lens-big', name: 'Big', methodIds: ids }],
  };
  const hugeKey = ids;
  const book = markPeerCapable(
    recordLensKeys(setRecipientLens(bookWith({}), r.fingerprint, 'lens-big'), r.fingerprint, hugeKey),
    r.fingerprint,
  );
  const plan = await buildLensDeposits({
    ownerFingerprint: OWNER, bag: big, book,
    recipients: [recip(r)],
    admit: admitAll, sPairFor: () => sPair, nowSeconds: () => NOW,
  });
  assert.equal(plan.deposits.length, 0);
  assert.deepEqual(plan.skipped, [{ fingerprint: r.fingerprint, reason: 'too-large' }]);
  // The sender-facing string exists and is the contract's exact wording — never "encode-failed".
  assert.equal(lensTooLargeLine('Ana'), 'This lens has too much in it to send to Ana. Nothing went to them.');
});

test('R5: the existing RecipientGate is required and honored — a blocked recipient gets nothing', async () => {
  const r = await hybridOf();
  const book = markPeerCapable(bookWith({}), r.fingerprint);
  const plan = await buildLensDeposits({
    ownerFingerprint: OWNER, bag, book,
    recipients: [recip(r)],
    admit: () => false,
    sPairFor: () => sPair,
  });
  assert.equal(plan.deposits.length, 0);
  assert.deepEqual(plan.skipped, [{ fingerprint: r.fingerprint, reason: 'blocked' }]);
  await assert.rejects(
    () => buildLensDeposits({ ownerFingerprint: OWNER, bag, book, recipients: [], admit: undefined as never, sPairFor: () => sPair }),
    /recipient check/,
  );
});

test('R7: a granted recipient with no capability ⇒ HELD (reported), never sent', async () => {
  const r = await hybridOf();
  const emailKey = 'm-email';
  const book = recordLensKeys(setRecipientLens(bookWith({}), r.fingerprint, 'lens-everyone'), r.fingerprint, [emailKey]);
  const plan = await buildLensDeposits({
    ownerFingerprint: OWNER, bag, book,
    recipients: [recip(r)],
    admit: admitAll, sPairFor: () => sPair,
  });
  assert.equal(plan.deposits.length, 0);
  assert.deepEqual(plan.held, [{ fingerprint: r.fingerprint, reason: 'no-capability' }]);
  assert.equal(plan.skipped.length, 0);
});

test('end-to-end shape: capable+admitted+confirmed recipient gets exactly one 2048B sealed cell with only their sent methods', async () => {
  const r = await hybridOf();
  const emailKey = 'm-email';
  const signalKey = 'm-signal';
  let book = markPeerCapable(
    setRecipientLens(bookWith({ [r.fingerprint]: { seq: 4 } }), r.fingerprint, 'lens-close'),
    r.fingerprint,
  );
  // Confirmed for email + signal — but NOT instagram (which lens-close also carries).
  book = recordLensKeys(book, r.fingerprint, [emailKey, signalKey]);
  const plan = await buildLensDeposits({
    ownerFingerprint: OWNER, bag, book,
    recipients: [recip(r), { fingerprint: 'f'.repeat(64), publicKeyArmored: '', pqKemPublicKey: undefined }],
    admit: admitAll, sPairFor: () => sPair, nowSeconds: () => NOW,
  });
  assert.equal(plan.deposits.length, 1);
  assert.equal(plan.skipped.length, 0);
  assert.deepEqual(plan.held, [{ fingerprint: 'f'.repeat(64), reason: 'no-record' }], 'a recordless recipient is held before key material is even looked at');
  const { parsed, methods } = await depositedMethods(plan.deposits[0].blob, r);
  assert.equal(parsed.kind, LENS_KIND_METHODS);
  assert.equal(parsed.seq, NOW, 'seq anchors to wall time even off an old counter');
  assert.equal(parsed.fpSender, OWNER);
  assert.deepEqual(methods, [{ kind: 'email', value: 'me@work.example' }, { kind: 'signal', value: '@me' }]);
  // Uniform shape: exactly one 2048B cell whatever the lens holds.
  const cell = await openMailboxEnvelope(JSON.parse(plan.deposits[0].blob), r.hybrid.secrets, r.hybrid.myFp);
  assert.equal(cell!.length, FRAME_BYTES);
  assert.equal(unframeLensCell(cell!)!.kind, LENS_KIND_METHODS);
});

test('R7 hello: the capability signal rides the same sealed 2048B shape, seq 0, admitted-only', async () => {
  const r = await hybridOf();
  const { deposits, skipped } = await buildLensHelloDeposits({
    ownerFingerprint: OWNER,
    recipients: [recip(r)],
    admit: admitAll,
    sPairFor: () => sPair,
    book: { v: 1, grants: {} },
  });
  assert.equal(skipped.length, 0);
  const pkg = JSON.parse(deposits[0].blob);
  const cell = await openMailboxEnvelope(pkg, r.hybrid.secrets, r.hybrid.myFp);
  const parsed = parseLensPayload(unframeUniform(cell!)!.payload);
  assert.equal(parsed!.kind, 0x01);
  assert.equal(parsed!.seq, 0);
  const refused = await buildLensHelloDeposits({
    ownerFingerprint: OWNER,
    recipients: [recip(r)],
    admit: () => false,
    sPairFor: () => sPair,
    book: { v: 1, grants: {} },
  });
  assert.equal(refused.deposits.length, 0);
  assert.deepEqual(refused.skipped, [{ fingerprint: r.fingerprint, reason: 'blocked' }]);
});

test('R9: lens methods never enter the signed-update path (source guard)', () => {
  const dir = fileURLToPath(new URL('.', import.meta.url));
  for (const f of ['lens-send.ts', 'lens-wire.ts', 'lens-consume.ts', 'lens-grants.ts', 'lens-plan.ts', 'lens-display.ts']) {
    const src = readFileSync(`${dir}/${f}`, 'utf8');
    assert.equal(/import[^;]*contact-update-sign/.test(src), false, `${f}: must not import the signed-update builder`);
    assert.equal(/buildAndSignContactUpdate\s*\(/.test(src), false, `${f}: must not call the signed-update builder`);
    assert.equal(/CONTACT_UPDATE_ALLOWED_FIELDS/.test(src.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, '')), false, `${f}: must not touch the update allowlist`);
  }
});

test('R3a: the sent set keys the owner METHOD id — a slot-colliding lens move asks (widening)', async () => {
  // Two lenses each holding ONE unlabelled phone with different VALUES: same wire slot
  // (kind+label), different owner methods. A mutant keyed on the slot would report no widening.
  const r = await hybridOf();
  const two: OwnerCardBag = {
    methods: [
      { id: 'm-phone-work', kind: 'phone', value: '+15550001' },
      { id: 'm-phone-personal', kind: 'phone', value: '+19990002' },
    ],
    lenses: [
      { id: 'lens-work', name: 'Work', methodIds: ['m-phone-work'] },
      { id: 'lens-personal', name: 'Personal', methodIds: ['m-phone-personal'] },
    ],
  };
  // Sent the work phone already (by method id), then reassigned to lens-personal without confirm:
  // the personal number is a WIDENING even though it shares the work number's slot.
  const book = markPeerCapable(
    recordLensKeys(setRecipientLens(bookWith({}), r.fingerprint, 'lens-personal'), r.fingerprint, ['m-phone-work']),
    r.fingerprint,
  );
  const plan = await buildLensDeposits({
    ownerFingerprint: OWNER, bag: two, book,
    recipients: [recip(r)],
    admit: admitAll, sPairFor: () => sPair, nowSeconds: () => NOW,
  });
  assert.equal(plan.deposits.length, 0, 'nothing flows until the per-recipient confirm');
  assert.equal(plan.held[0].reason, 'unconfirmed');
  assert.deepEqual(plan.wideningPending, [{ fingerprint: r.fingerprint, methods: [{ id: 'm-phone-personal', kind: 'phone', value: '+19990002' }] }],
    'the same-slot different-method reports as a widening — keyed by method id, never by wire slot');
});

test('R8a composer hold: a lens carrying two methods in one slot is HELD — owner labels first', async () => {
  const r = await hybridOf();
  const dup: OwnerCardBag = {
    methods: [
      { id: 'm-p1', kind: 'phone', value: '+111' },
      { id: 'm-p2', kind: 'phone', value: '+222' }, // same kind, no label — same slot as m-p1
      { id: 'm-mail', kind: 'email', value: 'a@x' },
    ],
    lenses: [{ id: 'lens-dup', name: 'Dup', methodIds: ['m-p1', 'm-p2', 'm-mail'] }],
  };
  const book = markPeerCapable(
    recordLensKeys(setRecipientLens(bookWith({}), r.fingerprint, 'lens-dup'), r.fingerprint, ['m-p1', 'm-p2', 'm-mail']),
    r.fingerprint,
  );
  const plan = await buildLensDeposits({
    ownerFingerprint: OWNER, bag: dup, book,
    recipients: [recip(r)],
    admit: admitAll, sPairFor: () => sPair, nowSeconds: () => NOW,
  });
  assert.equal(plan.deposits.length, 0);
  assert.equal(plan.held[0].reason, 'shared-slot');
  assert.equal(plan.book, book, 'a held composer bumps no seq and touches no row');
});

test('R7a hello rate: two calls send ONE hello; one retry after the envelope life; then nothing', async () => {
  const r = await hybridOf();
  const call = (book: LensGrantBook, at: number) =>
    buildLensHelloDeposits({
      ownerFingerprint: OWNER, recipients: [recip(r)], admit: admitAll, sPairFor: () => sPair,
      book, nowSeconds: () => at,
    });
  const first = await call({ v: 1, grants: {} }, NOW);
  assert.equal(first.deposits.length, 1);
  assert.deepEqual(first.book.grants[r.fingerprint]!.hello, { v: 1, at: NOW, n: 1 }, 'the sealed marker is what rations the next call');
  const second = await call(first.book, NOW + 60);
  assert.equal(second.deposits.length, 0, 'a second call inside the window sends nothing');
  assert.deepEqual(second.skipped, [{ fingerprint: r.fingerprint, reason: 'hello-throttled' }]);
  const retry = await call(second.book, NOW + 7 * 86400 + 1);
  assert.equal(retry.deposits.length, 1, 'one retry after the envelope life');
  assert.equal(retry.book.grants[r.fingerprint]!.hello!.n, 2);
  const third = await call(retry.book, NOW + 30 * 86400);
  assert.equal(third.deposits.length, 0, 'budget spent — nothing until the capability version changes');
});
