// src/lib/lenses/lens-send.test.ts — contract R2 (fail-closed filter), R5 (the gate), R7 (capability
// hold), R9 (no signed-update path), R8 (uniform deposit shape).
// Run: npx tsx --test src/lib/lenses/lens-send.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { randomBytes } from '@noble/hashes/utils.js';
import type { OwnerCardBag } from '../../components/identity/owner-card';
import { buildLensDeposits, buildLensHelloDeposits, lensForSend, methodsForSend, narrowestLens } from './lens-send';
import { markPeerCapable, type LensGrantBook } from './lens-grants';
import { FRAME_BYTES, unframeUniform } from '../crypto/uniform-frame';
import { openMailboxEnvelope } from '../crypto/mailbox-envelope';
import { mintHybridRecipient } from '../sync/hybrid-test-fixture';
import { LENS_KIND_METHODS, parseLensPayload } from './lens-wire';

const OWNER = 'a'.repeat(64);
const sPair = randomBytes(32);

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

test('R2: no record ⇒ the narrowest face (fewest methods), not the default lens', () => {
  assert.equal(narrowestLens(bag)!.id, 'lens-min'); // 0 methods — narrower than the default's 1
  const book = bookWith({});
  assert.equal(lensForSend(bag, book, 'b'.repeat(64))!.id, 'lens-min');
  // A grant naming a deleted lens falls to the same floor.
  const stale = bookWith({ ['b'.repeat(64)]: { lens: 'lens-gone' } });
  assert.equal(lensForSend(bag, stale, 'b'.repeat(64))!.id, 'lens-min');
  // A real grant resolves its own lens.
  const granted = bookWith({ ['b'.repeat(64)]: { lens: 'lens-close' } });
  assert.equal(lensForSend(bag, granted, 'b'.repeat(64))!.id, 'lens-close');
});

test('R2: methodsForSend carries only the lens methods (value-bearing, resolved)', () => {
  const everyone = bag.lenses[0];
  assert.deepEqual(methodsForSend(bag, everyone), [{ kind: 'email', value: 'me@work.example' }]);
  const min = bag.lenses.find((l) => l.id === 'lens-min')!;
  assert.deepEqual(methodsForSend(bag, min), []);
});

test('R5: the existing RecipientGate is required and honored — a blocked recipient gets nothing', async () => {
  const r = await mintHybridRecipient();
  const book = markPeerCapable(bookWith({}), r.fingerprint);
  const plan = await buildLensDeposits({
    ownerFingerprint: OWNER,
    bag,
    book,
    recipients: [{ fingerprint: r.fingerprint, publicKeyArmored: r.publicKeyArmored, pqKemPublicKey: r.pqKemPublicKey }],
    admit: () => false, // the book says blocked
    sPairFor: () => sPair,
  });
  assert.equal(plan.deposits.length, 0);
  assert.deepEqual(plan.skipped, [{ fingerprint: r.fingerprint, reason: 'blocked' }]);
  // And a missing gate refuses the whole batch, loudly.
  await assert.rejects(
    () => buildLensDeposits({ ownerFingerprint: OWNER, bag, book, recipients: [], admit: undefined as never, sPairFor: () => sPair }),
    /recipient check/,
  );
});

test('R7: no capability ⇒ the payload is HELD (reported), never sent', async () => {
  const r = await mintHybridRecipient();
  const book = bookWith({ [r.fingerprint]: { lens: 'lens-close' } }); // grant, but NO hello
  const plan = await buildLensDeposits({
    ownerFingerprint: OWNER,
    bag,
    book,
    recipients: [{ fingerprint: r.fingerprint, publicKeyArmored: r.publicKeyArmored, pqKemPublicKey: r.pqKemPublicKey }],
    admit: admitAll,
    sPairFor: () => sPair,
  });
  assert.equal(plan.deposits.length, 0);
  assert.deepEqual(plan.held, [{ fingerprint: r.fingerprint, reason: 'no-capability' }]);
  assert.equal(plan.skipped.length, 0);
});

test('end-to-end shape: capable+admitted recipient gets exactly one 2048B sealed cell with only their lens methods', async () => {
  const r = await mintHybridRecipient();
  const book = markPeerCapable(bookWith({ [r.fingerprint]: { lens: 'lens-close', seq: 4 } }), r.fingerprint);
  const plan = await buildLensDeposits({
    ownerFingerprint: OWNER,
    bag,
    book,
    recipients: [
      { fingerprint: r.fingerprint, publicKeyArmored: r.publicKeyArmored, pqKemPublicKey: r.pqKemPublicKey },
      { fingerprint: 'f'.repeat(64), publicKeyArmored: '', pqKemPublicKey: undefined }, // fails closed, per-recipient
    ],
    admit: admitAll,
    sPairFor: () => sPair,
  });
  assert.equal(plan.deposits.length, 1);
  assert.deepEqual(plan.skipped, [{ fingerprint: 'f'.repeat(64), reason: 'no-public-key' }]);
  // seq bumped only for the built recipient.
  assert.equal(plan.book.grants[r.fingerprint]!.seq, 5);
  // Open it the way the recipient would: hybrid unwrap → uniform cell → lens payload.
  const pkg = JSON.parse(plan.deposits[0].blob);
  const cell = await openMailboxEnvelope(pkg, r.hybrid.secrets, r.hybrid.myFp);
  assert.ok(cell);
  assert.equal(cell!.length, FRAME_BYTES);
  const framed = unframeUniform(cell!);
  assert.equal(framed!.type, 'lens');
  const parsed = parseLensPayload(framed!.payload);
  assert.equal(parsed!.kind, LENS_KIND_METHODS);
  assert.equal(parsed!.seq, 5);
  assert.equal(parsed!.fpSender, OWNER);
});

test('R7 hello: the capability signal rides the same sealed 2048B shape, seq 0, admitted-only', async () => {
  const r = await mintHybridRecipient();
  const { deposits, skipped } = await buildLensHelloDeposits({
    ownerFingerprint: OWNER,
    recipients: [{ fingerprint: r.fingerprint, publicKeyArmored: r.publicKeyArmored, pqKemPublicKey: r.pqKemPublicKey }],
    admit: admitAll,
    sPairFor: () => sPair,
  });
  assert.equal(skipped.length, 0);
  const pkg = JSON.parse(deposits[0].blob);
  const cell = await openMailboxEnvelope(pkg, r.hybrid.secrets, r.hybrid.myFp);
  const parsed = parseLensPayload(unframeUniform(cell!)!.payload);
  assert.equal(parsed!.kind, 0x01);
  assert.equal(parsed!.seq, 0);
  // A blocked contact gets no hello either — the gate is the only path.
  const refused = await buildLensHelloDeposits({
    ownerFingerprint: OWNER,
    recipients: [{ fingerprint: r.fingerprint, publicKeyArmored: r.publicKeyArmored, pqKemPublicKey: r.pqKemPublicKey }],
    admit: () => false,
    sPairFor: () => sPair,
  });
  assert.equal(refused.deposits.length, 0);
  assert.deepEqual(refused.skipped, [{ fingerprint: r.fingerprint, reason: 'blocked' }]);
});

test('R9: lens methods never enter the signed-update path (source guard)', () => {
  const dir = fileURLToPath(new URL('.', import.meta.url));
  for (const f of ['lens-send.ts', 'lens-wire.ts', 'lens-consume.ts', 'lens-grants.ts', 'lens-plan.ts']) {
    const src = readFileSync(`${dir}/${f}`, 'utf8');
    // The NAME may appear in a comment (the contract names it); the import and the call may not.
    assert.equal(/import[^;]*contact-update-sign/.test(src), false, `${f}: must not import the signed-update builder`);
    assert.equal(/buildAndSignContactUpdate\s*\(/.test(src), false, `${f}: must not call the signed-update builder`);
    assert.equal(/CONTACT_UPDATE_ALLOWED_FIELDS/.test(src.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, '')), false, `${f}: must not touch the update allowlist`);
  }
});
