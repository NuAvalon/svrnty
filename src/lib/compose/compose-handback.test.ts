// Run: npx tsx --test src/lib/compose/compose-handback.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildHandBackModel, handBackText } from './compose-handback';
import type { SignedCompose } from './compose-sign';

const SIGNED: SignedCompose = {
  kind: 'post',
  object: { thread: 'lane:ops', purpose: 'svrnty-loom-post-v1', body: 'hi "there"\n👨‍👩‍👧', origin: 'noosphere.nuavalon.com', nonce: '0'.repeat(31) + '1', issued_at: '2026-10-25T07:20:00.000Z', fleet: 'autobots', expires_at: '2026-10-25T07:25:00.000Z' },
  suite: 'ed25519',
  sig_packet_b64: 'iHUEABYKAB0WIQQ=',
};

test('the text is compact JSON in a FIXED order {kind, object, suite, sig_packet_b64} with the object keys sorted, and it round-trips exactly', () => {
  const t = handBackText(SIGNED);
  assert.deepEqual(Object.keys(JSON.parse(t)), ['kind', 'object', 'suite', 'sig_packet_b64']);
  assert.deepEqual(Object.keys(JSON.parse(t).object), [...Object.keys(SIGNED.object)].sort());
  assert.deepEqual(JSON.parse(t), { kind: SIGNED.kind, object: SIGNED.object, suite: SIGNED.suite, sig_packet_b64: SIGNED.sig_packet_b64 });
  assert.doesNotMatch(t, /\n/, 'single line: the body\'s newline is escaped');
  assert.equal(handBackText({ ...SIGNED, object: Object.fromEntries(Object.entries(SIGNED.object).reverse()) }), t, 'insertion order of the object does not change the text');
});

test('NOTHING but those four fields can reach the text: extra properties on the signed value (a key, a passphrase) are dropped', () => {
  const dirty = { ...SIGNED, passphrase: 'hunter2', privateKeyArmored: '-----BEGIN PGP PRIVATE KEY BLOCK-----', secret: 1 } as unknown as SignedCompose;
  const t = handBackText(dirty);
  assert.equal(t, handBackText(SIGNED));
  assert.doesNotMatch(t, /hunter2|PRIVATE KEY|secret/);
});

test('the screen\'s strings are Hypatia\'s: title, body, Copy, Copied.; and title/buttons never say Posted, Sent or Delivered', () => {
  const m = buildHandBackModel(SIGNED);
  assert.equal(m.title, 'Signed. Not posted yet.');
  assert.equal(m.body, 'Copy this and paste it into the portal\'s "Sign on your phone" box. Nothing is posted until the portal delivers it; the portal shows what happened.');
  assert.equal(m.copy, 'Copy');
  assert.equal(m.copied, 'Copied.');
  assert.equal(m.json, handBackText(SIGNED));
  for (const s of [m.title, m.copy, m.copied]) assert.doesNotMatch(s, /\b(posted|sent|delivered)\b(?!\s+yet)/i, s);
  assert.doesNotMatch(m.copied, /sent/i, 'after Copy it says Copied, never sent');
});
