// src/lib/sync/send-introduction.test.ts
// Introduce P2-A (#600): the INTRODUCER's deposit. Real signatures, real hybrid seal, and the recipient's real verifyIntroduction round trip.
// Fail-closed on every input the sender controls. Run: npx tsx --test src/lib/sync/send-introduction.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { buildIntroductionConsent, signIntroductionConsent, verifyIntroduction } from '@/lib/trust/introduction';
import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { asMailboxEnvelopePackage } from '@/lib/sync/hybrid-dual-read';
import { mintHybridRecipient, type HybridRecipient } from '@/lib/sync/hybrid-test-fixture';
import { buildIntroductionDeposit, sendIntroduction, type NewcomerCard } from './send-introduction';

let ivan: HybridRecipient, newt: HybridRecipient, rachel: HybridRecipient;
before(async () => {
  [ivan, newt, rachel] = [await mintHybridRecipient(), await mintHybridRecipient(), await mintHybridRecipient()];
});

const NONCE = 'INTRO-P2A-1';
async function card(over: { recipientFp?: string; introducerFp?: string; displayName?: string; consentName?: string } = {}): Promise<NewcomerCard> {
  const consent = buildIntroductionConsent({
    introducedFp: newt.fingerprint, introducerFp: over.introducerFp ?? ivan.fingerprint, recipientFp: over.recipientFp ?? rachel.fingerprint,
    displayName: over.consentName ?? 'Newt', nonce: NONCE, ts: '2026-10-31T00:00:00Z',
  });
  const consentSignature = await signIntroductionConsent(consent, newt.privateKeyArmored, newt.passphrase, newt.pqSigSecretKey); // a canonical newcomer signs hybrid
  return {
    fingerprint: newt.fingerprint, publicKeyArmored: newt.publicKeyArmored, displayName: over.displayName ?? 'Newt',
    pqKemPublicKeyB64: newt.pqKemPublicKey, pqSigPublicKeyB64: newt.pqSigPublicKey, consent, consentSignature,
  };
}
const introducer = () => ({ fingerprint: ivan.fingerprint, privateKeyArmored: ivan.privateKeyArmored, passphrase: ivan.passphrase });
const target = (over: Partial<{ pqKemPublicKey: string | undefined }> = {}) => ({ fingerprint: rachel.fingerprint, publicKeyArmored: rachel.publicKeyArmored, pqKemPublicKey: rachel.pqKemPublicKey, ...over });
const knowsIvan = (fp: string) => (fp === ivan.fingerprint ? { publicKeyArmored: ivan.publicKeyArmored } : null);

test('D1 the deposit is a HYBRID package addressed to the recipient mailbox, and the relay-visible blob contains no name or fingerprint', async () => {
  const dep = await buildIntroductionDeposit(introducer(), await card(), target(), 'met at the conference');
  assert.ok(dep);
  assert.equal(dep.mailbox_id, deriveMailboxId(rachel.fingerprint));
  assert.ok(asMailboxEnvelopePackage(dep.blob), 'a MailboxEnvelopePackage, not armored OpenPGP');
  for (const leak of ['Newt', 'conference', newt.fingerprint, ivan.fingerprint]) assert.equal(dep.blob.includes(leak), false, `blob must not contain ${leak.slice(0, 12)}`);
});

test('D2 ROUND TRIP: Rachel opens it with her mailbox secrets and verifyIntroduction surfaces Newt as KNOWN, introduced by Ivan', async () => {
  const dep = await buildIntroductionDeposit(introducer(), await card(), target(), 'met at the conference');
  const p = await verifyIntroduction(dep!.blob, { fingerprint: rachel.fingerprint, hybrid: rachel.hybrid }, knowsIvan);
  assert.ok(p);
  assert.equal(p.fingerprint, newt.fingerprint);
  assert.equal(p.introducedByFingerprint, ivan.fingerprint);
  assert.equal(p.displayName, 'Newt');
  assert.equal(p.nonce, NONCE);
});

test('D3 NEG (HNDL): a recipient with NO ML-KEM key gets no deposit, no request is made, and the result says encrypt-failed', async () => {
  const calls: string[] = [];
  const fetchImpl = (async (u: unknown) => { calls.push(String(u)); return new Response('{}', { status: 200 }); }) as typeof fetch;
  assert.equal(await buildIntroductionDeposit(introducer(), await card(), target({ pqKemPublicKey: undefined }), 'x'), null);
  assert.equal(await buildIntroductionDeposit(introducer(), await card(), target({ pqKemPublicKey: '' }), 'x'), null);
  const r = await sendIntroduction(introducer(), await card(), target({ pqKemPublicKey: undefined }), 'x', { fetchImpl });
  assert.deepEqual(r, { ok: false, status: 'encrypt-failed' });
  assert.deepEqual(calls, []);
});

test('D4 NEG (survivor-safety S1): a consent harvested for ANOTHER recipient, or ANOTHER introducer, or signed under a DIFFERENT name, produces no deposit', async () => {
  assert.equal(await buildIntroductionDeposit(introducer(), await card({ recipientFp: ivan.fingerprint }), target(), 'x'), null, 'consent names a different recipient');
  assert.equal(await buildIntroductionDeposit(introducer(), await card({ introducerFp: rachel.fingerprint }), target(), 'x'), null, 'consent names a different introducer');
  assert.equal(await buildIntroductionDeposit(introducer(), await card({ displayName: 'Deadname', consentName: 'Newt' }), target(), 'x'), null, 'introducer renames Newt to a name they did not consent to');
});

test('D5 NEG: a recipient with no fingerprint or no key yields no deposit (never throws to the UI)', async () => {
  assert.equal(await buildIntroductionDeposit(introducer(), await card(), { fingerprint: '', publicKeyArmored: rachel.publicKeyArmored, pqKemPublicKey: rachel.pqKemPublicKey }, 'x'), null);
  assert.equal(await buildIntroductionDeposit(introducer(), await card(), { fingerprint: rachel.fingerprint, publicKeyArmored: '', pqKemPublicKey: rachel.pqKemPublicKey }, 'x'), null);
  assert.equal(await buildIntroductionDeposit(introducer(), await card(), { fingerprint: rachel.fingerprint, publicKeyArmored: 'not a key', pqKemPublicKey: rachel.pqKemPublicKey }, 'x'), null);
});

test('S1 sendIntroduction POSTs {mailbox_id, blob} to <relay>/envelope once and reports the status; a refusal and a network failure are results, not throws', async () => {
  const seen: Array<{ url: string; body: string }> = [];
  const mk = (status: number | 'throw') => (async (u: unknown, i?: RequestInit) => {
    seen.push({ url: String(u), body: String(i?.body) });
    if (status === 'throw') throw new TypeError('fetch failed');
    return new Response('{}', { status });
  }) as typeof fetch;
  const ok = await sendIntroduction(introducer(), await card(), target(), 'x', { fetchImpl: mk(200), relayBase: 'http://relay.test/api/relay' });
  assert.deepEqual(ok, { ok: true, status: 200 });
  assert.equal(seen[0].url, 'http://relay.test/api/relay/envelope');
  const sent = JSON.parse(seen[0].body) as { mailbox_id: string; blob: string };
  assert.equal(sent.mailbox_id, deriveMailboxId(rachel.fingerprint));
  assert.deepEqual((await sendIntroduction(introducer(), await card(), target(), 'x', { fetchImpl: mk(429) })), { ok: false, status: 429 });
  assert.deepEqual((await sendIntroduction(introducer(), await card(), target(), 'x', { fetchImpl: mk('throw') })), { ok: false, status: 'network-error' });
  assert.equal(seen.length, 3);
});
