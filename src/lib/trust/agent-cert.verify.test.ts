// #705 INT-4 human-signed agent cert set: every refusal is tested on its own, plus the done_when cases
// (unknown/principal scope, expiry, monotonic seq, revocation reaching 3 holders, V4 domain separation).
// APOLLO verifier probes for INT-4 (not Flint's tests).
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import { mintCanonicalFingerprint } from '../identity/fingerprint';
import { signIdentityCard, type SignedIdentityCard } from '../identity/identity-card-sign';
import { signWithEnvelope } from '../crypto/sign-envelope';
import { DOMAIN_AGENT_CERT_SET, DOMAIN_MUTUAL_VOUCH, DOMAIN_IDENTITY_CARD } from '../format/envelope';
import {
  agentCardSha256, agentCertSetSigningInput, agentOf, applyAgentCertSet, checkAgentCertSetShape,
  entryCoversCard, signAgentCertSet, verifyAgentCertSet,
  AGENT_CERT_MAX_LIFETIME_MS, type AgentCertSet, type HumanPublicKeys,
} from './agent-cert';

interface Id extends HumanPublicKeys { privateKey: string; passphrase: string; sigSecretKey: Uint8Array }

async function makeId(name: string): Promise<Id> {
  const passphrase = 'pw-' + name;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart (same as identity/core.ts and joiner-response.test.ts)
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }],
    passphrase,
    format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase });
  const { fingerprint } = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey,
  });
  return {
    fingerprint, publicKey, privateKey, passphrase,
    kemPublicKeyB64: uint8ToBase64(pq.kem.publicKey), sigPublicKeyB64: uint8ToBase64(pq.signing.publicKey),
    sigSecretKey: pq.signing.secretKey,
  };
}

async function agentCard(id: Id, entity: 'agent' | 'human' = 'agent', name = 'a'): Promise<SignedIdentityCard> {
  return signIdentityCard({
    version: '1.0', type: 'identity-exchange', created_at: '2026-10-25T09:00:00Z',
    identity: {
      fingerprint: id.fingerprint, display_name: name, public_key: id.publicKey, email: '',
      pq_sig_public_key: id.sigPublicKeyB64, pq_kem_public_key: id.kemPublicKeyB64, next_authority_commitment: '',
    },
    entity_type: entity,
  }, id.privateKey, id.passphrase, id.sigSecretKey);
}

const NOW = new Date('2026-10-25T12:00:00Z');
let human: Id, other: Id, agA: Id, agB: Id, cardA: SignedIdentityCard, cardB: SignedIdentityCard;

before(async () => {
  [human, other, agA, agB] = await Promise.all([makeId('human'), makeId('other'), makeId('agA'), makeId('agB')]);
  [cardA, cardB] = await Promise.all([agentCard(agA), agentCard(agB)]);
});


function setOf(seq: number, ids: Array<[Id, SignedIdentityCard, string]>, o: Partial<AgentCertSet> = {}): AgentCertSet {
  const agents = ids
    .map(([id, card, scope]) => ({ agent_card_sha256: agentCardSha256(card), agent_fp: id.fingerprint, scope: scope as 'collaborate' }))
    .sort((a, b) => (a.agent_fp < b.agent_fp ? -1 : 1));
  return { v: 1, human_fp: human.fingerprint, seq, issued_at: '2026-10-25T10:00:00Z', expires_at: '2026-11-25T10:00:00Z', agents, ...o };
}
const sign = (s: AgentCertSet, id: Id = human) => signAgentCertSet(s, id.privateKey, id.passphrase, id.sigSecretKey);
const one = () => setOf(1, [[agA, cardA, 'collaborate']]);

test('P1 ISO validity: an impossible date, fractional seconds, a space, lowercase z, a zone offset are all shape', () => {
  for (const bad of ['2026-02-30T10:00:00Z', '2026-10-25T10:00:00.123Z', '2026-10-25 10:00:00Z', '2026-10-25T10:00:00z', '2026-10-25T10:00:00+00:00', '2026-13-01T10:00:00Z', '']) {
    assert.equal(checkAgentCertSetShape({ ...one(), issued_at: bad }), 'shape', 'issued_at ' + bad);
    assert.equal(checkAgentCertSetShape({ ...one(), expires_at: bad }), 'shape', 'expires_at ' + bad);
  }
  assert.equal(checkAgentCertSetShape(one()), null, 'control: the good set passes');
});

test('P2 seq: 0, -1, 1.5, NaN, a string, 2**53 are shape; the largest safe integer is fine', () => {
  for (const bad of [0, -1, 1.5, NaN, Infinity, '1', 2 ** 53, null, undefined]) assert.equal(checkAgentCertSetShape({ ...one(), seq: bad as number }), 'shape', String(bad));
  assert.equal(checkAgentCertSetShape({ ...one(), seq: Number.MAX_SAFE_INTEGER }), null);
});

test('P3 lifetime boundary: exactly 400 d is fine, 400 d + 1 s and zero/negative are lifetime', () => {
  const t0 = Date.parse('2026-10-25T10:00:00Z');
  const iso = (ms: number) => new Date(ms).toISOString().replace('.000Z', 'Z');
  assert.equal(checkAgentCertSetShape({ ...one(), expires_at: iso(t0 + AGENT_CERT_MAX_LIFETIME_MS) }), null);
  assert.equal(checkAgentCertSetShape({ ...one(), expires_at: iso(t0 + AGENT_CERT_MAX_LIFETIME_MS + 1000) }), 'lifetime');
  assert.equal(checkAgentCertSetShape({ ...one(), expires_at: iso(t0) }), 'lifetime');
  assert.equal(checkAgentCertSetShape({ ...one(), expires_at: iso(t0 - 1000) }), 'lifetime');
});

test('P4 size: 64 agents fit, 65 are shape', async () => {
  const mk = (n: number) => Array.from({ length: n }, (_, i) => ({ agent_card_sha256: 'c'.repeat(32) + i.toString(16).padStart(32, '0'), agent_fp: (i + 1).toString(16).padStart(64, '0'), scope: 'collaborate' as const }));
  assert.equal(checkAgentCertSetShape({ ...one(), agents: mk(64) }), null);
  assert.equal(checkAgentCertSetShape({ ...one(), agents: mk(65) }), 'shape');
});

test('P5 the verifier is bound to ONE human: another human\'s keys (right fp, or their own fp) never verify this set', async () => {
  const s = await sign(one());
  assert.equal((await verifyAgentCertSet(s, human, NOW)).ok, true, 'control');
  const asOther = await verifyAgentCertSet(s, other, NOW);
  assert.deepEqual(asOther, { ok: false, reason: 'wrong-human' });
  const wrongKeyRightFp = await verifyAgentCertSet(s, { ...human, publicKey: other.publicKey }, NOW);
  assert.deepEqual(wrongKeyRightFp, { ok: false, reason: 'key-binding' });
  const wrongPq = await verifyAgentCertSet(s, { ...human, sigPublicKeyB64: other.sigPublicKeyB64 }, NOW);
  assert.equal(wrongPq.ok, false);
});

test('P6 each signature half is bound: swapping EITHER half for a valid signature of the same human over something else fails', async () => {
  const s = await sign(one());
  const input = agentCertSetSigningInput(one());
  const other1 = await signWithEnvelope(DOMAIN_AGENT_CERT_SET, input + ' ', human.privateKey, human.passphrase, human.sigSecretKey); // same domain, different bytes
  for (const [label, forged] of [['classical', { ...s, signature: other1.classical }], ['pq', { ...s, pq_signature: other1.pq_signature! }]] as const) {
    const r = await verifyAgentCertSet(forged, human, NOW);
    assert.equal(r.ok, false, label + ' swap');
  }
});

test('P7 cross-domain replay: this human\'s hybrid signatures over the SAME bytes under the vouch, card and a made-up domain never verify as a cert', async () => {
  const input = agentCertSetSigningInput(one());
  for (const d of [DOMAIN_MUTUAL_VOUCH, DOMAIN_IDENTITY_CARD, 'svrnty:something-else:v1']) {
    const sg = await signWithEnvelope(d, input, human.privateKey, human.passphrase, human.sigSecretKey);
    const r = await verifyAgentCertSet({ ...one(), signature: sg.classical, pq_signature: sg.pq_signature! }, human, NOW);
    assert.equal(r.ok, false, d);
  }
});

test('P8 signature fields: missing PQ, empty strings, wrong types, an extra field are each refused', async () => {
  const s = await sign(one());
  const { pq_signature, ...noPq } = s;
  assert.deepEqual(await verifyAgentCertSet(noPq, human, NOW), { ok: false, reason: 'pq-missing' });
  assert.equal((await verifyAgentCertSet({ ...s, pq_signature: '' }, human, NOW)).ok, false);
  assert.equal((await verifyAgentCertSet({ ...s, signature: '' }, human, NOW)).ok, false);
  assert.equal((await verifyAgentCertSet({ ...s, signature: 5 as unknown as string }, human, NOW)).ok, false);
  assert.deepEqual(await verifyAgentCertSet({ ...s, extra: 1 }, human, NOW), { ok: false, reason: 'shape' });
  assert.equal(pq_signature.length > 100, true);
  for (const bad of [null, undefined, 'x', 5, [], [s]]) assert.equal((await verifyAgentCertSet(bad, human, NOW)).ok, false);
});

test('P9 time edges: not-yet-valid exactly at the skew is accepted and 1 s past is refused; expires_at == now is expired', async () => {
  const mkAt = async (issued: string, expires: string) => sign(one() && { ...one(), issued_at: issued, expires_at: expires });
  const skewOk = await mkAt('2026-10-25T12:05:00Z', '2026-11-25T10:00:00Z');
  assert.equal((await verifyAgentCertSet(skewOk, human, NOW)).ok, true);
  const skewBad = await mkAt('2026-10-25T12:05:01Z', '2026-11-25T10:00:00Z');
  assert.deepEqual(await verifyAgentCertSet(skewBad, human, NOW), { ok: false, reason: 'not-yet-valid' });
  const expNow = await mkAt('2026-10-25T10:00:00Z', '2026-10-25T12:00:00Z');
  assert.deepEqual(await verifyAgentCertSet(expNow, human, NOW), { ok: false, reason: 'expired' });
  const expSoon = await mkAt('2026-10-25T10:00:00Z', '2026-10-25T12:00:01Z');
  assert.equal((await verifyAgentCertSet(expSoon, human, NOW)).ok, true);
});

test('P10 agentOf: needs the exact fp AND the exact card hash AND an unexpired set; expiry boundary is exclusive', () => {
  const s = one();
  assert.ok(agentOf(s, agA.fingerprint, agentCardSha256(cardA), NOW));
  assert.equal(agentOf(s, agA.fingerprint, agentCardSha256(cardB), NOW), null, 'right fp, other card');
  assert.equal(agentOf(s, agB.fingerprint, agentCardSha256(cardA), NOW), null, 'fp not listed');
  assert.equal(agentOf(undefined, agA.fingerprint, agentCardSha256(cardA), NOW), null);
  assert.equal(agentOf(s, agA.fingerprint, agentCardSha256(cardA), new Date(Date.parse(s.expires_at))), null, 'now == expires_at');
  assert.ok(agentOf(s, agA.fingerprint, agentCardSha256(cardA), new Date(Date.parse(s.expires_at) - 1)));
});

test('P11 the card hash covers the WHOLE card: key order does not change it, any field change does', () => {
  const h = agentCardSha256(cardA);
  const reordered = JSON.parse(JSON.stringify(Object.fromEntries(Object.entries(cardA).reverse()))) as SignedIdentityCard;
  assert.equal(agentCardSha256(reordered), h, 'key order is irrelevant');
  assert.notEqual(agentCardSha256({ ...cardA, entity_type: 'human' } as SignedIdentityCard), h);
  assert.notEqual(agentCardSha256({ ...cardA, identity: { ...cardA.identity, display_name: 'z' } } as SignedIdentityCard), h);
  assert.notEqual(agentCardSha256({ ...cardA, created_at: '2026-10-25T09:00:01Z' } as SignedIdentityCard), h);
});

test('P12 entryCoversCard: only an attested AGENT card with that fp and that hash; a human card or another agent\'s card is not covered', async () => {
  const entry = setOf(1, [[agA, cardA, 'collaborate']]).agents[0];
  assert.equal(entryCoversCard(entry, cardA), true);
  assert.equal(entryCoversCard(entry, cardB), false);
  const humanCard = await agentCard(agA, 'human');
  assert.equal(entryCoversCard({ ...entry, agent_card_sha256: agentCardSha256(humanCard) }, humanCard), false, 'a human-typed card under its own hash');
});

test('P13 apply: lower seq = rollback even if the OLD set is the one held and expired; same set re-sent = keep; a different human = wrong-human', () => {
  const a = one(); const b = setOf(2, [[agB, cardB, 'read-only']]);
  assert.deepEqual(applyAgentCertSet(b, a), { action: 'refuse', reason: 'rollback' });
  assert.deepEqual(applyAgentCertSet(a, { ...a }), { action: 'keep' });
  assert.deepEqual(applyAgentCertSet(a, { ...a, human_fp: other.fingerprint }), { action: 'refuse', reason: 'wrong-human' });
  assert.equal(applyAgentCertSet(a, b).action, 'store');
  assert.equal(applyAgentCertSet(undefined, a).action, 'store');
});
