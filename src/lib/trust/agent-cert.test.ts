// #705 INT-4 human-signed agent cert set: every refusal is tested on its own, plus the done_when cases
// (unknown/principal scope, expiry, monotonic seq, revocation reaching 3 holders, V4 domain separation).
// Run: npx tsx --test src/lib/trust/agent-cert.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { generatePQKeypairBundle, uint8ToBase64, base64ToUint8 } from '../crypto/pq';
import { mintCanonicalFingerprint } from '../identity/fingerprint';
import { signIdentityCard, type SignedIdentityCard } from '../identity/identity-card-sign';
import { signWithEnvelope, verifyWithEnvelope } from '../crypto/sign-envelope';
import { DOMAIN_AGENT_CERT_SET, DOMAIN_MUTUAL_VOUCH, DOMAIN_IDENTITY_CARD } from '../format/envelope';
import {
  agentCardSha256, agentCertSetSigningInput, agentOf, applyAgentCertSet, checkAgentCertSetShape,
  entryCoversCard, signAgentCertSet, verifyAgentCertSet,
  AGENT_CERT_MAX_LIFETIME_MS, type AgentCertSet, type HumanPublicKeys, type SignedAgentCertSet,
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
/** Sign WITHOUT the module's pre-sign checks, to prove the VERIFIER refuses what an attacker could still sign. */
async function rawSign(s: Record<string, unknown>, id: Id = human): Promise<Record<string, unknown>> {
  const sig = await signWithEnvelope(DOMAIN_AGENT_CERT_SET, agentCertSetSigningInput(s as unknown as AgentCertSet),
    id.privateKey, id.passphrase, id.sigSecretKey);
  return { ...s, signature: sig.classical, pq_signature: sig.pq_signature };
}

test('round trip: a hybrid set verifies, and agentOf shows exactly the listed agent with its card', async () => {
  const signed = await sign(setOf(1, [[agA, cardA, 'collaborate'], [agB, cardB, 'read-only']]));
  const r = await verifyAgentCertSet(signed, human, NOW);
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.deepEqual(agentOf(r.set, agA.fingerprint, agentCardSha256(cardA), NOW), { human_fp: human.fingerprint, scope: 'collaborate', seq: 1 });
  assert.equal(agentOf(r.set, agB.fingerprint, agentCardSha256(cardA), NOW), null, 'right fp, WRONG card → not shown');
  assert.equal(agentOf(r.set, other.fingerprint, agentCardSha256(cardA), NOW), null, 'unlisted agent → not shown');
});

test('V1: an unknown or principal-level scope is refused by the signer AND by the verifier', async () => {
  for (const scope of ['admin', 'act-as', 'principal', 'owner', 'Collaborate', '']) {
    const s = setOf(1, [[agA, cardA, scope]]);
    await assert.rejects(sign(s), /refused before signing: scope/, `signer must refuse scope ${JSON.stringify(scope)}`);
    const r = await verifyAgentCertSet(await rawSign(s as unknown as Record<string, unknown>), human, NOW);
    assert.deepEqual(r, { ok: false, reason: 'scope' }, `verifier must refuse a validly SIGNED scope ${JSON.stringify(scope)}`);
  }
});

test('time: expired, not-yet-valid and over-long sets are refused; an expired held set shows nobody', async () => {
  const exp = await sign(setOf(1, [[agA, cardA, 'collaborate']], { issued_at: '2026-09-01T00:00:00Z', expires_at: '2026-10-25T11:59:59Z' }));
  assert.deepEqual(await verifyAgentCertSet(exp, human, NOW), { ok: false, reason: 'expired' });
  const future = await sign(setOf(1, [[agA, cardA, 'collaborate']], { issued_at: '2026-10-25T12:10:00Z' }));
  assert.deepEqual(await verifyAgentCertSet(future, human, NOW), { ok: false, reason: 'not-yet-valid' });
  const longSet = setOf(1, [[agA, cardA, 'collaborate']], {
    issued_at: '2026-10-25T10:00:00Z', expires_at: new Date(Date.parse('2026-10-25T10:00:00Z') + AGENT_CERT_MAX_LIFETIME_MS + 1000).toISOString().replace('.000Z', 'Z'),
  });
  assert.equal(checkAgentCertSetShape(longSet), 'lifetime');
  const ok = await verifyAgentCertSet(await sign(setOf(1, [[agA, cardA, 'collaborate']])), human, NOW);
  assert.ok(ok.ok);
  if (ok.ok) assert.equal(agentOf(ok.set, agA.fingerprint, agentCardSha256(cardA), new Date('2026-11-25T10:00:00Z')), null, 'at expiry → not shown');
});

test('monotonic seq: lower = rollback, same seq different set = equivocation, same set = no-op', async () => {
  const v = async (s: SignedAgentCertSet) => { const r = await verifyAgentCertSet(s, human, NOW); assert.ok(r.ok); return (r as { ok: true; set: AgentCertSet }).set; };
  const s1 = await v(await sign(setOf(1, [[agA, cardA, 'collaborate'], [agB, cardB, 'collaborate']])));
  const s2 = await v(await sign(setOf(2, [[agA, cardA, 'collaborate']])));
  const s2b = await v(await sign(setOf(2, [[agB, cardB, 'collaborate']])));
  assert.deepEqual(applyAgentCertSet(undefined, s1), { action: 'store', set: s1 });
  assert.deepEqual(applyAgentCertSet(s1, s2), { action: 'store', set: s2 });
  assert.deepEqual(applyAgentCertSet(s2, s1), { action: 'refuse', reason: 'rollback' });
  assert.deepEqual(applyAgentCertSet(s2, s2b), { action: 'refuse', reason: 'equivocation' });
  const s2again = await v(await sign(setOf(2, [[agA, cardA, 'collaborate']]))); // re-signed: new signature bytes, same set
  assert.deepEqual(applyAgentCertSet(s2, s2again), { action: 'keep' });
});

test('V3 revocation reaches 3 holders: seq 2 drops agent B everywhere, and replaying seq 1 never brings B back', async () => {
  const seq1 = await sign(setOf(1, [[agA, cardA, 'collaborate'], [agB, cardB, 'collaborate']]));
  const seq2 = await sign(setOf(2, [[agA, cardA, 'collaborate']]));
  const holders: Array<AgentCertSet | undefined> = [undefined, undefined, undefined];
  const sync = async (i: number, wire: unknown) => {
    const r = await verifyAgentCertSet(wire, human, NOW);
    if (!r.ok) return r.reason;
    const d = applyAgentCertSet(holders[i], r.set);
    if (d.action === 'store') holders[i] = d.set;
    return d.action === 'refuse' ? d.reason : d.action;
  };
  for (let i = 0; i < 3; i++) assert.equal(await sync(i, seq1), 'store');
  for (let i = 0; i < 3; i++) assert.ok(agentOf(holders[i], agB.fingerprint, agentCardSha256(cardB), NOW), `holder ${i} shows B at seq 1`);
  for (let i = 0; i < 3; i++) assert.equal(await sync(i, seq2), 'store');
  for (let i = 0; i < 3; i++) {
    assert.equal(agentOf(holders[i], agB.fingerprint, agentCardSha256(cardB), NOW), null, `holder ${i}: B revoked`);
    assert.ok(agentOf(holders[i], agA.fingerprint, agentCardSha256(cardA), NOW), `holder ${i}: A still shown`);
    assert.equal(await sync(i, seq1), 'rollback', `holder ${i}: replayed seq 1 refused`);
    assert.equal(agentOf(holders[i], agB.fingerprint, agentCardSha256(cardB), NOW), null, `holder ${i}: B stays revoked`);
  }
});

test('signature binding: PQ leg stripped / swapped, tampered field, wrong human, broken key binding → refused', async () => {
  const signed = await sign(setOf(1, [[agA, cardA, 'collaborate']]));
  // eslint-disable-next-line @typescript-eslint/no-unused-vars -- dropping the field is the point
  const { pq_signature: _drop, ...noPq } = signed;
  assert.deepEqual(await verifyAgentCertSet(noPq, human, NOW), { ok: false, reason: 'pq-missing' });
  const otherSig = await sign({ ...setOf(1, [[agA, cardA, 'collaborate']]), human_fp: other.fingerprint }, other);
  assert.deepEqual(await verifyAgentCertSet({ ...signed, pq_signature: otherSig.pq_signature }, human, NOW), { ok: false, reason: 'signature' });
  assert.deepEqual(await verifyAgentCertSet({ ...signed, seq: 2 }, human, NOW), { ok: false, reason: 'signature' }, 'seq bumped after signing');
  assert.deepEqual(await verifyAgentCertSet({ ...signed, agents: [{ ...signed.agents[0], scope: 'read-only' }] }, human, NOW),
    { ok: false, reason: 'signature' }, 'scope changed after signing');
  assert.deepEqual(await verifyAgentCertSet(signed, other, NOW), { ok: false, reason: 'wrong-human' });
  assert.deepEqual(await verifyAgentCertSet(signed, { ...human, sigPublicKeyB64: other.sigPublicKeyB64 }, NOW),
    { ok: false, reason: 'key-binding' }, "a PQ key that isn't the human's fingerprint's");
  // the other human signs a set naming OUR human: the verifier holds our human's key, so it can't verify
  const forged = await rawSign(setOf(1, [[agA, cardA, 'collaborate']]) as unknown as Record<string, unknown>, other);
  assert.deepEqual(await verifyAgentCertSet(forged, human, NOW), { ok: false, reason: 'signature' });
});

test('V4 domain separation: a cert signature never verifies as a vouch or a card, and theirs never verifies as a cert', async () => {
  const signed = await sign(setOf(1, [[agA, cardA, 'collaborate']]));
  const input = agentCertSetSigningInput(signed);
  for (const d of [DOMAIN_MUTUAL_VOUCH, DOMAIN_IDENTITY_CARD]) {
    assert.equal(await verifyWithEnvelope(d, input, { classical: signed.signature, pq_signature: signed.pq_signature },
      human.publicKey, base64ToUint8(human.sigPublicKeyB64)), false, `cert signature must not verify under ${d}`);
    const foreign = await signWithEnvelope(d, input, human.privateKey, human.passphrase, human.sigSecretKey);
    assert.deepEqual(await verifyAgentCertSet({ ...signed, signature: foreign.classical, pq_signature: foreign.pq_signature }, human, NOW),
      { ok: false, reason: 'signature' }, `a ${d} signature over the same bytes must not verify as a cert`);
  }
});

test('shape: unknown keys, unsorted / duplicate agents, self-listing, bad seq, bad dates, too many → refused', () => {
  const base = setOf(1, [[agA, cardA, 'collaborate'], [agB, cardB, 'collaborate']]);
  assert.equal(checkAgentCertSetShape(base), null);
  assert.equal(checkAgentCertSetShape({ ...base, act_as: true }), 'shape');
  assert.equal(checkAgentCertSetShape({ ...base, agents: [{ ...base.agents[0], note: 'x' }] }), 'shape');
  assert.equal(checkAgentCertSetShape({ ...base, agents: [...base.agents].reverse() }), 'shape', 'unsorted');
  assert.equal(checkAgentCertSetShape({ ...base, agents: [base.agents[0], base.agents[0]] }), 'shape', 'duplicate fp');
  assert.equal(checkAgentCertSetShape({ ...base, agents: [{ ...base.agents[0], agent_fp: human.fingerprint }] }), 'self');
  for (const seq of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 2, '1']) assert.equal(checkAgentCertSetShape({ ...base, seq }), 'shape', `seq ${seq}`);
  for (const d of ['2026-10-25', '2026-10-25T10:00:00.000Z', '2026-02-30T10:00:00Z', '2026-10-25T10:00:00+00:00'])
    assert.equal(checkAgentCertSetShape({ ...base, issued_at: d }), 'shape', `date ${d}`);
  assert.equal(checkAgentCertSetShape({ ...base, human_fp: human.fingerprint.toUpperCase() }), 'shape', 'non-normalized fp');
  assert.equal(checkAgentCertSetShape({ ...base, v: 2 }), 'shape');
  const many = Array.from({ length: 65 }, (_, i) => ({ agent_card_sha256: i.toString(16).padStart(64, 'a'), agent_fp: i.toString(16).padStart(64, '0'), scope: 'collaborate' }));
  assert.equal(checkAgentCertSetShape({ ...base, agents: many }), 'shape', '> 64 agents');
});

test('entryCoversCard: only an attested AGENT card with that fp AND that exact hash', async () => {
  const s = setOf(1, [[agA, cardA, 'collaborate']]);
  assert.equal(entryCoversCard(s.agents[0], cardA), true);
  assert.equal(entryCoversCard(s.agents[0], await agentCard(agA, 'human')), false, 'self-attested human card');
  assert.equal(entryCoversCard(s.agents[0], await agentCard(agA, 'agent', 'renamed')), false, 'same fp, a different card');
  assert.equal(entryCoversCard(s.agents[0], cardB), false);
});

test('isolated refusals (each checked alone): same fp with two cards, a human card under its OWN hash, signer without the PQ key', async () => {
  const base = setOf(1, [[agA, cardA, 'collaborate']]);
  const otherCardSameFp = agentCardSha256(await agentCard(agA, 'agent', 'second'));
  assert.equal(checkAgentCertSetShape({ ...base, agents: [base.agents[0], { ...base.agents[0], agent_card_sha256: otherCardSameFp }] }),
    'shape', 'one agent fp listed twice with different cards');
  const humanCard = await agentCard(agA, 'human');
  assert.equal(entryCoversCard({ agent_card_sha256: agentCardSha256(humanCard), agent_fp: agA.fingerprint, scope: 'collaborate' }, humanCard),
    false, 'fp and hash both match, but the card attests "human": not an agent card');
  for (const k of [new Uint8Array(0), undefined as unknown as Uint8Array])
    await assert.rejects(signAgentCertSet(base, human.privateKey, human.passphrase, k), /PQ signing key is required/);
});

test('hygiene (Apollo A18): one card hash listed under two different fps is refused', () => {
  const base = setOf(1, [[agA, cardA, 'collaborate'], [agB, cardB, 'collaborate']]);
  assert.equal(checkAgentCertSetShape({ ...base, agents: [base.agents[0], { ...base.agents[1], agent_card_sha256: base.agents[0].agent_card_sha256 }] }), 'shape');
});
