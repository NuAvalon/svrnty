// #705 ORG-1 org v0 member list: each refusal on its own, plus the done_when cases (stale list, expiry → "no longer
// listed", removal reaching 3 holders, any org-signed object that isn't the member list → refused).
// Run: npx tsx --test src/lib/trust/org-list.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { generatePQKeypairBundle, uint8ToBase64, base64ToUint8 } from '../crypto/pq';
import { mintCanonicalFingerprint } from '../identity/fingerprint';
import { signWithEnvelope, verifyWithEnvelope } from '../crypto/sign-envelope';
import { DOMAIN_ORG_MEMBER_LIST, DOMAIN_MUTUAL_VOUCH, DOMAIN_IDENTITY_CARD, DOMAIN_JOINER_RESPONSE } from '../format/envelope';
// INT-4's tag, as a literal: this branch is cut from dev without INT-4, and an undefined import would silently fall back.
const DOMAIN_AGENT_CERT_SET = 'svrnty:agent-cert-set:v1';
const OTHER_DOMAINS = [DOMAIN_AGENT_CERT_SET, DOMAIN_MUTUAL_VOUCH, DOMAIN_IDENTITY_CARD, DOMAIN_JOINER_RESPONSE];
import {
  applyOrgMemberList, checkOrgMemberListShape, membershipOf, orgMemberListSigningInput, signOrgMemberList,
  verifyOrgMemberList, ORG_LIST_MAX_LIFETIME_MS, type OrgMemberList, type OrgPublicKeys,
} from './org-list';

interface Id extends OrgPublicKeys { privateKey: string; passphrase: string; sigSecretKey: Uint8Array }

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

const NOW = new Date('2026-10-25T12:00:00Z');
const M1 = 'a'.repeat(64), M2 = 'b'.repeat(64), M3 = 'c'.repeat(64);
let org: Id, other: Id;
before(async () => { [org, other] = await Promise.all([makeId('org'), makeId('other')]); });

const listOf = (seq: number, members: string[], o: Partial<OrgMemberList> = {}): OrgMemberList => ({
  v: 1, org_fp: org.fingerprint, seq, issued_at: '2026-10-25T10:00:00Z', expires_at: '2026-11-25T10:00:00Z',
  members: [...members].sort(), constitution_ref: '', ...o,
});
const sign = (l: OrgMemberList, id: Id = org) => signOrgMemberList(l, id.privateKey, id.passphrase, id.sigSecretKey);
async function rawSign(l: Record<string, unknown>, domain = DOMAIN_ORG_MEMBER_LIST, id: Id = org): Promise<Record<string, unknown>> {
  assert.equal(typeof domain, 'string', 'a domain tag must be a real string (never an undefined import)');
  const sig = await signWithEnvelope(domain, orgMemberListSigningInput(l as unknown as OrgMemberList), id.privateKey, id.passphrase, id.sigSecretKey);
  return { ...l, signature: sig.classical, pq_signature: sig.pq_signature };
}

test('round trip: a hybrid list verifies; a listed card shows "member as of issued_at"; an unlisted one shows nothing', async () => {
  const r = await verifyOrgMemberList(await sign(listOf(1, [M1, M2])), org, NOW);
  assert.ok(r.ok);
  if (!r.ok) return;
  assert.deepEqual(membershipOf(r.list, M1, NOW), { org_fp: org.fingerprint, status: 'member', as_of: '2026-10-25T10:00:00Z' });
  assert.equal(membershipOf(r.list, M3, NOW), null);
});

test('ORG-2 reserve: a non-empty constitution_ref is refused by the signer AND the verifier (never silently ignored)', async () => {
  const l = listOf(1, [M1], { constitution_ref: 'sha256:' + 'a'.repeat(64) });
  await assert.rejects(sign(l), /refused before signing: constitution/);
  assert.deepEqual(await verifyOrgMemberList(await rawSign(l as unknown as Record<string, unknown>), org, NOW), { ok: false, reason: 'constitution' });
  const { constitution_ref: _c, ...missing } = listOf(1, [M1]);
  assert.equal(checkOrgMemberListShape(missing), 'shape', 'the field is required, so v0 and ORG-2 lists never look alike');
});

test('stale list: lower seq = rollback; same seq different members = equivocation; same list = no-op', async () => {
  const v = async (l: OrgMemberList) => { const r = await verifyOrgMemberList(await sign(l), org, NOW); assert.ok(r.ok); return (r as { ok: true; list: OrgMemberList }).list; };
  const l1 = await v(listOf(1, [M1, M2])), l2 = await v(listOf(2, [M1])), l2b = await v(listOf(2, [M2]));
  assert.deepEqual(applyOrgMemberList(undefined, l1), { action: 'store', list: l1 });
  assert.deepEqual(applyOrgMemberList(l1, l2), { action: 'store', list: l2 });
  assert.deepEqual(applyOrgMemberList(l2, l1), { action: 'refuse', reason: 'rollback' });
  assert.deepEqual(applyOrgMemberList(l2, l2b), { action: 'refuse', reason: 'equivocation' });
  assert.deepEqual(applyOrgMemberList(l2, await v(listOf(2, [M1]))), { action: 'keep' });
});

test('expiry: an expired incoming list is refused; a HELD list that expires shows "list expired" (cannot confirm, NOT removed), never "member"', async () => {
  const exp = await sign(listOf(1, [M1], { issued_at: '2026-09-01T00:00:00Z', expires_at: '2026-10-25T11:00:00Z' }));
  assert.deepEqual(await verifyOrgMemberList(exp, org, NOW), { ok: false, reason: 'expired' });
  assert.deepEqual(await verifyOrgMemberList(await sign(listOf(1, [M1], { issued_at: '2026-10-25T12:10:00Z' })), org, NOW),
    { ok: false, reason: 'not-yet-valid' });
  const long = listOf(1, [M1], { expires_at: new Date(Date.parse('2026-10-25T10:00:00Z') + ORG_LIST_MAX_LIFETIME_MS + 1000).toISOString().replace('.000Z', 'Z') });
  assert.equal(checkOrgMemberListShape(long), 'lifetime');
  const r = await verifyOrgMemberList(await sign(listOf(1, [M1])), org, NOW);
  assert.ok(r.ok);
  if (r.ok) assert.deepEqual(membershipOf(r.list, M1, new Date('2026-11-26T00:00:00Z')),
    { org_fp: org.fingerprint, status: 'list-expired', as_of: '2026-11-25T10:00:00Z' });
});

test('removal reaches 3 holders: seq 2 drops M2 everywhere; replaying seq 1 never brings it back', async () => {
  const s1 = await sign(listOf(1, [M1, M2])), s2 = await sign(listOf(2, [M1]));
  const held: Array<OrgMemberList | undefined> = [undefined, undefined, undefined];
  const sync = async (i: number, wire: unknown) => {
    const r = await verifyOrgMemberList(wire, org, NOW);
    if (!r.ok) return r.reason;
    const d = applyOrgMemberList(held[i], r.list);
    if (d.action === 'store') held[i] = d.list;
    return d.action === 'refuse' ? d.reason : d.action;
  };
  for (let i = 0; i < 3; i++) assert.equal(await sync(i, s1), 'store');
  for (let i = 0; i < 3; i++) assert.equal(membershipOf(held[i], M2, NOW)?.status, 'member');
  for (let i = 0; i < 3; i++) assert.equal(await sync(i, s2), 'store');
  for (let i = 0; i < 3; i++) {
    assert.equal(membershipOf(held[i], M2, NOW), null, `holder ${i}: M2 removed`);
    assert.equal(membershipOf(held[i], M1, NOW)?.status, 'member', `holder ${i}: M1 kept`);
    assert.equal(await sync(i, s1), 'rollback');
    assert.equal(membershipOf(held[i], M2, NOW), null, `holder ${i}: M2 stays removed`);
  }
});

test('an org-signed object that is not the member list is refused, and a list signature verifies under no other domain', async () => {
  // (a) the org key signs a cert-set-shaped object: the member-list verifier refuses it on shape, before any signature
  const certShaped = { v: 1, human_fp: org.fingerprint, seq: 1, issued_at: '2026-10-25T10:00:00Z', expires_at: '2026-11-25T10:00:00Z', agents: [] };
  const sig = await signWithEnvelope(DOMAIN_AGENT_CERT_SET, JSON.stringify(certShaped), org.privateKey, org.passphrase, org.sigSecretKey);
  assert.deepEqual(await verifyOrgMemberList({ ...certShaped, signature: sig.classical, pq_signature: sig.pq_signature }, org, NOW), { ok: false, reason: 'shape' });
  // (b) the org key signs the exact list bytes under another domain: refused
  const l = listOf(1, [M1]);
  for (const d of OTHER_DOMAINS) {
    assert.ok(typeof d === 'string' && d.startsWith('svrnty:') && d !== DOMAIN_ORG_MEMBER_LIST, `bad test domain ${d}`);
    assert.deepEqual(await verifyOrgMemberList(await rawSign(l as unknown as Record<string, unknown>, d), org, NOW), { ok: false, reason: 'signature' }, d);
  }
  // (c) a real list signature does not verify under any other domain
  const signed = await sign(l);
  for (const d of OTHER_DOMAINS) {
    assert.equal(await verifyWithEnvelope(d, orgMemberListSigningInput(signed), { classical: signed.signature, pq_signature: signed.pq_signature },
      org.publicKey, base64ToUint8(org.sigPublicKeyB64)), false, d);
  }
});

test('signature binding: PQ stripped, member added after signing, wrong org, wrong PQ key, another org\'s key → refused', async () => {
  const signed = await sign(listOf(1, [M1]));
  const { pq_signature: _d, ...noPq } = signed;
  assert.deepEqual(await verifyOrgMemberList(noPq, org, NOW), { ok: false, reason: 'pq-missing' });
  assert.deepEqual(await verifyOrgMemberList({ ...signed, members: [M1, M2] }, org, NOW), { ok: false, reason: 'signature' });
  assert.deepEqual(await verifyOrgMemberList(signed, other, NOW), { ok: false, reason: 'wrong-org' });
  assert.deepEqual(await verifyOrgMemberList(signed, { ...org, sigPublicKeyB64: other.sigPublicKeyB64 }, NOW), { ok: false, reason: 'key-binding' });
  assert.deepEqual(await verifyOrgMemberList(await rawSign(listOf(1, [M1]) as unknown as Record<string, unknown>, DOMAIN_ORG_MEMBER_LIST, other), org, NOW),
    { ok: false, reason: 'signature' }, 'another key signing a list that names our org');
  for (const k of [new Uint8Array(0), undefined as unknown as Uint8Array])
    await assert.rejects(signOrgMemberList(listOf(1, [M1]), org.privateKey, org.passphrase, k), /PQ signing key is required/);
});

test('shape: unknown key, unsorted / duplicate / non-hex members, too many, bad seq/dates/version', () => {
  const b = listOf(1, [M1, M2]);
  assert.equal(checkOrgMemberListShape(b), null);
  assert.equal(checkOrgMemberListShape({ ...b, can_vouch: true }), 'shape', 'no capability field can ride along');
  assert.equal(checkOrgMemberListShape({ ...b, members: [M2, M1] }), 'shape', 'unsorted');
  assert.equal(checkOrgMemberListShape({ ...b, members: [M1, M1] }), 'shape', 'duplicate');
  assert.equal(checkOrgMemberListShape({ ...b, members: [M1.toUpperCase()] }), 'shape', 'non-normalized');
  assert.equal(checkOrgMemberListShape({ ...b, members: Array.from({ length: 257 }, (_, i) => i.toString(16).padStart(64, '0')) }), 'shape');
  for (const seq of [0, 1.5, '1']) assert.equal(checkOrgMemberListShape({ ...b, seq }), 'shape');
  assert.equal(checkOrgMemberListShape({ ...b, issued_at: '2026-10-25T10:00:00.000Z' }), 'shape');
  assert.equal(checkOrgMemberListShape({ ...b, v: 2 }), 'shape');
});
