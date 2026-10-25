// #705 ORG-1 org v0 member list: each refusal on its own, plus the done_when cases (stale list, expiry → "no longer
// listed", removal reaching 3 holders, any org-signed object that isn't the member list → refused).
// APOLLO verifier probes for ORG-1 (not Flint's tests).
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


const one = () => listOf(1, [M1, M2]);
const iso = (ms: number) => new Date(ms).toISOString().replace('.000Z', 'Z');

test('O1 shape: impossible dates, fractions, space, lowercase z, offsets, seq edges, non-hex/short/uppercase/duplicate/unsorted members, extra/missing keys', () => {
  for (const bad of ['2026-02-30T10:00:00Z', '2026-10-25T10:00:00.123Z', '2026-10-25 10:00:00Z', '2026-10-25T10:00:00z', '2026-10-25T10:00:00+00:00', '']) {
    assert.equal(checkOrgMemberListShape({ ...one(), issued_at: bad }), 'shape', bad);
    assert.equal(checkOrgMemberListShape({ ...one(), expires_at: bad }), 'shape', bad);
  }
  for (const bad of [0, -1, 1.5, NaN, '1', 2 ** 53, null]) assert.equal(checkOrgMemberListShape({ ...one(), seq: bad as number }), 'shape', String(bad));
  assert.equal(checkOrgMemberListShape({ ...one(), seq: Number.MAX_SAFE_INTEGER }), null);
  for (const m of [['a'.repeat(63)], ['A'.repeat(64)], ['g'.repeat(64)], [M2, M1], [M1, M1], [5 as unknown as string], ['']]) assert.equal(checkOrgMemberListShape({ ...one(), members: m }), 'shape', JSON.stringify(m).slice(0, 30));
  const { v, ...noV } = one(); void v;
  assert.equal(checkOrgMemberListShape(noV), 'shape');
  assert.equal(checkOrgMemberListShape({ ...one(), extra: 1 }), 'shape');
  assert.equal(checkOrgMemberListShape({ ...one(), members: [] }), null, 'an empty list is a valid list');
  for (const bad of [null, undefined, [], 'x', 5]) assert.equal(checkOrgMemberListShape(bad), 'shape');
});

test('O2 constitution_ref: empty is fine, ANY non-empty string is refused as constitution (never ignored), a non-string is shape', () => {
  assert.equal(checkOrgMemberListShape(one()), null);
  for (const c of ['x', ' ', 'sha256:abc', '0']) assert.equal(checkOrgMemberListShape({ ...one(), constitution_ref: c }), 'constitution', c);
  for (const c of [null, 5, [], {}]) assert.equal(checkOrgMemberListShape({ ...one(), constitution_ref: c as unknown as string }), 'shape');
});

test('O3 lifetime and size boundaries: 400 d ok, +1 s lifetime, zero/negative lifetime; 256 members ok, 257 shape', () => {
  const t0 = Date.parse('2026-10-25T10:00:00Z');
  assert.equal(checkOrgMemberListShape({ ...one(), expires_at: iso(t0 + ORG_LIST_MAX_LIFETIME_MS) }), null);
  assert.equal(checkOrgMemberListShape({ ...one(), expires_at: iso(t0 + ORG_LIST_MAX_LIFETIME_MS + 1000) }), 'lifetime');
  assert.equal(checkOrgMemberListShape({ ...one(), expires_at: iso(t0) }), 'lifetime');
  const mk = (n: number) => Array.from({ length: n }, (_, i) => 'd'.repeat(32) + (i + 1).toString(16).padStart(32, '0'));
  assert.equal(checkOrgMemberListShape({ ...one(), members: mk(256) }), null);
  assert.equal(checkOrgMemberListShape({ ...one(), members: mk(257) }), 'shape');
});

test('O4 the verifier is bound to ONE org: another org\'s keys, a swapped public key, a swapped PQ key never verify', async () => {
  const s = await sign(one());
  assert.equal((await verifyOrgMemberList(s, org, NOW)).ok, true, 'control');
  assert.deepEqual(await verifyOrgMemberList(s, other, NOW), { ok: false, reason: 'wrong-org' });
  assert.deepEqual(await verifyOrgMemberList(s, { ...org, publicKey: other.publicKey }, NOW), { ok: false, reason: 'key-binding' });
  assert.equal((await verifyOrgMemberList(s, { ...org, sigPublicKeyB64: other.sigPublicKeyB64 }, NOW)).ok, false);
  assert.equal((await verifyOrgMemberList(s, { ...org, kemPublicKeyB64: other.kemPublicKeyB64 }, NOW)).ok, false);
  // the list text names ANOTHER org but is signed by this org's key
  const lie = await rawSign({ ...one(), org_fp: other.fingerprint });
  assert.equal((await verifyOrgMemberList(lie, org, NOW)).ok, false);
  assert.equal((await verifyOrgMemberList(lie, other, NOW)).ok, false, 'and it does not verify as the other org either (signed by the wrong key)');
});

test('O5 each signature half is bound; cross-domain replay and a tampered member never verify', async () => {
  const s = await sign(one());
  const alt = await signWithEnvelope(DOMAIN_ORG_MEMBER_LIST, orgMemberListSigningInput(one()) + ' ', org.privateKey, org.passphrase, org.sigSecretKey);
  assert.equal((await verifyOrgMemberList({ ...s, signature: alt.classical }, org, NOW)).ok, false);
  assert.equal((await verifyOrgMemberList({ ...s, pq_signature: alt.pq_signature! }, org, NOW)).ok, false);
  for (const d of [...OTHER_DOMAINS, 'svrnty:other:v9']) {
    assert.equal((await verifyOrgMemberList(await rawSign(one(), d), org, NOW)).ok, false, d);
  }
  assert.equal((await verifyOrgMemberList({ ...s, members: [M1, M3] }, org, NOW)).ok, false, 'tampered member');
  assert.equal((await verifyOrgMemberList({ ...s, seq: 2 }, org, NOW)).ok, false, 'tampered seq');
  assert.equal((await verifyOrgMemberList({ ...s, expires_at: '2027-10-25T10:00:00Z' }, org, NOW)).ok, false, 'extended expiry');
});

test('O6 signature fields: missing PQ, empty, wrong type, extra field, non-objects', async () => {
  const s = await sign(one());
  const { pq_signature, ...noPq } = s; void pq_signature;
  assert.deepEqual(await verifyOrgMemberList(noPq, org, NOW), { ok: false, reason: 'pq-missing' });
  assert.equal((await verifyOrgMemberList({ ...s, pq_signature: '' }, org, NOW)).ok, false);
  assert.equal((await verifyOrgMemberList({ ...s, signature: '' }, org, NOW)).ok, false);
  assert.equal((await verifyOrgMemberList({ ...s, signature: 5 }, org, NOW)).ok, false);
  assert.deepEqual(await verifyOrgMemberList({ ...s, extra: 1 }, org, NOW), { ok: false, reason: 'shape' });
  for (const bad of [null, undefined, 'x', 5, [], [s]]) assert.equal((await verifyOrgMemberList(bad, org, NOW)).ok, false);
});

test('O7 a list that claims a constitution is refused by the SIGNER and by the VERIFIER (raw-signed)', async () => {
  await assert.rejects(() => sign({ ...one(), constitution_ref: 'x' }));
  const raw = await rawSign({ ...one(), constitution_ref: 'x' });
  assert.deepEqual(await verifyOrgMemberList(raw, org, NOW), { ok: false, reason: 'constitution' });
  await assert.rejects(() => signOrgMemberList(one(), org.privateKey, org.passphrase, new Uint8Array(0)));
  await assert.rejects(() => sign({ ...one(), seq: 0 }));
});

test('O8 time edges: skew exactly ok / +1 s not-yet-valid; expires_at == now expired, +1 s ok', async () => {
  const mk = (i: string, e: string) => sign({ ...one(), issued_at: i, expires_at: e });
  assert.equal((await verifyOrgMemberList(await mk('2026-10-25T12:05:00Z', '2026-11-25T10:00:00Z'), org, NOW)).ok, true);
  assert.deepEqual(await verifyOrgMemberList(await mk('2026-10-25T12:05:01Z', '2026-11-25T10:00:00Z'), org, NOW), { ok: false, reason: 'not-yet-valid' });
  assert.deepEqual(await verifyOrgMemberList(await mk('2026-10-25T10:00:00Z', '2026-10-25T12:00:00Z'), org, NOW), { ok: false, reason: 'expired' });
  assert.equal((await verifyOrgMemberList(await mk('2026-10-25T10:00:00Z', '2026-10-25T12:00:01Z'), org, NOW)).ok, true);
});

test('O9 membershipOf: member while valid, list-expired at/after expiry (never "member", never a removal), nothing if unlisted/removed/undefined', () => {
  const l = one();
  assert.deepEqual(membershipOf(l, M1, NOW), { org_fp: org.fingerprint, status: 'member', as_of: l.issued_at });
  assert.equal(membershipOf(l, M3, NOW), null, 'not listed');
  assert.equal(membershipOf(undefined, M1, NOW), null);
  const exp = new Date(Date.parse(l.expires_at));
  assert.deepEqual(membershipOf(l, M1, exp), { org_fp: org.fingerprint, status: 'list-expired', as_of: l.expires_at }, 'at expiry');
  assert.equal(membershipOf(l, M1, new Date(exp.getTime() - 1))!.status, 'member', '1 ms before expiry');
  assert.equal(membershipOf(l, M1, new Date(exp.getTime() + 86400000))!.status, 'list-expired');
  assert.equal(membershipOf(l, M3, new Date(exp.getTime() + 86400000)), null, 'an unlisted card is never "list-expired"');
  for (const junk of ['', 'a', M1.toUpperCase(), M1 + 'x']) assert.equal(membershipOf(l, junk, NOW), null, junk);
});

test('O10 apply: higher seq stores, lower is rollback, same list keeps, a different list at the same seq is equivocation, another org is wrong-org, no held list stores; removal then replay never restores', () => {
  const a = one(); const b = listOf(2, [M2]);
  assert.equal(applyOrgMemberList(undefined, a).action, 'store');
  assert.equal(applyOrgMemberList(a, b).action, 'store');
  assert.deepEqual(applyOrgMemberList(b, a), { action: 'refuse', reason: 'rollback' });
  assert.deepEqual(applyOrgMemberList(a, { ...a }), { action: 'keep' });
  assert.deepEqual(applyOrgMemberList(a, listOf(1, [M3])), { action: 'refuse', reason: 'equivocation' });
  assert.deepEqual(applyOrgMemberList(a, { ...a, org_fp: other.fingerprint }), { action: 'refuse', reason: 'wrong-org' });
  // M1 removed in seq 2; a replay of seq 1 cannot bring it back
  let held: OrgMemberList | undefined = a;
  const r2 = applyOrgMemberList(held, b); if (r2.action === 'store') held = r2.list;
  assert.equal(membershipOf(held, M1, NOW), null);
  assert.equal(applyOrgMemberList(held, a).action, 'refuse');
  assert.equal(membershipOf(held, M1, NOW), null);
});
