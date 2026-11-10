// src/lib/trust/approve-wire.test.ts — task #810: the APPROVE record (D2 v1.6) bytes and gate.
// Run: npx tsx --test src/lib/trust/approve-wire.test.ts
// Real Ed25519 + ML-DSA-87 signatures and the real pointer v2 verifier. No network, no clock.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { LpParseError } from '../crypto/lp-reader';
import { ownerAuthorityCommitment } from '../crypto/owner-authority-commitment';
import { encodePointerV2, parsePointerV2, pointerV2Prefix, pointerV2SigningInput, type HybridSig, type PointerV2Fields } from './pointer-v2-wire';
import { pointerClaimDigest, digestOfPointer } from './claim-digest';
import {
  encodeApprove, parseApprove, approveBody, approveSigningInput, ApproveRefused, UnverifiedApprove,
  APPROVE_SUBJECT_MAX, type ApproveFields, type ApproveVerifyDeps,
} from './approve-wire';

const fill = (n: number, v: number) => new Uint8Array(n).fill(v);
const sign = (msg: Uint8Array, edSecret: Uint8Array, dsaSecret: Uint8Array): HybridSig => ({ ed: ed25519.sign(msg, edSecret), dsa: ml_dsa87.sign(msg, dsaSecret) });
const hex = (b: Uint8Array) => bytesToHex(b);

// ---------- known-answer vector (D2 v1.6): fixed bytes, does NOT verify ----------
const KAT_FIELDS: ApproveFields = { kind: 1, durableId: fill(32, 0x21), identityEpoch: 3, claimDigest: fill(32, 0x44), subject: fill(40, 0x55) };
const KAT_KEYS = { edPublic: fill(32, 0x66), dsaPublic: fill(2592, 0x77) };
const KAT_ID: HybridSig = { ed: fill(64, 0x88), dsa: fill(4627, 0x99) };
const KAT_AUTH: HybridSig = { ed: fill(64, 0xaa), dsa: fill(4627, 0xbb) };

test('A0 known-answer vector: the body, both signing inputs and the full record are exactly the bytes D2 v1.6 pins', () => {
  const body = approveBody(KAT_FIELDS);
  assert.equal(body.length, 77);
  assert.equal(hex(body), '01' + '21'.repeat(32) + '0000000000000003' + '00000020' + '44'.repeat(32));
  assert.equal(hex(sha256(approveSigningInput(body, 'identity'))), '44bde7d621d4b8456008a37defedd9120328993d991849044233e72db0aaf2f0');
  assert.equal(hex(sha256(approveSigningInput(body, 'authority'))), 'f932b8ec92420fcfe249b9cad010ab0413b028f8c246583c8570da26ffbafe3f');
  const rec = encodeApprove(KAT_FIELDS, KAT_KEYS, KAT_ID, KAT_AUTH);
  assert.equal(rec.length, 12130);
  assert.equal(hex(sha256(rec)), '10d67524fd624d2a9943a3b087b553dc4f18c53c48e3bd418c036c93474b4ecd');
  assert.equal(hex(rec.slice(0, 3)), '415001', "magic 'AP' and version 1");
  // byte-exact parse of the same record (it parses; it cannot verify)
  assert.ok(parseApprove(rec) instanceof UnverifiedApprove);
});

// ---------- strict parse ----------
test('A1 parse refuses every malformation with a stable reason, never partially', () => {
  const rec = encodeApprove(KAT_FIELDS, KAT_KEYS, KAT_ID, KAT_AUTH);
  const reason = (b: Uint8Array) => { try { parseApprove(b); return 'parsed'; } catch (e) { return e instanceof LpParseError ? e.reason : 'other'; } };
  const mut = (f: (b: Uint8Array) => void) => { const b = rec.slice(); f(b); return b; };
  assert.equal(reason(rec), 'parsed');
  assert.equal(reason(mut((b) => { b[0] = 0x41 ^ 1; })), 'bad-header', 'magic');
  assert.equal(reason(mut((b) => { b[2] = 2; })), 'bad-header', 'version');
  for (const kind of [0, 2, 3, 4, 255]) assert.equal(reason(mut((b) => { b[3] = kind; })), 'bad-field', 'kind ' + kind + ' (2 and 3 are reserved)');
  assert.equal(reason(Uint8Array.of(...rec, 0)), 'trailing-bytes');
  assert.equal(reason(rec.slice(0, rec.length - 1)), 'truncated');
  assert.equal(reason(new Uint8Array(0)), 'truncated');
  // the digest length prefix must say 32
  assert.equal(reason(mut((b) => { b[3 + 1 + 32 + 8 + 3] = 31; })), 'bad-field', 'LP(claim_digest) of 31 bytes');
  // the subject length prefix cannot exceed the cap
  const subjAt = 3 + 77;
  assert.equal(reason(mut((b) => new DataView(b.buffer).setUint32(subjAt, APPROVE_SUBJECT_MAX + 1, false))), 'length-over-max');
  assert.equal(APPROVE_SUBJECT_MAX, 32768, 'the cap D2 v1.6 names');
  assert.throws(() => encodeApprove({ ...KAT_FIELDS, subject: new Uint8Array(32769) }, KAT_KEYS, KAT_ID, KAT_AUTH), ApproveRefused);
  assert.equal(reason(mut((b) => new DataView(b.buffer).setUint32(subjAt, 32769, false))), 'length-over-max');
  assert.equal(encodeApprove({ ...KAT_FIELDS, subject: new Uint8Array(APPROVE_SUBJECT_MAX) }, KAT_KEYS, KAT_ID, KAT_AUTH).length, 12130 - 40 + APPROVE_SUBJECT_MAX);
  for (const bad of [0, 2, 3, 4]) assert.throws(() => encodeApprove({ ...KAT_FIELDS, kind: bad }, KAT_KEYS, KAT_ID, KAT_AUTH), (e: unknown) => e instanceof ApproveRefused && e.reason === 'bad-kind');
});

test('A2 the parsed object exposes nothing before verify', () => {
  const u = parseApprove(encodeApprove(KAT_FIELDS, KAT_KEYS, KAT_ID, KAT_AUTH));
  assert.deepEqual(Object.keys(u), []);
  assert.equal(JSON.stringify(u), '{}');
  assert.deepEqual(Object.getOwnPropertyNames(Object.getPrototypeOf(u)).sort(), ['constructor', 'verify']);
});

// ---------- fixtures: a real world to verify against ----------
function world(identityEpoch = 3) {
  const id = { edSecret: randomBytes(32), dsa: ml_dsa87.keygen(randomBytes(32)) };
  const au = { edSecret: randomBytes(32), dsa: ml_dsa87.keygen(randomBytes(32)) };
  const authorityKeys = { edPublic: ed25519.getPublicKey(au.edSecret), dsaPublic: au.dsa.publicKey };
  const durable = sha256(randomBytes(8));
  const held: ApproveVerifyDeps['held'] = {
    durableId: hex(durable), identityEpoch,
    identityKeys: { edPublic: ed25519.getPublicKey(id.edSecret), dsaPublic: id.dsa.publicKey },
    ownerAuthorityPin: ownerAuthorityCommitment(authorityKeys.edPublic, authorityKeys.dsaPublic),
  };
  const pointer = (o: { epoch?: number; relay?: string; authority?: boolean; identityEpoch?: number } = {}) => {
    const f: PointerV2Fields = { mailboxId: fill(32, 0x11), relay: o.relay ?? 'https://other.example.net', identityEpoch: o.identityEpoch ?? identityEpoch, pointerEpoch: o.epoch ?? 12,
      x25519Pub: fill(32, 0x22), mlkem1024Ek: fill(1568, 0x33), hasAuthority: o.authority ?? true };
    const prefix = pointerV2Prefix(f);
    const idSig = sign(pointerV2SigningInput(prefix, false), id.edSecret, id.dsa.secretKey);
    const authority = f.hasAuthority ? { ...authorityKeys, sig: sign(pointerV2SigningInput(prefix, true), au.edSecret, au.dsa.secretKey) } : undefined;
    return encodePointerV2(f, idSig, authority);
  };
  const digestOf = (subject: Uint8Array) => pointerClaimDigest(parsePointerV2(subject).verify({ identity: held.identityKeys, authorityPin: held.ownerAuthorityPin }));
  const record = (o: { subject?: Uint8Array; durable?: Uint8Array; epoch?: number; digest?: Uint8Array; idSigner?: typeof id; authSigner?: typeof au; keys?: typeof authorityKeys } = {}) => {
    const subject = o.subject ?? pointer();
    const f: ApproveFields = { kind: 1, durableId: o.durable ?? durable, identityEpoch: o.epoch ?? identityEpoch, claimDigest: o.digest ?? digestOf(subject), subject };
    const body = approveBody(f);
    const is = o.idSigner ?? id, as = o.authSigner ?? au;
    return encodeApprove(f, o.keys ?? authorityKeys, sign(approveSigningInput(body, 'identity'), is.edSecret, is.dsa.secretKey), sign(approveSigningInput(body, 'authority'), as.edSecret, as.dsa.secretKey));
  };
  return { id, au, authorityKeys, durable, held, pointer, digestOf, record };
}
const refusal = (bytes: Uint8Array, deps: ApproveVerifyDeps) => { try { parseApprove(bytes).verify(deps); return 'accepted'; } catch (e) { return e instanceof ApproveRefused ? e.reason : e instanceof LpParseError ? 'parse:' + e.reason : 'other'; } };

// ---------- verification is a real gate ----------
test('A3 a real record verifies and returns exactly what it names; the digest is the one pending and conflicts use', () => {
  const w = world();
  const subject = w.pointer();
  const v = parseApprove(w.record({ subject })).verify({ held: w.held });
  assert.equal(v.kind, 1);
  assert.equal(v.durableId, w.held.durableId);
  assert.equal(v.identityEpoch, 3);
  assert.equal(v.pointer.authoritySigned, true);
  assert.equal(v.pointer.relay, 'https://other.example.net');
  assert.equal(v.claimDigest, digestOfPointer(parsePointerV2(subject).verify({ identity: w.held.identityKeys, authorityPin: w.held.ownerAuthorityPin })), 'the one shared helper');
  assert.ok(Object.isFrozen(v));
});

test('A3b the claim digest is SHA-256 of the pointer\'s signed prefix, computed here independently of the helper (D2 v1.6)', () => {
  const w = world();
  const f: PointerV2Fields = { mailboxId: fill(32, 0x11), relay: 'https://other.example.net', identityEpoch: 3, pointerEpoch: 12, x25519Pub: fill(32, 0x22), mlkem1024Ek: fill(1568, 0x33), hasAuthority: true };
  const subject = w.pointer({ relay: 'https://other.example.net', epoch: 12 });
  assert.equal(hex(w.digestOf(subject)), hex(sha256(pointerV2Prefix(f))));
  assert.equal(hex(w.digestOf(w.pointer({ relay: 'https://other.example.net', epoch: 12, authority: false }))), hex(sha256(pointerV2Prefix({ ...f, hasAuthority: false }))), 'the authority flag is part of the signed claim');
});

test('A4 either half of either signature wrong, alone, refuses it with no fallback', () => {
  const w = world();
  const rec = w.record();
  const subjLen = w.pointer().length;
  const authKeysAt = 3 + 77 + 4 + subjLen;
  const idSigAt = authKeysAt + 32 + 2592;
  const authSigAt = idSigAt + 64 + 4627;
  const flip = (at: number) => { const b = rec.slice(); b[at] ^= 1; return b; };
  assert.equal(refusal(rec, { held: w.held }), 'accepted');
  assert.equal(refusal(flip(idSigAt + 3), { held: w.held }), 'bad-identity-sig', 'identity, Ed25519 half');
  assert.equal(refusal(flip(idSigAt + 64 + 100), { held: w.held }), 'bad-identity-sig', 'identity, ML-DSA half');
  assert.equal(refusal(flip(authSigAt + 3), { held: w.held }), 'bad-authority-sig', 'authority, Ed25519 half');
  assert.equal(refusal(flip(authSigAt + 64 + 100), { held: w.held }), 'bad-authority-sig', 'authority, ML-DSA half');
  // the body is signed: flipping the epoch or the digest or the kind byte breaks the signatures (or an earlier check)
  assert.notEqual(refusal(flip(3 + 1 + 32 + 7), { held: w.held }), 'accepted', 'identity_epoch flipped');
  assert.equal(refusal(flip(3 + 1 + 32 + 8 + 4 + 5), { held: w.held }), 'bad-identity-sig', 'claim_digest flipped');
  // stubs: both halves are required and the cheap half runs first
  let dsaCalls = 0;
  const stub = (ed: boolean, dsa: boolean) => ({ edVerify: () => ed, dsaVerify: () => { dsaCalls++; return dsa; } });
  assert.equal(refusal(rec, { held: w.held, verifiers: stub(true, true) }), 'accepted');
  dsaCalls = 0;
  assert.equal(refusal(rec, { held: w.held, verifiers: stub(false, true) }), 'bad-identity-sig');
  assert.equal(dsaCalls, 0, 'a failed Ed25519 half never reaches the ML-DSA half');
  assert.equal(refusal(rec, { held: w.held, verifiers: stub(true, false) }), 'bad-identity-sig');
  assert.equal(refusal(rec, { held: w.held, verifiers: { edVerify: () => { throw new Error('x'); }, dsaVerify: () => true } }), 'bad-identity-sig', 'a throwing primitive is a refusal');
});

test('A5 the identity signature is checked against the HELD keys, never keys carried in the record', () => {
  const w = world();
  const attacker = { edSecret: randomBytes(32), dsa: ml_dsa87.keygen(randomBytes(32)) };
  assert.equal(refusal(w.record({ idSigner: attacker }), { held: w.held }), 'bad-identity-sig');
});

test('A6 the authority keys must open the held pin; a pre-feature identity (no pin) can approve nothing', () => {
  const w = world();
  const other = { edSecret: randomBytes(32), dsa: ml_dsa87.keygen(randomBytes(32)) };
  const otherKeys = { edPublic: ed25519.getPublicKey(other.edSecret), dsaPublic: other.dsa.publicKey };
  assert.equal(refusal(w.record({ authSigner: other, keys: otherKeys }), { held: w.held }), 'authority-pin-mismatch', 'a self-consistent record under a different authority');
  assert.equal(refusal(w.record(), { held: { ...w.held, ownerAuthorityPin: undefined } }), 'no-authority-pin');
  assert.equal(refusal(w.record(), { held: { ...w.held, ownerAuthorityPin: 'AB'.repeat(32) } }), 'no-authority-pin', 'the pin is lower-case hex only');
  assert.equal(refusal(w.record({ authSigner: other }), { held: w.held }), 'bad-authority-sig', 'the right keys with a signature from another secret');
});

test('A7 durable id and epoch against what is held: wrong id refused; lower refused; higher refused (the caller writes nothing)', () => {
  const w = world();
  assert.equal(refusal(w.record({ durable: sha256(randomBytes(4)) }), { held: w.held }), 'wrong-durable-id');
  assert.equal(refusal(w.record(), { held: { ...w.held, identityEpoch: 4 } }), 'stale-identity-epoch');
  assert.equal(refusal(w.record(), { held: { ...w.held, identityEpoch: 2 } }), 'identity-epoch-ahead');
  assert.equal(refusal(w.record(), { held: { ...w.held, durableId: 'nope' } }), 'bad-held');
});

test('A8 the subject: an identity-only pointer is never approved; junk is refused; a different identity epoch is refused; the digest must match', () => {
  const w = world();
  const idOnly = w.pointer({ authority: false });
  assert.equal(refusal(w.record({ subject: idOnly }), { held: w.held }), 'subject-not-authority-signed');
  assert.equal(refusal(w.record({ subject: fill(40, 0x55), digest: fill(32, 1) }), { held: w.held }), 'bad-subject');
  const otherEpoch = w.pointer({ identityEpoch: 2 });
  assert.equal(refusal(w.record({ subject: otherEpoch }), { held: w.held }), 'subject-epoch-mismatch');
  const wrongDigest = w.record({ digest: sha256(randomBytes(4)) });
  assert.equal(refusal(wrongDigest, { held: w.held }), 'claim-digest-mismatch');
  // a subject signed by someone else does not verify as a pointer
  const evil = world();
  assert.equal(refusal(w.record({ subject: evil.pointer() , digest: fill(32, 1) }), { held: w.held }), 'bad-subject');
});

test('A9 the same claim re-signed (new ML-DSA signature bytes) is the SAME approved claim: the digest still matches', () => {
  const w = world();
  const a = w.pointer(), b = w.pointer();
  assert.notDeepEqual(Array.from(a), Array.from(b), 'the pointer bytes really differ');
  assert.deepEqual(Array.from(w.digestOf(a)), Array.from(w.digestOf(b)));
  assert.equal(refusal(w.record({ subject: b, digest: w.digestOf(a) }), { held: w.held }), 'accepted');
});

test('A10 a refusal carries a reason code and never any part of the input', () => {
  const w = world();
  const junk = new TextEncoder().encode('MARKER-ATTACKER-STRING');
  try { parseApprove(junk); assert.fail('parsed'); } catch (e) { assert.ok(!String((e as Error).message).includes('MARKER')); }
  try { parseApprove(w.record({ digest: sha256(randomBytes(4)) })).verify({ held: w.held }); assert.fail('verified'); } catch (e) {
    assert.ok(e instanceof ApproveRefused); assert.ok(!String((e as Error).message).includes('MARKER'));
  }
});

// ---------- the module is pure and dark ----------
test('A11 pure: no clock, randomness, storage or network; imports only the codecs, the pin helper, the digest helper and the primitives', () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'approve-wire.ts'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  for (const bad of ['Date.now', 'new Date', 'Math.random', 'getRandomValues', 'randomBytes', 'fetch(', 'indexedDB', 'localStorage', 'process.', 'setTimeout', 'require(', 'readFileSync']) assert.ok(!src.includes(bad), 'must not use ' + bad);
  const imports = [...src.matchAll(/from '([^']+)'/g)].map((m) => m[1]).sort();
  assert.deepEqual(imports, ['../crypto/lp-reader', '../crypto/lp-tlv', '../crypto/owner-authority-commitment', './claim-digest', './pointer-v2-wire', '@noble/curves/ed25519.js', '@noble/hashes/utils.js', '@noble/post-quantum/ml-dsa.js']);
});

test('A12 dark: nothing outside tests imports approve-wire', () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
  const hits: string[] = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      if (n === 'node_modules' || n === '.next' || n === '.git') continue;
      const p = join(d, n); const st = statSync(p);
      if (st.isDirectory()) { walk(p); continue; }
      if (!/\.(ts|tsx|mjs|js)$/.test(n) || /\.test\.|\.spec\./.test(n) || p.endsWith('/src/lib/trust/approve-wire.ts') || p.endsWith('/src/lib/trust/rotation-receive.ts')) continue; // rotation-receive is the one consumer, itself guarded dark by its own test
      if (/from ['"][^'"]*approve-wire['"]/.test(readFileSync(p, 'utf8'))) hits.push(p);
    }
  };
  for (const d of ['src', 'app', 'scripts']) { try { walk(join(root, d)); } catch { /* absent */ } }
  assert.deepEqual(hits, []);
});
