// src/lib/relay/mailbox-auth-v2.test.ts
// #721 I1 (D1 + D2): the v2 mailbox id comes from a random hybrid AUTH key, and owner poll/ack carries no fingerprint, identity key or
// identity signature. Drives the REAL queue + ack routes over the real (in-memory) store. done_when 1, 3, 10 (Flint design v2 a494590d).
//
// Run: npx tsx --test src/lib/relay/mailbox-auth-v2.test.ts

process.env.RELAY_DB_PATH = ':memory:';
import { test, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToHex, concatBytes, randomBytes } from '@noble/hashes/utils.js';
import { canonicalize } from '@/lib/format/canonical';
import { lpStr } from '@/lib/crypto/lp-tlv';
import { generateKey } from 'openpgp';
import { generatePQKeypairBundle, uint8ToBase64 } from '@/lib/crypto/pq';
import { buildSignedMailboxPointer, verifyMailboxPointer } from '@/lib/crypto/mailbox-pointer';
import { depositEnvelope, pollMailbox, resetMailboxStore } from './mailbox-store';
import { deriveMailboxId, signMailboxPollRequest, OWNER_AUTH_HEADER } from './mailbox-auth';
import {
  deriveMailboxIdV2,
  generateMailboxAuthKeypair,
  isMailboxIdV2,
  signOwnerRequestV2,
  OWNER_AUTH_V2_HEADER,
  DOMAIN_MAILBOX_OWNER_V2,
  verifyOwnerRequestV2,
  ownerSignedMessageV2,
  type MailboxAuthKeypair,
} from './mailbox-auth-v2';

let A: MailboxAuthKeypair;
let B: MailboxAuthKeypair;
before(() => {
  A = generateMailboxAuthKeypair();
  B = generateMailboxAuthKeypair();
});
beforeEach(() => {
  resetMailboxStore();
  delete process.env.INVITE_REQUIRED;
});

const decode = (h: string) => JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
const encode = (o: unknown) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');

async function poll(mailboxId: string, headers: Record<string, string>) {
  const { GET } = await import('../../../app/api/relay/queue/route');
  const res = await GET(new Request(`http://r.test/api/relay/queue?mailbox_id=${encodeURIComponent(mailboxId)}`, { headers }));
  return { status: res.status, body: await res.json() };
}
async function ack(mailboxId: string, envelopeIds: string[], headers: Record<string, string>) {
  const { POST } = await import('../../../app/api/relay/ack/route');
  const res = await POST(
    new Request('http://r.test/api/relay/ack', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify({ mailbox_id: mailboxId, envelope_ids: envelopeIds }),
    }),
  );
  return { status: res.status, body: await res.json() };
}
const pollHeaders = (k: MailboxAuthKeypair, now = Date.now()) => signOwnerRequestV2({ keypair: k, op: 'poll', now }).headers;

// ---- D1: the id

test('D1: mbx2_ id is deterministic per auth key, distinct across keys, and in the v2 namespace only', () => {
  const id = deriveMailboxIdV2(A);
  assert.match(id, /^mbx2_[0-9a-f]{64}$/);
  assert.equal(deriveMailboxIdV2({ edPublicKey: A.edPublicKey, dsaPublicKey: A.dsaPublicKey }), id);
  assert.notEqual(deriveMailboxIdV2(B), id);
  assert.equal(isMailboxIdV2(id), true);
  assert.equal(isMailboxIdV2('mbx_' + id.slice(5)), false, 'a v1-shaped id is never treated as v2');
  assert.throws(() => deriveMailboxIdV2({ edPublicKey: A.edPublicKey.slice(1), dsaPublicKey: A.dsaPublicKey }));
});

// ---- KNOWN-ANSWER vectors (Flint #2189 condition). Expected values computed INDEPENDENTLY in Python (hashlib + struct + json sort_keys)
// from the public-key bytes, not by this module. Every other reader (Python cells, the Weft) must reproduce them: a drift there means
// polling the wrong mailbox, which is silent loss.

const KAT_ED_PUB = 'd04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737'; // ed25519.getPublicKey(32 x 0x11)
const KAT_DSA_PUB_SHA256 = '80d5337fba46deb2112b8e3b3ea453e446bfcd311f4bf2bb79fdeb2aff45165d'; // ml_dsa87.keygen(32 x 0x22).publicKey
const KAT_ID = 'mbx2_49ff5d1d47e8bdb98c1f6ddc460a55fe859e6c73f6b574b56f0a3969090f5273';
const KAT_POLL_MSG =
  '000000177376726e74793a6d61696c626f782d6f776e65723a763200000004706f6c6c000000947b226d61696c626f785f6964223a226d6278325f343966663564' +
  '31643437653862646239386331663664646334363061353566653835396536633733663662353734623536663061333936393039306635323733222c226e6f6e6365' +
  '223a223030303130323033303430353036303730383039306130623063306430653066222c227473223a313730303030303030303030307d';
const KAT_ACK_MSG_SHA256 = '24367197ff0c96350c6a2e37eafe23231d714897652b23e67b6c354beed46009'; // envelope_ids ['e1','e2'], 213 bytes

function katKeys() {
  const edPublicKey = ed25519.getPublicKey(new Uint8Array(32).fill(0x11));
  const dsaPublicKey = ml_dsa87.keygen(new Uint8Array(32).fill(0x22)).publicKey;
  return { edPublicKey, dsaPublicKey };
}

test('KAT: fixed keys -> the exact mbx2_ id (pins the domain tag, LP framing, field order, hash and hex)', async () => {
  const { sha256 } = await import('@noble/hashes/sha2.js');
  const k = katKeys();
  assert.equal(bytesToHex(k.edPublicKey), KAT_ED_PUB, 'Ed25519 keygen from the seed (RFC 8032)');
  assert.equal(bytesToHex(sha256(k.dsaPublicKey)), KAT_DSA_PUB_SHA256, 'ML-DSA-87 keygen from the seed (FIPS 204)');
  assert.equal(deriveMailboxIdV2(k), KAT_ID);
});

test('KAT: the exact bytes a poll signs, and the digest of the bytes an ack signs', async () => {
  const { sha256 } = await import('@noble/hashes/sha2.js');
  const nonce = '000102030405060708090a0b0c0d0e0f';
  assert.equal(bytesToHex(ownerSignedMessageV2('poll', KAT_ID, nonce, 1_700_000_000_000)), KAT_POLL_MSG);
  const ack = ownerSignedMessageV2('ack', KAT_ID, nonce, 1_700_000_000_000, ['e1', 'e2']);
  assert.equal(ack.length, 213);
  assert.equal(bytesToHex(sha256(ack)), KAT_ACK_MSG_SHA256);
});

// ---- done_when 1: no fingerprint / identity key / identity signature in any v2 owner request

test('done_when 1: the v2 bundle has EXACTLY {v, ed_pub, dsa_pub, nonce, ts, sig, pq_sig}, and no v1 header rides along', () => {
  const { headers } = signOwnerRequestV2({ keypair: A, op: 'poll', now: 1_700_000_000_000 });
  assert.deepEqual(Object.keys(headers), [OWNER_AUTH_V2_HEADER]);
  assert.equal(OWNER_AUTH_HEADER in headers, false);
  assert.deepEqual(Object.keys(decode(headers[OWNER_AUTH_V2_HEADER])).sort(), ['dsa_pub', 'ed_pub', 'nonce', 'pq_sig', 'sig', 'ts', 'v']);
});

test('done_when 1: the owner polls and acks its v2 mailbox with the auth key alone', async () => {
  const id = deriveMailboxIdV2(A);
  depositEnvelope(id, 'blob-1', Date.now());
  depositEnvelope(id, 'blob-2', Date.now());
  const p = await poll(id, pollHeaders(A));
  assert.equal(p.status, 200);
  assert.equal((p.body as unknown[]).length, 2);
  const eid = (p.body as { envelope_id: string }[])[0].envelope_id;
  const a = await ack(id, [eid], signOwnerRequestV2({ keypair: A, op: 'ack', now: Date.now(), envelopeIds: [eid] }).headers);
  assert.equal(a.status, 200);
  assert.equal(pollMailbox(id, Date.now()).length, 1);
});

test('done_when 1 NEG: a v1 identity bundle is refused on a v2 mailbox (and the store is never reached)', async () => {
  const id = deriveMailboxIdV2(A);
  depositEnvelope(id, 'blob', Date.now());
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime.
    curve: 'ed25519',
    userIDs: [{ name: 'o', email: 'o@x.test' }],
    passphrase: 'pw',
    format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const v1 = await signMailboxPollRequest({
    mailboxId: id,
    fingerprint: 'A'.repeat(64),
    publicKeyArmored: publicKey,
    privateKeyArmored: privateKey,
    passphrase: 'pw',
    now: Date.now(),
    kemPublicKey: uint8ToBase64(pq.kem.publicKey),
    sigPublicKey: uint8ToBase64(pq.signing.publicKey),
  });
  assert.equal((await poll(id, v1)).status, 401);
  assert.equal((await poll(id, { ...v1, [OWNER_AUTH_V2_HEADER]: v1[OWNER_AUTH_HEADER] })).status, 401, 'a v1 bundle in the v2 header');
});

test('NEG: a v2 bundle is refused on a v1 (mbx_) id, on another key\'s mailbox, and with no header', async () => {
  assert.equal((await poll(deriveMailboxId('A'.repeat(64)), pollHeaders(A))).status, 401);
  assert.equal((await poll(deriveMailboxIdV2(B), pollHeaders(A))).status, 401);
  assert.equal((await poll(deriveMailboxIdV2(A), {})).status, 401);
});

test('NEG: tampered sig, tampered pq_sig, a swapped key, an extra field, a stale ts: all refused', async () => {
  const id = deriveMailboxIdV2(A);
  const h = pollHeaders(A);
  const b = decode(h[OWNER_AUTH_V2_HEADER]);
  const flip = (s: string) => {
    const x = Buffer.from(s, 'base64url');
    x[3] ^= 1;
    return x.toString('base64url');
  };
  const bad = (o: object) => ({ [OWNER_AUTH_V2_HEADER]: encode({ ...b, ...o }) });
  assert.equal((await poll(id, bad({ sig: flip(b.sig) }))).status, 401, 'Ed25519 half');
  assert.equal((await poll(id, bad({ pq_sig: flip(b.pq_sig) }))).status, 401, 'ML-DSA half: BOTH must verify');
  const Bb = decode(pollHeaders(B)[OWNER_AUTH_V2_HEADER]);
  assert.equal((await poll(id, bad({ ed_pub: Bb.ed_pub }))).status, 401, 'key no longer derives this id');
  assert.equal((await poll(id, bad({ fingerprint: 'A'.repeat(64) }))).status, 401, 'no field outside the fixed set');
  assert.equal((await poll(id, pollHeaders(A, Date.now() - 10 * 60_000))).status, 401, 'outside the freshness window');
});

test('NEG: op separation: a poll signature never authorises an ack; an ack is bound to its exact envelope_ids', async () => {
  const id = deriveMailboxIdV2(A);
  depositEnvelope(id, 'blob', Date.now());
  const e = pollMailbox(id, Date.now())[0];
  assert.equal((await ack(id, [e.envelope_id], pollHeaders(A))).status, 401);
  const signedFor = signOwnerRequestV2({ keypair: A, op: 'ack', now: Date.now(), envelopeIds: ['other'] }).headers;
  assert.equal((await ack(id, [e.envelope_id], signedFor)).status, 401);
  assert.equal(pollMailbox(id, Date.now()).length, 1, 'nothing deleted');
});

/** A VALID hybrid signature by `signer` over a claim naming ANY mailbox id: what an attacker with their own key can always make. */
function forge(signer: MailboxAuthKeypair, op: string, mailboxId: string) {
  const nonce = bytesToHex(randomBytes(16));
  const ts = Date.now();
  const msg = concatBytes(lpStr(DOMAIN_MAILBOX_OWNER_V2), lpStr(op), lpStr(canonicalize({ mailbox_id: mailboxId, nonce, ts })));
  const b64 = (x: Uint8Array) => Buffer.from(x).toString('base64url');
  return {
    [OWNER_AUTH_V2_HEADER]: encode({
      v: 2, ed_pub: b64(signer.edPublicKey), dsa_pub: b64(signer.dsaPublicKey), nonce, ts,
      sig: b64(ed25519.sign(msg, signer.edSecretKey)), pq_sig: b64(ml_dsa87.sign(msg, signer.dsaSecretKey)),
    }),
  };
}

test('NEG: someone validly signing a claim for ANOTHER key\'s mailbox id is refused: the key must derive the id', async () => {
  const victim = deriveMailboxIdV2(A);
  depositEnvelope(victim, 'secret', Date.now());
  assert.equal((await poll(deriveMailboxIdV2(B), forge(B, 'poll', deriveMailboxIdV2(B)))).status, 200, 'control: forge() is a valid own-mailbox poll');
  assert.equal((await poll(victim, forge(B, 'poll', victim))).status, 401);
});

test('NEG: a poll signature is not a claim signature (same claim body; only the op separates them)', async () => {
  const id = deriveMailboxIdV2(A);
  const req = () => new Request('http://r.test/x', { headers: pollHeaders(A) });
  assert.equal(await verifyOwnerRequestV2(req(), 'poll', id, Date.now()), true, 'control');
  assert.equal(await verifyOwnerRequestV2(req(), 'claim', id, Date.now()), false);
});

// ---- done_when 3: the auth key can't produce an identity or pointer signature (key + domain separation)

test('done_when 3: an auth-key-signed pointer never verifies as the identity\'s pointer', () => {
  const identitySeed = ed25519.utils.randomSecretKey();
  const identityPub = ed25519.getPublicKey(identitySeed);
  const x = new Uint8Array(32).fill(7);
  const k = new Uint8Array(1568).fill(9);
  assert.ok(verifyMailboxPointer(buildSignedMailboxPointer(1, x, k, identitySeed), identityPub), 'control: the identity can publish');
  assert.equal(verifyMailboxPointer(buildSignedMailboxPointer(1, x, k, A.edSecretKey), identityPub), null);
});

test('done_when 3: a v2 owner signature is bound to its domain + op, so it is not a signature over anything else', () => {
  const b = decode(pollHeaders(A)[OWNER_AUTH_V2_HEADER]);
  const sig = Buffer.from(b.sig, 'base64url');
  // the same signature over the bare claim (no domain / op framing), as any other signer of that JSON would sign it, does not verify
  const claim = JSON.stringify({ mailbox_id: deriveMailboxIdV2(A), nonce: b.nonce, ts: b.ts });
  assert.equal(ed25519.verify(sig, new TextEncoder().encode(claim), A.edPublicKey), false);
});

// ---- done_when 10: /mailbox/register has no caller (R1c: stays unwired until it moves to the mailbox key)

function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    if (n === 'node_modules' || n.startsWith('.')) continue;
    const p = join(dir, n);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx)$/.test(n) && !/\.test\.tsx?$/.test(n)) out.push(p);
  }
  return out;
}

test('done_when 10: nothing outside its own module imports the /mailbox/register client', () => {
  const root = join(__dirname, '..', '..', '..');
  const offenders = ['src', 'app', 'scripts']
    .flatMap((d) => walk(join(root, d)))
    .filter((p) => !p.endsWith('mailbox-registry-client.ts'))
    .filter((p) => /mailbox-registry-client/.test(readFileSync(p, 'utf8')));
  assert.deepEqual(offenders, []);
});

test('NEG: freshness is two-sided: a bundle dated 10 min in the FUTURE is refused too (else one signed header stays replayable until its ts)', async () => {
  const id = deriveMailboxIdV2(A);
  assert.equal((await poll(id, pollHeaders(A, Date.now() + 10 * 60_000))).status, 401, 'future-dated, outside the window');
  assert.equal((await poll(id, pollHeaders(A, Date.now()))).status, 200, 'control: a current bundle is accepted');
});
