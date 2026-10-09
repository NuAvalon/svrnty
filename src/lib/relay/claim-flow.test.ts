// src/lib/relay/claim-flow.test.ts
// Layer (A) END-TO-END claim flow through the REAL route handlers (queue GET + claim POST) +
// mailbox-store, with CANONICAL identities (the only kind the mint produces — res1 gate: owner-auth's
// fingerprintMatchesKey is canonical-only, 64-hex SHA256(sign‖enc‖kem‖sig), classical 40-hex rejected).
// Proves the two gate-criteria + non-transferability:
//   • criterion-1 RETROACTIVE DELIVERY (Archie #165854, Apollo §5): deposit to an UNCLAIMED mailbox is
//     buffered; owner-poll returns EMPTY until claim; CLAIM flips the flag WITHOUT flushing → the next
//     poll delivers the SAME buffered envelope. Never ack-deleted-unseen.
//   • NON-TRANSFERABILITY (format §3): a stranger cannot redeem a token minted for the owner's sub.
// Run: PATH=~/.nvm/versions/node/v22.22.1/bin:$PATH npx tsx --test claim-flow.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey, readPrivateKey, decryptKey } from 'openpgp';
import { generatePQKeypairBundle, uint8ToBase64 } from '@/lib/crypto/pq';
import { mintCanonicalFingerprint } from '@/lib/identity/fingerprint';

interface Canon { fp: string; pub: string; priv: string; pass: string; kemB64: string; sigB64: string }

// A §5 CANONICAL identity (mirrors mailbox-auth.test.ts makeCanonicalIdentity / genesis): openpgp +
// ML-KEM/ML-DSA → 64-hex SHA256(sign‖enc‖kem‖sig) fp. This is what the owner-auth requires (res1).
async function mkCanon(name: string): Promise<Canon> {
  const pass = `pw-${name}`;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart — 'ed25519' valid at runtime.
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }],
    passphrase: pass,
    format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase: pass });
  const { fingerprint } = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked,
    kemPublicKey: pq.kem.publicKey,
    sigPublicKey: pq.signing.publicKey,
  });
  return { fp: fingerprint, pub: publicKey, priv: privateKey, pass, kemB64: uint8ToBase64(pq.kem.publicKey), sigB64: uint8ToBase64(pq.signing.publicKey) };
}

let ISSUER: Canon; // the pinned beta-gate issuer (token sig verified by pin; canonical is realistic)
let OWNER: Canon; // the beta user redeeming
let STRANGER: Canon; // a different canonical identity (theft attempt)

before(async () => {
  ISSUER = await mkCanon('issuer');
  OWNER = await mkCanon('owner');
  STRANGER = await mkCanon('stranger');
  process.env.INVITE_REQUIRED = 'true';
  process.env.SVRNTY_BETA_ISSUER_FP = ISSUER.fp;
  process.env.SVRNTY_BETA_ISSUER_PUBKEY = ISSUER.pub;
});

async function pollBody(mailboxId: string, owner: Canon): Promise<{ status: number; body: unknown }> {
  const { GET } = await import('../../../app/api/relay/queue/route');
  const { signMailboxPollRequest } = await import('./mailbox-auth');
  const headers = await signMailboxPollRequest({
    mailboxId, fingerprint: owner.fp, publicKeyArmored: owner.pub, privateKeyArmored: owner.priv,
    passphrase: owner.pass, now: Date.now(), kemPublicKey: owner.kemB64, sigPublicKey: owner.sigB64,
  });
  const res = await GET(new Request(`http://r.test/api/relay/queue?mailbox_id=${encodeURIComponent(mailboxId)}`, { headers }));
  return { status: res.status, body: await res.json() };
}

async function claim(token: string, mailboxId: string, owner: Canon): Promise<{ status: number }> {
  const { POST } = await import('../../../app/api/relay/claim/route');
  const { signMailboxClaimRequest } = await import('./mailbox-auth');
  const auth = await signMailboxClaimRequest({
    mailboxId, fingerprint: owner.fp, publicKeyArmored: owner.pub, privateKeyArmored: owner.priv,
    passphrase: owner.pass, now: Date.now(), kemPublicKey: owner.kemB64, sigPublicKey: owner.sigB64,
  });
  const res = await POST(new Request('http://r.test/api/relay/claim', {
    method: 'POST', headers: { ...auth, 'content-type': 'application/json' }, body: JSON.stringify({ token }),
  }));
  return { status: res.status };
}

test('criterion-1: deposit→unclaimed poll EMPTY→claim→poll DELIVERS retroactively (no flush, no loss)', async () => {
  const { depositEnvelope } = await import('./mailbox-store');
  const { deriveMailboxId } = await import('./mailbox-auth');
  const { signBetaAccessToken, encodeBetaAccessToken } = await import('./beta-access');

  const mailboxId = deriveMailboxId(OWNER.fp);
  const dep = depositEnvelope(mailboxId, 'OPAQUE_NOTE_BLOB', Date.now());
  assert.equal(dep.ok, true, 'deposit to an unclaimed mailbox is accepted uniformly (no occupancy-oracle)');

  const before = await pollBody(mailboxId, OWNER);
  assert.equal(before.status, 200);
  assert.deepEqual(before.body, [], 'unclaimed mailbox is UNREADABLE — poll returns empty, buffered note hidden');

  const token = encodeBetaAccessToken(await signBetaAccessToken(
    { iss: ISSUER.fp, sub: OWNER.fp, jti: 'flow-jti-1', iat: Date.now() }, ISSUER.priv, ISSUER.pass));
  const claimed = await claim(token, mailboxId, OWNER);
  assert.equal(claimed.status, 200, 'owner redeems their own token → claimed');

  const after = await pollBody(mailboxId, OWNER) as { status: number; body: Array<{ blob: string }> };
  assert.equal(after.status, 200);
  assert.equal(after.body.length, 1, 'the buffered deposit delivers RETROACTIVELY after claim');
  assert.equal(after.body[0].blob, 'OPAQUE_NOTE_BLOB', 'same envelope — buffered, never ack-deleted-unseen');
});

test('non-transferability: a STRANGER cannot redeem a token minted for the OWNER', async () => {
  const { deriveMailboxId } = await import('./mailbox-auth');
  const { signBetaAccessToken, encodeBetaAccessToken } = await import('./beta-access');
  const token = encodeBetaAccessToken(await signBetaAccessToken(
    { iss: ISSUER.fp, sub: OWNER.fp, jti: 'flow-jti-steal', iat: Date.now() }, ISSUER.priv, ISSUER.pass));
  // Stranger holds the token bytes but signs owner-auth with STRANGER's key → can't derive OWNER's mailbox.
  const res = await claim(token, deriveMailboxId(OWNER.fp), STRANGER);
  assert.equal(res.status, 401, 'stranger-signed owner-auth for OWNER mailbox → rejected (token non-transferable)');
});

test('bad token (not signed by the pinned issuer) → claim rejected even with valid owner-auth', async () => {
  const { deriveMailboxId } = await import('./mailbox-auth');
  const { signBetaAccessToken, encodeBetaAccessToken } = await import('./beta-access');
  // Token claims iss=ISSUER but is signed by STRANGER → sig fails against the pinned issuer pubkey.
  const forged = encodeBetaAccessToken(await signBetaAccessToken(
    { iss: ISSUER.fp, sub: OWNER.fp, jti: 'flow-jti-forge', iat: Date.now() }, STRANGER.priv, STRANGER.pass));
  const res = await claim(forged, deriveMailboxId(OWNER.fp), OWNER);
  assert.equal(res.status, 401, 'a token not signed by the pinned issuer → rejected (pin is the trust root)');
});
