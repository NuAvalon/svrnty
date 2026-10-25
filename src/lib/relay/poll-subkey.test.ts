// src/lib/relay/poll-subkey.test.ts
// N12 (#703): the poll-only subkey. Flint's done_when (task:703 #1151/#1306), with REAL openpgp identities:
//   - the poll key cannot ack or claim (the new header is invisible to those verifiers; the old header cannot carry it)
//   - an expired cert is refused; a cert for another mailbox is refused; a cert signed by a key whose fingerprint is not the
//     presented one is refused; the relay caps the lifetime at 24 h and refuses issued_ts > 60 s ahead
//   - a PRESENT but invalid v2 header never falls through to a valid v1 header
//   - the identity key is unlocked once per cert (spy via makeUnlockCycle opts.onUnlock), never per idle poll
//   - lock / identity switch leaves no poll key or cert, and the next poll mints a NEW key
//   - P1: nothing is persisted
// Run: npx tsx --test src/lib/relay/poll-subkey.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { generateKey, readKey, readPrivateKey, decryptKey } from 'openpgp';
import { generatePQKeypairBundle, uint8ToBase64 } from '@/lib/crypto/pq';
import { mintCanonicalFingerprint } from '@/lib/identity/fingerprint';
import { signWithEnvelope } from '@/lib/crypto/sign-envelope';
import { canonicalize } from '@/lib/format/canonical';
import { makeUnlockCycle } from '@/lib/crypto/unlock-cycle';
import { lockSession } from '@/lib/identity/client-store';
import {
  deriveMailboxId,
  signMailboxPollRequest,
  signMailboxPollV2,
  signMailboxAckRequest,
  verifyMailboxPollAuth,
  verifyMailboxAckAuth,
  verifyMailboxClaimAuth,
  OWNER_AUTH_HEADER,
  POLL_AUTH_HEADER,
  DOMAIN_MAILBOX_POLL_DELEGATION,
  POLL_LIFETIME_DEFAULT_MS,
  POLL_LIFETIME_MAX_MS,
  POLL_ISSUED_FUTURE_SKEW_MS,
  type PollDelegation,
} from './mailbox-auth';
import { pollHeaders, pollKeyState, dropPollKey, PollKeyDropped, POLL_REMINT_MARGIN_MS, type PollOwner } from './poll-subkey';

interface Identity { fingerprint: string; publicKey: string; privateKey: string; passphrase: string; kem?: string; sig?: string }

async function makeIdentity(name: string): Promise<Identity> {
  const passphrase = 'pw-' + name;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime (same keygen as core.ts).
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }],
    passphrase,
    format: 'armored',
  });
  const fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint();
  return { fingerprint, publicKey, privateKey, passphrase };
}

// A §5 CANONICAL identity (64-hex fingerprint over sign+enc+kem+sig), as mailbox-auth.test.ts builds it.
async function makeCanonicalIdentity(name: string): Promise<Identity> {
  const passphrase = 'pw-' + name;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime.
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }],
    passphrase,
    format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase });
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  return { fingerprint, publicKey, privateKey, passphrase, kem: uint8ToBase64(pq.kem.publicKey), sig: uint8ToBase64(pq.signing.publicKey) };
}

const NOW = 1_700_000_000_000;
// Dev has a CANONICAL-ONLY GATE (mailbox-auth.test.ts res1): a classical 40-hex identity proves no ownership at all, so every
// identity that must verify here is canonical. `legacy` is classical, to pin that v2 does NOT reopen that gate.
let alice: Identity;
let bob: Identity;
let mallory: Identity;
let carol: Identity;
let legacy: Identity;

before(async () => {
  alice = await makeCanonicalIdentity('alice');
  bob = await makeCanonicalIdentity('bob');
  mallory = await makeCanonicalIdentity('mallory');
  carol = await makeCanonicalIdentity('carol');
  legacy = await makeIdentity('legacy');
});

const ownerOf = (id: Identity): PollOwner => ({
  fingerprint: id.fingerprint, publicKeyArmored: id.publicKey, privateKeyArmored: id.privateKey, passphrase: id.passphrase,
  kemPublicKey: id.kem, sigPublicKey: id.sig,
});
const req = (headers: Record<string, string>) => new Request('http://relay.test/api/relay/queue', { headers });

// Build a cert BY HAND (bypassing mintPollDelegation's clamps) so the RELAY's own caps are what the test exercises.
async function handCert(opts: {
  id: Identity; mailboxId?: string; pollMailboxId?: string; issued: number; expires: number; now?: number;
  signer?: Identity; presentFingerprint?: string; presentKey?: string; extra?: Record<string, unknown>; pq?: boolean;
}) {
  const { secretKey, publicKey } = ed25519.keygen();
  const mailboxId = opts.mailboxId ?? deriveMailboxId(opts.id.fingerprint);
  const delegation = { mailbox_id: mailboxId, poll_pub: bytesToHex(publicKey), issued_ts: opts.issued, expires_ts: opts.expires, ...(opts.extra ?? {}) } as PollDelegation;
  const signer = opts.signer ?? opts.id;
  const sig = await signWithEnvelope(DOMAIN_MAILBOX_POLL_DELEGATION, canonicalize(delegation), signer.privateKey, signer.passphrase);
  const cert = {
    delegation,
    fingerprint: opts.presentFingerprint ?? opts.id.fingerprint,
    public_key: opts.presentKey ?? opts.id.publicKey,
    signature: sig.classical,
    ...(opts.id.kem ? { kem_public_key: opts.id.kem, sig_public_key: opts.id.sig } : {}),
  };
  const pollMailbox = opts.pollMailboxId ?? deriveMailboxId(opts.id.fingerprint);
  const headers = signMailboxPollV2({ cert, secretKey, mailboxId: pollMailbox, now: opts.now ?? NOW });
  return { headers, cert, secretKey, mailboxId: pollMailbox };
}

// The wire shape of the v2 bundle as JSON, loose enough for the tamper tests to add unknown fields.
type BundleJson = {
  nonce: string; ts: number; signature: string;
  cert: {
    fingerprint: string; public_key: string; signature: string; kem_public_key?: string; sig_public_key?: string;
    delegation: { mailbox_id: string; poll_pub: string; issued_ts: number; expires_ts: number; [k: string]: unknown };
  };
};
function mutatePollHeader(headers: Record<string, string>, fn: (b: BundleJson) => void): Record<string, string> {
  const b = JSON.parse(atob(headers[POLL_AUTH_HEADER].replace(/-/g, '+').replace(/_/g, '/')));
  fn(b);
  return { [POLL_AUTH_HEADER]: btoa(JSON.stringify(b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') };
}

// ───────────────────────────── relay verifier ─────────────────────────────

test('a freshly minted v2 poll verifies for the right mailbox (canonical identity)', async () => {
  dropPollKey();
  const mbx = deriveMailboxId(alice.fingerprint);
  const h = await pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW });
  assert.deepEqual(Object.keys(h), [POLL_AUTH_HEADER]);
  assert.equal(await verifyMailboxPollAuth(req(h), mbx, NOW), true);
});

test('a v2 poll verifies for a second canonical identity, and a half-present or wrong-length PQ pair in the cert refuses', async () => {
  dropPollKey();
  const mbx = deriveMailboxId(carol.fingerprint);
  const h = await pollHeaders({ owner: ownerOf(carol), mailboxId: mbx, now: NOW });
  assert.equal(await verifyMailboxPollAuth(req(h), mbx, NOW), true);
  const bad = mutatePollHeader(h, (b) => { delete b.cert.sig_public_key; }); // half-present PQ pair
  assert.equal(await verifyMailboxPollAuth(req(bad), mbx, NOW), false);
  const wrongLen = mutatePollHeader(h, (b) => { b.cert.kem_public_key = btoa('short'); });
  assert.equal(await verifyMailboxPollAuth(req(wrongLen), mbx, NOW), false);
});

test('the canonical-only gate holds for v2: a CLASSICAL 40-hex identity is refused on v2 exactly as on v1 (v2 does not reopen it)', async () => {
  dropPollKey();
  const mbx = deriveMailboxId(legacy.fingerprint);
  const v2 = await pollHeaders({ owner: ownerOf(legacy), mailboxId: mbx, now: NOW });
  assert.equal(await verifyMailboxPollAuth(req(v2), mbx, NOW), false, 'v2 for a classical identity');
  const v1 = await signMailboxPollRequest({ mailboxId: mbx, fingerprint: legacy.fingerprint, publicKeyArmored: legacy.publicKey, privateKeyArmored: legacy.privateKey, passphrase: legacy.passphrase, now: NOW });
  assert.equal(await verifyMailboxPollAuth(req(v1), mbx, NOW), false, 'control: v1 refuses it too (the gate being preserved)');
  dropPollKey();
});

test('done_when: the poll key cannot ack or claim. The new header is invisible to those verifiers and the old header cannot carry it', async () => {
  dropPollKey();
  const mbx = deriveMailboxId(alice.fingerprint);
  const h = await pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW });
  assert.equal(await verifyMailboxAckAuth(req(h), mbx, ['e1'], NOW), false, 'ack with only the poll header');
  assert.equal(await verifyMailboxClaimAuth(req(h), mbx, NOW), false, 'claim with only the poll header');
  const asOwner = { [OWNER_AUTH_HEADER]: h[POLL_AUTH_HEADER] }; // the same bytes smuggled into the identity-key header
  assert.equal(await verifyMailboxAckAuth(req(asOwner), mbx, ['e1'], NOW), false, 'ack with the poll bundle in the owner header');
  assert.equal(await verifyMailboxClaimAuth(req(asOwner), mbx, NOW), false, 'claim with the poll bundle in the owner header');
  assert.equal(await verifyMailboxPollAuth(req(asOwner), mbx, NOW), false, 'and v1 poll refuses it too');
});

test('control: the identity key CAN still ack, and v1 poll is still accepted when no v2 header is present (rollout)', async () => {
  const mbx = deriveMailboxId(alice.fingerprint);
  const v1 = await signMailboxPollRequest({ mailboxId: mbx, fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase, kemPublicKey: alice.kem, sigPublicKey: alice.sig, now: NOW });
  assert.equal(await verifyMailboxPollAuth(req(v1), mbx, NOW), true);
  const ack = await signMailboxAckRequest({ mailboxId: mbx, envelopeIds: ['e1'], fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase, kemPublicKey: alice.kem, sigPublicKey: alice.sig, now: NOW });
  assert.equal(await verifyMailboxAckAuth(req(ack), mbx, ['e1'], NOW), true);
});

test('no silent fallback: a PRESENT but invalid v2 header is refused even beside a VALID v1 header', async () => {
  dropPollKey();
  const mbx = deriveMailboxId(alice.fingerprint);
  const v1 = await signMailboxPollRequest({ mailboxId: mbx, fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase, kemPublicKey: alice.kem, sigPublicKey: alice.sig, now: NOW });
  assert.equal(await verifyMailboxPollAuth(req(v1), mbx, NOW), true, 'the v1 header alone is fine');
  const v2 = await pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW });
  const broken = mutatePollHeader(v2, (b) => { b.nonce = b.nonce + 'x'; });
  assert.equal(await verifyMailboxPollAuth(req({ ...v1, ...broken }), mbx, NOW), false, 'invalid v2 + valid v1 must refuse');
  for (const junk of ['', 'not-base64!!', btoa('{}'), btoa('null')]) {
    assert.equal(await verifyMailboxPollAuth(req({ ...v1, [POLL_AUTH_HEADER]: junk }), mbx, NOW), false, `junk v2 "${junk.slice(0, 12)}" + valid v1 must refuse`);
  }
});

test('done_when: an expired cert is refused (strictly: expires_ts == now is expired, expires_ts == now + 1 is not)', async () => {
  const a = await handCert({ id: alice, issued: NOW - 1000, expires: NOW });
  assert.equal(await verifyMailboxPollAuth(req(a.headers), a.mailboxId, NOW), false);
  const b = await handCert({ id: alice, issued: NOW - 1000, expires: NOW + 1 });
  assert.equal(await verifyMailboxPollAuth(req(b.headers), b.mailboxId, NOW), true);
  const c = await handCert({ id: alice, issued: NOW - 7_200_000, expires: NOW - 3_600_000 });
  assert.equal(await verifyMailboxPollAuth(req(c.headers), c.mailboxId, NOW), false, 'long expired');
});

test('done_when: a cert for ANOTHER mailbox is refused (the delegation names a different mailbox; or a valid cert of Bob presented on Alice\'s mailbox)', async () => {
  const wrongNamed = await handCert({ id: alice, mailboxId: deriveMailboxId(bob.fingerprint), issued: NOW - 1000, expires: NOW + 600_000 });
  assert.equal(await verifyMailboxPollAuth(req(wrongNamed.headers), deriveMailboxId(alice.fingerprint), NOW), false);
  const bobs = await handCert({ id: bob, issued: NOW - 1000, expires: NOW + 600_000 });
  assert.equal(await verifyMailboxPollAuth(req(bobs.headers), deriveMailboxId(bob.fingerprint), NOW), true, 'control: Bob\'s own cert works on Bob\'s mailbox');
  assert.equal(await verifyMailboxPollAuth(req(bobs.headers), deriveMailboxId(alice.fingerprint), NOW), false, 'but not on Alice\'s');
});

test('done_when: a cert signed by a key whose fingerprint is not the presented one is refused (both ways)', async () => {
  const mbxA = deriveMailboxId(alice.fingerprint);
  // (a) Mallory signs the delegation but presents Alice's fingerprint AND Alice's public key: the signature does not verify
  const a = await handCert({ id: alice, signer: mallory, issued: NOW - 1000, expires: NOW + 600_000 });
  assert.equal(await verifyMailboxPollAuth(req(a.headers), mbxA, NOW), false);
  // (b) Mallory signs and presents HER key under Alice's fingerprint: the fp<->key binding fails
  const b = await handCert({ id: alice, signer: mallory, presentKey: mallory.publicKey, issued: NOW - 1000, expires: NOW + 600_000 });
  assert.equal(await verifyMailboxPollAuth(req(b.headers), mbxA, NOW), false);
  // (c) Mallory presents her own fingerprint+key for Alice's mailbox: the mailbox derivation fails
  // (c) Mallory presents her own fingerprint+key, names ALICE's mailbox in the delegation AND signs the poll over it: every
  // check passes except 'this fingerprint derives this mailbox', so only that binding can refuse it
  const c = await handCert({ id: mallory, mailboxId: mbxA, pollMailboxId: mbxA, issued: NOW - 1000, expires: NOW + 600_000 });
  assert.equal(await verifyMailboxPollAuth(req(c.headers), mbxA, NOW), false);
});

test('relay caps: lifetime <= 24 h exactly (24 h ok, 24 h + 1 ms refused); issued_ts <= now + 60 s (60 s ok, 60 s + 1 ms refused); zero/negative lifetime refused', async () => {
  const ok24 = await handCert({ id: alice, issued: NOW - 1000, expires: NOW - 1000 + POLL_LIFETIME_MAX_MS });
  assert.equal(await verifyMailboxPollAuth(req(ok24.headers), ok24.mailboxId, NOW), true);
  const over = await handCert({ id: alice, issued: NOW - 1000, expires: NOW - 1000 + POLL_LIFETIME_MAX_MS + 1 });
  assert.equal(await verifyMailboxPollAuth(req(over.headers), over.mailboxId, NOW), false);
  const fut60 = await handCert({ id: alice, issued: NOW + POLL_ISSUED_FUTURE_SKEW_MS, expires: NOW + POLL_ISSUED_FUTURE_SKEW_MS + 600_000 });
  assert.equal(await verifyMailboxPollAuth(req(fut60.headers), fut60.mailboxId, NOW), true);
  const fut61 = await handCert({ id: alice, issued: NOW + POLL_ISSUED_FUTURE_SKEW_MS + 1, expires: NOW + POLL_ISSUED_FUTURE_SKEW_MS + 600_000 });
  assert.equal(await verifyMailboxPollAuth(req(fut61.headers), fut61.mailboxId, NOW), false);
  const zero = await handCert({ id: alice, issued: NOW - 1000, expires: NOW - 1000 });
  assert.equal(await verifyMailboxPollAuth(req(zero.headers), zero.mailboxId, NOW), false);
  const neg = await handCert({ id: alice, issued: NOW, expires: NOW - 5000 });
  assert.equal(await verifyMailboxPollAuth(req(neg.headers), neg.mailboxId, NOW), false);
});

test('mintPollDelegation clamps the lifetime to the 24 h cap, defaults to 1 h, and never goes below 1 ms', async () => {
  dropPollKey();
  const mbx = deriveMailboxId(alice.fingerprint);
  const dflt = await pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW });
  const d1 = JSON.parse(atob(dflt[POLL_AUTH_HEADER].replace(/-/g, '+').replace(/_/g, '/'))).cert.delegation;
  assert.equal(d1.expires_ts - d1.issued_ts, POLL_LIFETIME_DEFAULT_MS);
  dropPollKey();
  const huge = await pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW, lifetimeMs: 10 * POLL_LIFETIME_MAX_MS });
  const d2 = JSON.parse(atob(huge[POLL_AUTH_HEADER].replace(/-/g, '+').replace(/_/g, '/'))).cert.delegation;
  assert.equal(d2.expires_ts - d2.issued_ts, POLL_LIFETIME_MAX_MS);
  dropPollKey();
});

test('tampering with any signed part of the poll refuses: nonce, ts, poll signature, delegation fields, cert signature, presented key', async () => {
  dropPollKey();
  const mbx = deriveMailboxId(alice.fingerprint);
  const h = await pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW });
  assert.equal(await verifyMailboxPollAuth(req(h), mbx, NOW), true);
  const flip = (s: string) => (s[0] === '0' ? '1' : '0') + s.slice(1);
  const muts: Array<[string, (b: BundleJson) => void]> = [
    ['nonce', (b) => { b.nonce = flip(b.nonce); }],
    ['ts', (b) => { b.ts += 1; }],
    ['poll signature', (b) => { b.signature = flip(b.signature); }],
    ['poll_pub swapped for another key', (b) => { b.cert.delegation.poll_pub = bytesToHex(ed25519.keygen().publicKey); }],
    ['expires_ts extended', (b) => { b.cert.delegation.expires_ts += 1000; }],
    ['issued_ts moved', (b) => { b.cert.delegation.issued_ts -= 1000; }],
    ['delegation mailbox_id', (b) => { b.cert.delegation.mailbox_id = deriveMailboxId(bob.fingerprint); }],
    ['cert signature', (b) => { b.cert.signature = b.cert.signature.slice(0, -4) + 'AAAA'; }],
    ['presented public key', (b) => { b.cert.public_key = bob.publicKey; }],
    ['presented fingerprint', (b) => { b.cert.fingerprint = bob.fingerprint; }],
    ['an UNKNOWN field added to the delegation', (b) => { b.cert.delegation.scope = 'ack'; }],
    ['poll_pub not hex', (b) => { b.cert.delegation.poll_pub = 'zz'.repeat(32); }],
    ['poll signature wrong length', (b) => { b.signature = b.signature.slice(2); }],
  ];
  for (const [name, fn] of muts) {
    assert.equal(await verifyMailboxPollAuth(req(mutatePollHeader(h, fn)), mbx, NOW), false, `tampered ${name} must refuse`);
  }
});

test('domain separation: an identity-key v1 poll signature cannot stand in for the delegation, and a v2 poll signature cannot stand in for a v1 poll', async () => {
  const mbx = deriveMailboxId(alice.fingerprint);
  dropPollKey();
  const v2 = await pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW });
  const v1 = await signMailboxPollRequest({ mailboxId: mbx, fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase, kemPublicKey: alice.kem, sigPublicKey: alice.sig, now: NOW });
  const v1b = JSON.parse(atob(v1[OWNER_AUTH_HEADER].replace(/-/g, '+').replace(/_/g, '/')));
  // the identity key's v1 poll signature put where the delegation signature belongs
  const swapped = mutatePollHeader(v2, (b) => { b.cert.signature = v1b.signature; });
  assert.equal(await verifyMailboxPollAuth(req(swapped), mbx, NOW), false);
  // the v2 poll signature (an Ed25519 hex string) offered as a v1 owner bundle's signature
  const v2b = JSON.parse(atob(v2[POLL_AUTH_HEADER].replace(/-/g, '+').replace(/_/g, '/')));
  const asV1 = { ...v1b, signature: v2b.signature };
  const enc = btoa(JSON.stringify(asV1)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  assert.equal(await verifyMailboxPollAuth(req({ [OWNER_AUTH_HEADER]: enc }), mbx, NOW), false);
  dropPollKey();
});

test('freshness: a v2 poll older or newer than the relay window is refused (replay bound), within it is accepted', async () => {
  const c = await handCert({ id: alice, issued: NOW - 1000, expires: NOW + 600_000, now: NOW });
  assert.equal(await verifyMailboxPollAuth(req(c.headers), c.mailboxId, NOW + 60_000), true, 'at the window edge');
  assert.equal(await verifyMailboxPollAuth(req(c.headers), c.mailboxId, NOW + 60_001), false, 'just past it');
  assert.equal(await verifyMailboxPollAuth(req(c.headers), c.mailboxId, NOW - 60_001), false, 'from the future');
});

// ───────────────────────────── the in-memory holder ─────────────────────────────

test('done_when (P3, the point of N12): 50 idle polls cost ONE identity-key unlock (the mint), not 50. CONTROL: the v1 path unlocks once per poll cycle', async () => {
  dropPollKey();
  const mbx = deriveMailboxId(alice.fingerprint);
  let unlocks = 0;
  const first = await (async () => {
    // each poll runs in its OWN cycle, as the real caller does; a cycle that is never asked for the key never unlocks
    const polls: Array<Record<string, string>> = [];
    for (let i = 0; i < 50; i++) {
      const cycle = makeUnlockCycle(alice.privateKey, alice.passphrase, { onUnlock: () => { unlocks++; } });
      polls.push(await pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW + i * 2000, cycle }));
      cycle.drop();
    }
    return polls;
  })();
  assert.equal(unlocks, 1, 'one unlock for the whole run: the cert mint');
  assert.equal(new Set(first.map((h) => JSON.parse(atob(h[POLL_AUTH_HEADER].replace(/-/g, '+').replace(/_/g, '/'))).cert.delegation.poll_pub)).size, 1, 'one poll key throughout');
  for (const i of [0, 24, 49]) assert.equal(await verifyMailboxPollAuth(req(first[i]), mbx, NOW + i * 2000), true, `poll ${i} verifies`);
  // CONTROL (the dev behaviour N12 replaces): the v1 signer unlocks in every cycle
  let v1unlocks = 0;
  for (let i = 0; i < 50; i++) {
    const cycle = makeUnlockCycle(alice.privateKey, alice.passphrase, { onUnlock: () => { v1unlocks++; } });
    await signMailboxPollRequest({ mailboxId: mbx, fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase, kemPublicKey: alice.kem, sigPublicKey: alice.sig, cycle, now: NOW + i * 2000 });
    cycle.drop();
  }
  assert.equal(v1unlocks, 50, 'v1: one unlock per poll cycle (this is the cost N12 removes)');
  dropPollKey();
});

test('re-mint happens only inside the margin before expiry (and exactly then): same key while more than the margin remains, a NEW key and ONE more unlock after', async () => {
  dropPollKey();
  const mbx = deriveMailboxId(alice.fingerprint);
  let unlocks = 0;
  const poll = async (now: number) => {
    const cycle = makeUnlockCycle(alice.privateKey, alice.passphrase, { onUnlock: () => { unlocks++; } });
    try { await pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now, cycle }); } finally { cycle.drop(); }
    return pollKeyState().pollPub;
  };
  const k0 = await poll(NOW);
  const expires = pollKeyState().expiresTs!;
  assert.equal(expires, NOW + POLL_LIFETIME_DEFAULT_MS);
  assert.equal(await poll(expires - POLL_REMINT_MARGIN_MS - 1), k0, 'more than the margin left: same key');
  assert.equal(unlocks, 1);
  const k1 = await poll(expires - POLL_REMINT_MARGIN_MS);
  assert.notEqual(k1, k0, 'exactly the margin left: a new key');
  assert.equal(unlocks, 2);
  dropPollKey();
});

test('a clock that goes BACKWARDS does not reuse a cert from its own future', async () => {
  dropPollKey();
  const mbx = deriveMailboxId(alice.fingerprint);
  await pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW });
  const k0 = pollKeyState().pollPub;
  await pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW - 10 * 60_000 });
  assert.notEqual(pollKeyState().pollPub, k0);
  dropPollKey();
});

test('done_when (lock): after lockSession no poll key or cert is held, and the next poll mints a NEW key with a NEW unlock', async () => {
  dropPollKey();
  const mbx = deriveMailboxId(alice.fingerprint);
  await pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW });
  const before = pollKeyState();
  assert.equal(before.held, true);
  lockSession();
  assert.deepEqual(pollKeyState(), { held: false }, 'nothing held after lock');
  let unlocks = 0;
  const cycle = makeUnlockCycle(alice.privateKey, alice.passphrase, { onUnlock: () => { unlocks++; } });
  await pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW + 1000, cycle });
  assert.equal(unlocks, 1);
  assert.notEqual(pollKeyState().pollPub, before.pollPub, 'a different poll_pub after lock');
  dropPollKey();
});

test('a mint IN FLIGHT when the session locks is discarded: PollKeyDropped, and nothing is held afterwards', async () => {
  dropPollKey();
  const mbx = deriveMailboxId(alice.fingerprint);
  const p = pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW });
  lockSession(); // the mint's async unlock+sign has not finished yet
  await assert.rejects(p, PollKeyDropped);
  assert.deepEqual(pollKeyState(), { held: false });
  const again = await pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW });
  assert.equal(await verifyMailboxPollAuth(req(again), mbx, NOW), true, 'and a fresh poll works');
  dropPollKey();
});

test('identity switch: another identity gets its own key (Alice\'s key is never used for Bob), and Alice\'s cert does not verify on Bob\'s mailbox', async () => {
  dropPollKey();
  const ma = deriveMailboxId(alice.fingerprint);
  const mb = deriveMailboxId(bob.fingerprint);
  const ha = await pollHeaders({ owner: ownerOf(alice), mailboxId: ma, now: NOW });
  const ka = pollKeyState().pollPub;
  const hb = await pollHeaders({ owner: ownerOf(bob), mailboxId: mb, now: NOW });
  assert.notEqual(pollKeyState().pollPub, ka);
  assert.equal(await verifyMailboxPollAuth(req(hb), mb, NOW), true);
  assert.equal(await verifyMailboxPollAuth(req(ha), mb, NOW), false);
  dropPollKey();
});

test('the holder never reuses a key for a DIFFERENT IDENTITY even when the mailbox id is the same (the fingerprint check, isolated)', async () => {
  dropPollKey();
  const ma = deriveMailboxId(alice.fingerprint);
  await pollHeaders({ owner: ownerOf(alice), mailboxId: ma, now: NOW });
  const ka = pollKeyState().pollPub;
  await pollHeaders({ owner: ownerOf(bob), mailboxId: ma, now: NOW }); // same mailbox id, different identity
  assert.notEqual(pollKeyState().pollPub, ka, 'bob must not sign with the key alice\'s identity delegated');
  dropPollKey();
});

test('the holder never reuses a key for a DIFFERENT MAILBOX of the same identity (the mailbox check, isolated)', async () => {
  dropPollKey();
  await pollHeaders({ owner: ownerOf(alice), mailboxId: deriveMailboxId(alice.fingerprint), now: NOW });
  const k0 = pollKeyState().pollPub;
  await pollHeaders({ owner: ownerOf(alice), mailboxId: deriveMailboxId(bob.fingerprint), now: NOW });
  assert.notEqual(pollKeyState().pollPub, k0);
  dropPollKey();
});

test('a caller for another identity that arrives while a mint is IN FLIGHT is refused (PollKeyDropped), not handed the other identity\'s cert; the first caller still succeeds', async () => {
  dropPollKey();
  const ma = deriveMailboxId(alice.fingerprint); const mb = deriveMailboxId(bob.fingerprint);
  const pa = pollHeaders({ owner: ownerOf(alice), mailboxId: ma, now: NOW });
  const pb = pollHeaders({ owner: ownerOf(bob), mailboxId: mb, now: NOW }); // joins alice's in-flight mint
  const [ra, rb] = await Promise.allSettled([pa, pb]);
  assert.equal(ra.status, 'fulfilled');
  assert.equal(rb.status, 'rejected');
  assert.ok((rb as PromiseRejectedResult).reason instanceof PollKeyDropped);
  assert.equal(await verifyMailboxPollAuth(req((ra as PromiseFulfilledResult<Record<string, string>>).value), ma, NOW), true);
  dropPollKey();
});

test('concurrent first polls share ONE mint (one unlock, one cert)', async () => {
  dropPollKey();
  const mbx = deriveMailboxId(alice.fingerprint);
  let unlocks = 0;
  const cycle = makeUnlockCycle(alice.privateKey, alice.passphrase, { onUnlock: () => { unlocks++; } });
  const [a, b, c] = await Promise.all([0, 1, 2].map((i) => pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW + i, cycle })));
  const pubs = [a, b, c].map((h) => JSON.parse(atob(h[POLL_AUTH_HEADER].replace(/-/g, '+').replace(/_/g, '/'))).cert.delegation.poll_pub);
  assert.equal(new Set(pubs).size, 1);
  assert.equal(unlocks, 1);
  dropPollKey();
});

test('a failed mint (wrong passphrase) is not cached and holds nothing; the next call with the right passphrase works', async () => {
  dropPollKey();
  const mbx = deriveMailboxId(alice.fingerprint);
  await assert.rejects(pollHeaders({ owner: { ...ownerOf(alice), passphrase: 'wrong' }, mailboxId: mbx, now: NOW }));
  assert.deepEqual(pollKeyState(), { held: false });
  const h = await pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW });
  assert.equal(await verifyMailboxPollAuth(req(h), mbx, NOW), true);
  dropPollKey();
});

test('an ENDED unlock cycle cannot mint (a dead cycle must not yield a key)', async () => {
  dropPollKey();
  const mbx = deriveMailboxId(alice.fingerprint);
  const cycle = makeUnlockCycle(alice.privateKey, alice.passphrase);
  cycle.drop();
  await assert.rejects(pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW, cycle }));
  assert.deepEqual(pollKeyState(), { held: false });
});

test('after dropPollKey a fresh poll does NOT reuse the old key or cert (the zeroing of the dropped secret is best-effort and not asserted here)', async () => {
  dropPollKey();
  const mbx = deriveMailboxId(alice.fingerprint);
  const h = await pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW });
  assert.equal(await verifyMailboxPollAuth(req(h), mbx, NOW), true);
  const cert = JSON.parse(atob(h[POLL_AUTH_HEADER].replace(/-/g, '+').replace(/_/g, '/'))).cert;
  dropPollKey();
  // after the drop a fresh poll must NOT reuse that cert
  const h2 = await pollHeaders({ owner: ownerOf(alice), mailboxId: mbx, now: NOW });
  const cert2 = JSON.parse(atob(h2[POLL_AUTH_HEADER].replace(/-/g, '+').replace(/_/g, '/'))).cert;
  assert.notEqual(cert2.delegation.poll_pub, cert.delegation.poll_pub);
  dropPollKey();
});

// ───────────────────────────── P1: nothing is persisted ─────────────────────────────

const STORAGE = /\b(localStorage|sessionStorage|indexedDB|IDBDatabase|IDBObjectStore|document\.cookie|writeFileSync|writeFile\b|appendFile|openDB|caches\.open)\b/;

test('P1: the poll-key module touches no storage API at all (control: the same pattern DOES match a line that would persist)', () => {
  const holder = readFileSync(join(__dirname, 'poll-subkey.ts'), 'utf8');
  assert.doesNotMatch(holder.replace(/\/\/.*$/gm, ''), STORAGE, 'poll-subkey.ts must not persist the key or cert');
  assert.match("localStorage.setItem('k', cert)", STORAGE, 'control: the pattern is not dead');
  assert.match('await openDB("x")', STORAGE);
});

test('P1: the new mailbox-auth section (mint / sign / verify) touches no storage API either', () => {
  const src = readFileSync(join(__dirname, 'mailbox-auth.ts'), 'utf8');
  const start = src.indexOf('N12 (#703): a POLL-ONLY subkey');
  assert.ok(start > 0);
  assert.doesNotMatch(src.slice(start).replace(/\/\/.*$/gm, ''), STORAGE);
});

test('P2 (relay side): the v2 verifier never logs: no console.* in poll-subkey.ts or the new mailbox-auth code', () => {
  const holder = readFileSync(join(__dirname, 'poll-subkey.ts'), 'utf8');
  const src = readFileSync(join(__dirname, 'mailbox-auth.ts'), 'utf8');
  const section = src.slice(src.indexOf('N12 (#703): a POLL-ONLY subkey'));
  for (const code of [holder, section]) assert.doesNotMatch(code.replace(/\/\/.*$/gm, ''), /\bconsole\.(log|info|warn|error|debug)\b/);
  assert.match("console.log(cert)", /\bconsole\.(log|info|warn|error|debug)\b/, 'control: the pattern is not dead');
});

test('the route that serves polls only ever asks verifyMailboxPollAuth, and ack/claim never mention the poll header', () => {
  const root = join(__dirname, '../../../app/api/relay');
  const read = (f: string) => readFileSync(join(root, f, 'route.ts'), 'utf8');
  assert.match(read('queue'), /verifyMailboxPollAuth/);
  assert.doesNotMatch(read('ack'), /POLL_AUTH_HEADER|x-svrnty-poll-auth/);
  assert.doesNotMatch(read('claim'), /POLL_AUTH_HEADER|x-svrnty-poll-auth/);
});
