// src/lib/trust/rotation-receive.test.ts — task #810 step 1: the one receive function (pure decision module).
// Run: npx tsx --test src/lib/trust/rotation-receive.test.ts
// Real keys: OpenPGP + ML-KEM-1024 + ML-DSA-87 successors chained from one master through the real rotation verifier; real hybrid pointer
// signatures. No network, no clock (every `now` is passed in).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import { deriveNextAuthorityCommitment, deriveNextAuthorityKeypair, encodeAuthorityPubkeys, signRotationAuthority, mintCanonicalFingerprint, canonicalPubsFromArmoredPublicKey } from '../identity/fingerprint';
import { rotationSigningInput } from '../format/envelope';
import { ownerAuthorityCommitment } from '../crypto/owner-authority-commitment';
import type { RotationSuccessorInput } from './contact-update';
import { encodeKeyRotate } from './key-rotate-wire';
import { encodePointerV2, pointerV2Prefix, pointerV2SigningInput, type HybridSig, type PointerV2Fields } from './pointer-v2-wire';
import { receive, pointerAllowance, POINTER_CEILING_STEP, PENDING_MAX_KEYS, WEEK_MS, type HeldIdentity, type PendingEntry, type Decision } from './rotation-receive';

// ---------- helpers ----------
const deepFreeze = <T,>(o: T): T => {
  if (o && typeof o === 'object' && !(o instanceof Uint8Array) && !Object.isFrozen(o)) { Object.freeze(o); for (const v of Object.values(o as object)) deepFreeze(v); }
  return o;
};
const NOW = 1_800_000_000_000;
const b64d = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));
const sign = (msg: Uint8Array, edSecret: Uint8Array, dsaSecret: Uint8Array): HybridSig => ({ ed: ed25519.sign(msg, edSecret), dsa: ml_dsa87.sign(msg, dsaSecret) });
const act = (d: Decision) => d.action + (d.action === 'refuse' ? ':' + d.reason : d.action === 'stale' ? ':' + d.reason : d.action === 'hold' ? ':' + d.reason : '');
const nextOf = (d: Decision): HeldIdentity => { assert.ok('next' in d && d.next, 'the decision carries a next state: ' + act(d)); return d.next as HeldIdentity; };

// ---------- successor fixtures: a REAL chain from one master ----------
async function makeOperational(name: string) {
  const pass = 'pw-' + name;
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime.
    curve: 'ed25519', userIDs: [{ name, email: `${name}@x.test` }], passphrase: pass, format: 'armored' });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase: pass });
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  return { fingerprint, publicKey, kemB64: uint8ToBase64(pq.kem.publicKey), sigB64: uint8ToBase64(pq.signing.publicKey) };
}
type Op = Awaited<ReturnType<typeof makeOperational>>;

function successorFor(master: Uint8Array, durableId: string, epoch: number, nextOp: Op): RotationSuccessorInput {
  const priorPin = deriveNextAuthorityCommitment(master, epoch);
  const authKp = deriveNextAuthorityKeypair(master, epoch);
  const nextPin = deriveNextAuthorityCommitment(master, epoch + 1);
  const fields = { durable_id: durableId, prior_epoch: epoch - 1, prior_authority_commitment: priorPin, successor_epoch: epoch, new_fingerprint: nextOp.fingerprint, next_authority_commitment: nextPin };
  const sig = signRotationAuthority(rotationSigningInput(fields), authKp.edSecret, authKp.dsaSecret);
  return { durable_id: durableId, prior_epoch: epoch - 1, successor_epoch: epoch, new_fingerprint: nextOp.fingerprint, new_public_key: nextOp.publicKey,
    new_pq_kem_public_key: nextOp.kemB64, new_pq_sig_public_key: nextOp.sigB64, next_authority_commitment: nextPin,
    auth: { kind: 'rotation', auth_pubkeys: encodeAuthorityPubkeys(authKp.edPublic, authKp.dsaPublic), sig_by_authority: sig } };
}

async function chain() {
  const master = randomBytes(32);
  const g = await makeOperational('g0'), o1 = await makeOperational('g1'), o1b = await makeOperational('g1b'), o2 = await makeOperational('g2');
  const gp = await canonicalPubsFromArmoredPublicKey(g.publicKey, g.kemB64, g.sigB64);
  const held: HeldIdentity = deepFreeze({
    durableId: g.fingerprint, identityEpoch: 0, identityKeys: { edPublic: gp.signPub, dsaPublic: gp.sigPub }, operationalFingerprint: g.fingerprint,
    classicalPublicKeyArmored: g.publicKey, rotationPin: deriveNextAuthorityCommitment(master, 1), pointerEpoch: null, relay: 'https://relay.example.org',
    lastAcceptedAtMs: null, pending: [], conflicts: [], lastAdopted: null, rekeyPending: false,
  });
  const s1 = successorFor(master, g.fingerprint, 1, o1);
  const s1b = successorFor(master, g.fingerprint, 1, o1b); // a DIFFERENT valid successor for the same epoch (same master)
  const s2 = successorFor(master, g.fingerprint, 2, o2);
  const s3 = successorFor(master, g.fingerprint, 3, o2); // only its epoch matters: it is ahead
  return { master, g, o1, o1b, o2, held, s1, s1b, s2, s3 };
}
let CH: Awaited<ReturnType<typeof chain>>;
const ch = async () => (CH ??= await chain());
const succ = (s: RotationSuccessorInput) => ({ kind: 'successor' as const, bytes: encodeKeyRotate(s) });

// ---------- pointer fixtures: synthetic held keys we can sign with ----------
function ptrWorld() {
  const edSecret = randomBytes(32), dsa = ml_dsa87.keygen(randomBytes(32));
  const auth = { edSecret: randomBytes(32), dsa: ml_dsa87.keygen(randomBytes(32)) };
  const authPub = { edPublic: ed25519.getPublicKey(auth.edSecret), dsaPublic: auth.dsa.publicKey };
  const held = (over: Partial<{ -readonly [K in keyof HeldIdentity]: HeldIdentity[K] }> = {}): HeldIdentity => deepFreeze({
    durableId: bytesToHex(sha256(randomBytes(8))), identityEpoch: 1, identityKeys: { edPublic: ed25519.getPublicKey(edSecret), dsaPublic: dsa.publicKey },
    operationalFingerprint: bytesToHex(sha256(randomBytes(8))), classicalPublicKeyArmored: '', rotationPin: bytesToHex(sha256(randomBytes(8))),
    ownerAuthorityPin: ownerAuthorityCommitment(authPub.edPublic, authPub.dsaPublic), pointerEpoch: 10, heldPointerDigest: undefined,
    relay: 'https://relay.example.org', lastAcceptedAtMs: NOW, pending: [], conflicts: [], lastAdopted: null, rekeyPending: false, ...over,
  } as HeldIdentity);
  const make = (o: { epoch: number; relay?: string; identityEpoch?: number; authority?: boolean; x?: number; signer?: { edSecret: Uint8Array; dsaSecret: Uint8Array } }) => {
    const f: PointerV2Fields = { mailboxId: new Uint8Array(32).fill(0x11), relay: o.relay ?? 'https://relay.example.org', identityEpoch: o.identityEpoch ?? 1, pointerEpoch: o.epoch,
      x25519Pub: new Uint8Array(32).fill(o.x ?? 0x22), mlkem1024Ek: new Uint8Array(1568).fill(0x33), hasAuthority: !!o.authority };
    const prefix = pointerV2Prefix(f);
    const s = o.signer ?? { edSecret, dsaSecret: dsa.secretKey };
    const idSig = sign(pointerV2SigningInput(prefix, false), s.edSecret, s.dsaSecret);
    const authority = o.authority ? { edPublic: authPub.edPublic, dsaPublic: authPub.dsaPublic, sig: sign(pointerV2SigningInput(prefix, true), auth.edSecret, auth.dsa.secretKey) } : undefined;
    return { kind: 'pointer' as const, bytes: encodePointerV2(f, idSig, authority) };
  };
  return { held, make };
}
const heldWithPointer = async (w: ReturnType<typeof ptrWorld>, e = 10, over = {}) => {
  const first = await receive(w.held({ pointerEpoch: null }), w.make({ epoch: e }), NOW);
  assert.equal(first.action, 'accept');
  return w.held({ pointerEpoch: e, heldPointerDigest: (first as { digest: string }).digest, ...over });
};

// ---------- 0. the module is pure and dark ----------
test('Q0 pure: no clock, no randomness, no storage, no network, no process; imports only the codecs, the verifier seam and hashing', () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'rotation-receive.ts'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  for (const bad of ['Date.now', 'new Date', 'Math.random', 'getRandomValues', 'randomBytes', 'fetch(', 'indexedDB', 'localStorage', 'sessionStorage', 'process.', 'setTimeout', 'XMLHttpRequest', 'require(', 'readFileSync']) {
    assert.ok(!src.includes(bad), 'must not use ' + bad);
  }
  const imports = [...src.matchAll(/from '([^']+)'/g)].map((m) => m[1]).sort();
  assert.deepEqual(imports, ['../format/envelope', '../identity/fingerprint', './contact-update', './key-rotate-wire', './pointer-v2-wire', '@noble/hashes/sha2.js', '@noble/hashes/utils.js']);
});

test('Q0b dark: nothing outside tests imports rotation-receive', () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
  const hits: string[] = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      if (n === 'node_modules' || n === '.next' || n === '.git') continue;
      const p = join(d, n); const st = statSync(p);
      if (st.isDirectory()) { walk(p); continue; }
      if (!/\.(ts|tsx|mjs|js)$/.test(n) || /\.test\.|\.spec\./.test(n) || /rotation-receive\.ts$/.test(p)) continue;
      if (/from ['"][^'"]*rotation-receive['"]/.test(readFileSync(p, 'utf8'))) hits.push(p);
    }
  };
  for (const d of ['src', 'app', 'scripts']) { try { walk(join(root, d)); } catch { /* absent */ } }
  assert.deepEqual(hits, []);
});

// ---------- 1. successors ----------
test('S1 adopt: the next successor verifies and the new state is complete; the held state is untouched', async () => {
  const c = await ch();
  const d = await receive(c.held, succ(c.s1), NOW);
  assert.equal(d.action, 'adopt');
  const n = nextOf(d);
  assert.equal(n.identityEpoch, 1);
  assert.equal(n.durableId, c.g.fingerprint, 'the durable id never changes');
  assert.equal(n.operationalFingerprint, c.o1.fingerprint);
  assert.equal(n.rotationPin, deriveNextAuthorityCommitment(c.master, 2));
  assert.equal(n.pointerEpoch, null);
  assert.equal(n.rekeyPending, true);
  assert.equal(n.lastAcceptedAtMs, NOW);
  assert.deepEqual(n.pending, []);
  assert.equal(n.lastAdopted?.epoch, 1);
  assert.equal(n.lastAdopted?.priorPin, c.held.rotationPin);
  assert.equal(n.relay, c.held.relay, 'a plain rotation does not move the relay');
  assert.deepEqual(Array.from(n.identityKeys.dsaPublic), Array.from(b64d(c.o1.sigB64)), 'the new ML-DSA key is the one the successor carries');
  assert.equal(n.identityKeys.edPublic.length, 32);
  assert.notEqual(n, c.held);
  assert.equal(c.held.identityEpoch, 0, 'the input is not modified');
});

test('S1b adopt resets what belonged to the old keys: the held pointer, its digest, the pending list', async () => {
  const c = await ch();
  const stale = deepFreeze({ ...c.held, pointerEpoch: 7, heldPointerDigest: 'aa'.repeat(32), pending: [{ kind: 'pointer' as const, identityEpoch: 0, epoch: 9, digests: ['bb'.repeat(32)], firstSeenAtMs: NOW }] });
  const n = nextOf(await receive(stale, succ(c.s1), NOW));
  assert.equal(n.pointerEpoch, null);
  assert.equal(n.heldPointerDigest, undefined);
  assert.deepEqual(n.pending, []);
});

test('S2 R7.3: the SECOND rotation of a contact verifies, because the durable id (not the operational fingerprint) is what the verifier compares', async () => {
  const c = await ch();
  const h1 = nextOf(await receive(c.held, succ(c.s1), NOW));
  assert.notEqual(h1.operationalFingerprint, h1.durableId);
  const d2 = await receive(deepFreeze({ ...h1 }), succ(c.s2), NOW + 1000);
  assert.equal(act(d2), 'adopt');
  const h2 = nextOf(d2);
  assert.equal(h2.identityEpoch, 2);
  assert.equal(h2.durableId, c.g.fingerprint);
  assert.equal(h2.operationalFingerprint, c.o2.fingerprint);
});

test('S3 stale and duplicate: epoch at or below the held one changes nothing; a re-signed identical claim is a duplicate, not a conflict', async () => {
  const c = await ch();
  const h1 = deepFreeze({ ...nextOf(await receive(c.held, succ(c.s1), NOW)) });
  assert.equal(act(await receive(h1, succ(c.s1), NOW)), 'stale:stale-successor', 'byte-identical re-delivery');
  const resigned = successorFor(c.master, c.g.fingerprint, 1, c.o1); // same claim, fresh randomized ML-DSA signature
  assert.notDeepEqual(Array.from(encodeKeyRotate(resigned)), Array.from(encodeKeyRotate(c.s1)), 'the bytes really differ');
  assert.equal(act(await receive(h1, succ(resigned), NOW)), 'stale:stale-successor', 'same claim re-signed');
  // no record of the last adopt (e.g. state restored from before it): a second claim cannot be checked, so it stays stale, never an error
  assert.equal(act(await receive(deepFreeze({ ...h1, lastAdopted: null }), succ(c.s1b), NOW)), 'stale:stale-successor');
  assert.equal(act(await receive(h1, succ({ ...c.s1, successor_epoch: 0, prior_epoch: 0 } as RotationSuccessorInput), NOW)), 'stale:stale-successor', 'an epoch below the held one');
});

test('S4 CONFLICT (Flint #7291): a different VALID successor for the epoch just adopted is recorded, both digests, WITHOUT un-adopting; nothing freezes', async () => {
  const c = await ch();
  const h1 = deepFreeze({ ...nextOf(await receive(c.held, succ(c.s1), NOW)) });
  const d = await receive(h1, succ(c.s1b), NOW + 5);
  assert.equal(d.action, 'conflict');
  const n = nextOf(d);
  assert.equal(n.identityEpoch, 1, 'not un-adopted');
  assert.equal(n.operationalFingerprint, c.o1.fingerprint, 'still the first key');
  assert.equal(n.conflicts.length, 1);
  assert.equal(n.conflicts[0].kind, 'successor');
  assert.equal(n.conflicts[0].digests.length, 2);
  assert.equal(n.conflicts[0].digests[0], h1.lastAdopted?.digest);
  assert.notEqual(n.conflicts[0].digests[0], n.conflicts[0].digests[1]);
  // it is detection only: the owner's next rotation still lands, and the record stays
  const d2 = await receive(deepFreeze({ ...n }), succ(c.s2), NOW + 9);
  assert.equal(act(d2), 'adopt');
  assert.equal(nextOf(d2).conflicts.length, 1, 'the successor conflict stays recorded after the next adopt');
  // delivering the same second claim again is not a new conflict
  assert.equal(act(await receive(deepFreeze({ ...n }), succ(c.s1b), NOW + 6)), 'stale:stale-successor');
});

test('S5 ahead: epoch + 2 is HELD, never adopted, nothing stored; the codec epoch is only a routing claim', async () => {
  const c = await ch();
  const d = await receive(c.held, succ(c.s3), NOW);
  assert.equal(act(d), 'hold:successor-ahead');
  assert.ok(!('next' in d));
  const d2 = await receive(c.held, succ(c.s2), NOW);
  assert.equal(act(d2), 'hold:successor-ahead', 'epoch 2 against held 0 is ahead, even though it would verify after epoch 1');
});

test('S6 refusals: wrong pin, empty pin, wrong durable id, tampered fingerprint, tampered signature; each is a reason code and changes nothing', async () => {
  const c = await ch();
  const r = async (held: HeldIdentity, s: RotationSuccessorInput) => act(await receive(held, succ(s), NOW));
  assert.equal(await r(deepFreeze({ ...c.held, rotationPin: bytesToHex(sha256(randomBytes(4))) }), c.s1), 'refuse:rotation-commitment-mismatch');
  assert.equal(await r(deepFreeze({ ...c.held, rotationPin: '' }), c.s1), 'refuse:rotation-commitment-mismatch');
  assert.equal(await r(deepFreeze({ ...c.held, durableId: bytesToHex(sha256(randomBytes(4))) }), c.s1), 'refuse:wrong-origin');
  assert.equal(await r(c.held, { ...c.s1, new_fingerprint: c.o1b.fingerprint }), 'refuse:rotation-bad-authority-sig');
  const sig = c.s1.auth as { sig_by_authority: string };
  const flipped = sig.sig_by_authority.slice(0, 10) + (sig.sig_by_authority[10] === 'a' ? 'b' : 'a') + sig.sig_by_authority.slice(11);
  assert.equal(await r(c.held, { ...c.s1, auth: { ...c.s1.auth, sig_by_authority: flipped } as RotationSuccessorInput['auth'] }), 'refuse:rotation-bad-authority-sig');
});

// ---------- 2. pointers ----------
test('P1 accept: a verified pointer at the held identity epoch, higher epoch within the ceiling, same relay', async () => {
  const w = ptrWorld();
  const h = w.held({ pointerEpoch: 10, heldPointerDigest: 'aa'.repeat(32) });
  const d = await receive(h, w.make({ epoch: 11 }), NOW + 1);
  assert.equal(d.action, 'accept');
  const n = nextOf(d);
  assert.equal(n.pointerEpoch, 11);
  assert.equal(n.lastAcceptedAtMs, NOW + 1);
  assert.equal(n.heldPointerDigest, (d as { digest: string }).digest);
  assert.equal(h.pointerEpoch, 10);
  const first = await receive(w.held({ pointerEpoch: null, lastAcceptedAtMs: null }), w.make({ epoch: 3 }), NOW);
  assert.equal(act(first), 'accept', 'the first pointer for a contact is accepted within the ceiling');
});

test('P2 a pointer is verified against the HELD keys: another signer is refused, and nothing in the pointer can name the keys', async () => {
  const w = ptrWorld();
  const other = { edSecret: randomBytes(32), dsaSecret: ml_dsa87.keygen(randomBytes(32)).secretKey };
  assert.equal(act(await receive(w.held(), w.make({ epoch: 11, signer: other }), NOW)), 'refuse:bad-identity-sig');
  const noPin = w.held({ ownerAuthorityPin: undefined });
  assert.equal(act(await receive(noPin, w.make({ epoch: 12, authority: true }), NOW)), 'refuse:no-authority-pin');
  const wrongPin = w.held({ ownerAuthorityPin: 'ab'.repeat(32) });
  assert.equal(act(await receive(wrongPin, w.make({ epoch: 12, authority: true }), NOW)), 'refuse:authority-pin-mismatch');
});

test('P3 identity epoch: lower is stale; a claim ABOVE the adopted epoch from the held keys is incoherent and refused', async () => {
  const w = ptrWorld();
  const h = w.held({ identityEpoch: 2 });
  assert.equal(act(await receive(h, w.make({ epoch: 11, identityEpoch: 1 }), NOW)), 'stale:stale-identity-epoch');
  assert.equal(act(await receive(h, w.make({ epoch: 11, identityEpoch: 3 }), NOW)), 'refuse:identity-epoch-ahead');
  assert.equal(act(await receive(h, w.make({ epoch: 11, identityEpoch: 2 }), NOW)), 'accept');
});

test('P4 epoch order at one identity epoch: lower stale; same claim idempotent; a different claim is a CONFLICT that freezes pointers only', async () => {
  const w = ptrWorld();
  const h = await heldWithPointer(w, 10);
  assert.equal(act(await receive(h, w.make({ epoch: 9 }), NOW)), 'stale:stale-pointer');
  const same = await receive(h, w.make({ epoch: 10 }), NOW);
  assert.equal(act(same), 'accept');
  assert.equal((same as { idempotent: boolean }).idempotent, true);
  assert.ok(!('next' in same), 'an idempotent accept changes nothing');
  const d = await receive(h, w.make({ epoch: 10, x: 0x77 }), NOW);
  assert.equal(d.action, 'conflict');
  const n = nextOf(d);
  assert.equal(n.pointerEpoch, 10, 'the held pointer is unchanged');
  assert.equal(n.heldPointerDigest, h.heldPointerDigest);
  assert.equal(n.conflicts[0].digests.length, 2);
  const frozen = deepFreeze({ ...n });
  assert.equal(act(await receive(frozen, w.make({ epoch: 11 }), NOW)), 'refuse:conflict-open', 'no pointer is accepted while a pointer conflict is open');
  assert.equal(act(await receive(frozen, w.make({ epoch: 10, x: 0x78 }), NOW)), 'refuse:conflict-open');
});

test('P4c a POINTER conflict never blocks a successor (the owner\'s escape), and the adopt clears it because it was about the old keys', async () => {
  const c = await ch();
  const open = deepFreeze({ ...c.held, conflicts: [{ kind: 'pointer' as const, identityEpoch: 0, epoch: 5, digests: ['aa'.repeat(32), 'bb'.repeat(32)] }] });
  const d = await receive(open, succ(c.s1), NOW);
  assert.equal(act(d), 'adopt');
  assert.deepEqual(nextOf(d).conflicts, []);
  const both = deepFreeze({ ...c.held, conflicts: [{ kind: 'pointer' as const, identityEpoch: 0, epoch: 5, digests: ['aa'.repeat(32), 'bb'.repeat(32)] }, { kind: 'successor' as const, identityEpoch: 0, epoch: 0, digests: ['cc'.repeat(32), 'dd'.repeat(32)] }] });
  assert.deepEqual(nextOf(await receive(both, succ(c.s1), NOW)).conflicts.map((x) => x.kind), ['successor'], 'a successor conflict is kept as the record it is');
});

test('P4b settle: only the receiver\'s own named choice passes, and only a digest that is in the conflict', async () => {
  const w = ptrWorld();
  const h = await heldWithPointer(w, 10);
  const n = deepFreeze({ ...nextOf(await receive(h, w.make({ epoch: 10, x: 0x77 }), NOW)) });
  const chosen = n.conflicts[0].digests[1];
  const d = await receive(n, w.make({ epoch: 10, x: 0x77 }), NOW + 3, { settleDigest: chosen });
  assert.equal(d.action, 'accept');
  const s = nextOf(d);
  assert.equal(s.heldPointerDigest, chosen);
  assert.deepEqual(s.conflicts, []);
  assert.equal(act(await receive(n, w.make({ epoch: 10, x: 0x77 }), NOW + 3, { settleDigest: 'cd'.repeat(32) })), 'refuse:conflict-open', 'a digest not in the conflict settles nothing');
  assert.equal(act(await receive(n, w.make({ epoch: 12 }), NOW + 3, { settleDigest: chosen })), 'refuse:conflict-open', 'a different object cannot ride the settle');
  // a THIRD claim that names ITS OWN digest as the choice is still refused: the choice must be one of the conflicting claims
  const third = w.make({ epoch: 10, x: 0x79 });
  const thirdDigest = (await receive(w.held({ pointerEpoch: null }), third, NOW) as { digest: string }).digest;
  assert.ok(!n.conflicts[0].digests.includes(thirdDigest));
  assert.equal(act(await receive(n, third, NOW + 3, { settleDigest: thirdDigest })), 'refuse:conflict-open', 'a digest outside the conflict settles nothing, even named by its own object');
});

test('P5 the ceiling: identity-only <= held + 16 + A, never above; authority-signed jumps any distance', async () => {
  const w = ptrWorld();
  const at = (e: number, lastAcceptedAtMs: number | null, nowMs: number, authority = false) => receive(w.held({ pointerEpoch: 10, lastAcceptedAtMs }), w.make({ epoch: e, authority }), nowMs).then(act);
  assert.equal(await at(10 + POINTER_CEILING_STEP, NOW, NOW), 'accept', 'held + 16');
  assert.equal(await at(10 + POINTER_CEILING_STEP + 1, NOW, NOW), 'refuse:above-ceiling', 'held + 17');
  assert.equal(await at(Number.MAX_SAFE_INTEGER, NOW, NOW), 'refuse:above-ceiling', '2^53 - 1');
  assert.equal(await at(10 + 16 + 1, NOW - WEEK_MS, NOW), 'accept', 'one week away: A = 1');
  assert.equal(await at(10 + 16 + 2, NOW - WEEK_MS, NOW), 'refuse:above-ceiling');
  assert.equal(await at(10 + 16 + 64, NOW - 64 * WEEK_MS, NOW), 'accept', 'A = 64');
  assert.equal(await at(10 + 16 + 65, NOW - 200 * WEEK_MS, NOW), 'refuse:above-ceiling', 'A is clamped at 64 however long the absence');
  assert.equal(await at(10 + 16 + 1, NOW + 30 * 24 * 3600_000, NOW), 'refuse:above-ceiling', 'a clock that went backward gives A = 0');
  assert.equal(await at(10 + 16 + 1, null, NOW), 'refuse:above-ceiling', 'never accepted gives A = 0');
  assert.equal(await at(10 + 16, NOW + 30 * 24 * 3600_000, NOW), 'accept', 'a clock that went backward gives A = 0, not a negative allowance: held + 16 still passes');
  assert.equal(await at(10 + 16, null, NOW), 'accept', 'never accepted: held + 16 passes');
  assert.equal(await at(510, NOW, NOW, true), 'accept', 'authority-signed: held + 500');
  assert.equal(await at(Number.MAX_SAFE_INTEGER, NOW, NOW, true), 'accept', 'authority-signed: any epoch');
  assert.equal(pointerAllowance(NOW - 3 * WEEK_MS - 1, NOW), 3);
  assert.equal(pointerAllowance(NOW, NOW), 0);
});

test('P5b with nothing held, an identity-only pointer is bounded by the same ceiling from 0', async () => {
  const w = ptrWorld();
  const at = (e: number) => receive(w.held({ pointerEpoch: null, lastAcceptedAtMs: null }), w.make({ epoch: e }), NOW).then(act);
  assert.equal(await at(POINTER_CEILING_STEP), 'accept');
  assert.equal(await at(POINTER_CEILING_STEP + 1), 'refuse:above-ceiling');
});

test('P6 relay: identity-only may not name another relay; an authority-signed change is PENDING with windowRequired and is never applied', async () => {
  const w = ptrWorld();
  const h = await heldWithPointer(w, 10);
  assert.equal(act(await receive(h, w.make({ epoch: 11, relay: 'https://other.example.net' }), NOW)), 'refuse:relay-change-needs-authority');
  const d = await receive(h, w.make({ epoch: 11, relay: 'https://other.example.net', authority: true }), NOW + 7);
  assert.equal(d.action, 'pend');
  assert.equal((d as { windowRequired: boolean }).windowRequired, true);
  assert.deepEqual((d as { relayChange: unknown }).relayChange, { from: 'https://relay.example.org', to: 'https://other.example.net' });
  const n = nextOf(d);
  assert.equal(n.relay, 'https://relay.example.org', 'the relay is NOT moved');
  assert.equal(n.pointerEpoch, 10, 'the held pointer is not replaced');
  assert.equal(n.pending.length, 1);
  assert.equal(n.pending[0].firstSeenAtMs, NOW + 7, 'the contact\'s own clock');
  // the same claim again: still pending, nothing new to write
  const again = await receive(deepFreeze({ ...n }), w.make({ epoch: 11, relay: 'https://other.example.net', authority: true }), NOW + 99);
  assert.equal(again.action, 'pend');
  assert.ok(!('next' in again));
  // a DIFFERENT valid claim at the same epoch while pending: adopt neither
  const c = await receive(deepFreeze({ ...n }), w.make({ epoch: 11, relay: 'https://third.example.net', authority: true }), NOW + 100);
  assert.equal(c.action, 'conflict');
  assert.equal(nextOf(c).conflicts[0].digests.length, 2);
  assert.equal(nextOf(c).relay, 'https://relay.example.org');
});

test('P7 pending is bounded and never evicts; the owner\'s escape (a successor, a same-relay pointer) still works with it full', async () => {
  const w = ptrWorld();
  assert.equal(PENDING_MAX_KEYS, 8, 'the agreed bound (Flint #7288)');
  const full: PendingEntry[] = Array.from({ length: PENDING_MAX_KEYS }, (_, i) => ({ kind: 'pointer', identityEpoch: 1, epoch: 100 + i, digests: [bytesToHex(sha256(Uint8Array.of(i)))], firstSeenAtMs: NOW }));
  const h = await heldWithPointer(w, 10, { pending: full });
  const d = await receive(h, w.make({ epoch: 11, relay: 'https://other.example.net', authority: true }), NOW);
  assert.equal(act(d), 'refuse:pending-full', 'the newest is refused');
  assert.equal(h.pending.length, PENDING_MAX_KEYS, 'nothing was evicted');
  assert.equal(act(await receive(h, w.make({ epoch: 12 }), NOW)), 'accept', 'a same-relay identity-only pointer is unaffected');
  assert.equal(act(await receive(h, w.make({ epoch: 13, authority: true }), NOW)), 'accept', 'a same-relay authority-signed pointer is unaffected');
  assert.equal(act(await receive(h, w.make({ epoch: 14, relay: 'https://x.example.net' }), NOW)), 'refuse:relay-change-needs-authority');
  assert.equal(h.pending.length, PENDING_MAX_KEYS, 'an identity-only relay attempt (all a device thief can make) never touches pending');
  const c = await ch();
  const fullReal = deepFreeze({ ...c.held, pending: full });
  const a = await receive(fullReal, succ(c.s1), NOW);
  assert.equal(act(a), 'adopt', 'a successor adopts with pending full');
  assert.deepEqual(nextOf(a).pending, [], 'and clears it: pending belongs to the old keys');
});

test('P8 an accepted pointer clears the pending entries at or below its epoch, for its identity epoch only', async () => {
  const w = ptrWorld();
  const mk = (identityEpoch: number, epoch: number): PendingEntry => ({ kind: 'pointer', identityEpoch, epoch, digests: ['ee'.repeat(32)], firstSeenAtMs: NOW });
  const h = await heldWithPointer(w, 10, { pending: [mk(1, 11), mk(1, 12), mk(1, 20), mk(0, 11)] });
  const n = nextOf(await receive(h, w.make({ epoch: 12 }), NOW + 1));
  assert.deepEqual(n.pending.map((e) => [e.identityEpoch, e.epoch]), [[1, 20], [0, 11]]);
});

test('P9 a re-signed identical pointer is the SAME claim: idempotent, not a conflict (ML-DSA signatures are randomized)', async () => {
  const w = ptrWorld();
  const a = w.make({ epoch: 10 }), b = w.make({ epoch: 10 });
  assert.notDeepEqual(Array.from(a.bytes), Array.from(b.bytes), 'the bytes really differ');
  const first = await receive(w.held({ pointerEpoch: null }), a, NOW);
  const h = w.held({ pointerEpoch: 10, heldPointerDigest: (first as { digest: string }).digest });
  const d = await receive(h, b, NOW);
  assert.equal(act(d), 'accept');
  assert.equal((d as { idempotent: boolean }).idempotent, true);
});

// ---------- 3. inputs, purity of effect, no echo ----------
test('X1 inputs: a bad held state, a bad clock, an unknown kind, garbage bytes are refusals with a code and no part of the input', async () => {
  const w = ptrWorld();
  const h = w.held();
  const good = w.make({ epoch: 11 });
  assert.equal(act(await receive({ ...h, durableId: 'nope' } as HeldIdentity, good, NOW)), 'refuse:bad-held');
  assert.equal(act(await receive({ ...h, identityKeys: { edPublic: new Uint8Array(5), dsaPublic: h.identityKeys.dsaPublic } } as HeldIdentity, good, NOW)), 'refuse:bad-held');
  assert.equal(act(await receive({ ...h, pending: undefined } as unknown as HeldIdentity, good, NOW)), 'refuse:bad-held');
  assert.equal(act(await receive(h, good, -1)), 'refuse:bad-now');
  assert.equal(act(await receive(h, good, 1.5)), 'refuse:bad-now');
  assert.equal(act(await receive(h, { kind: 'nope' as 'pointer', bytes: good.bytes }, NOW)), 'refuse:bad-kind');
  const junk = new TextEncoder().encode('MARKER-ATTACKER-STRING');
  for (const kind of ['pointer', 'successor'] as const) {
    const d = await receive(h, { kind, bytes: junk }, NOW);
    assert.equal(d.action, 'refuse');
    assert.ok(!JSON.stringify(d).includes('MARKER'), 'no echo of the input');
    assert.match((d as { reason: string }).reason, /^malformed:[a-z-]+$/);
  }
});

test('X2 effects: a decision with a next state returns a NEW object and the input stays byte-for-byte what it was', async () => {
  const w = ptrWorld();
  const h = w.held({ pointerEpoch: 10, heldPointerDigest: 'aa'.repeat(32), pending: [] });
  const before = JSON.stringify(h);
  const d = await receive(h, w.make({ epoch: 11 }), NOW);
  assert.notEqual(nextOf(d), h);
  assert.equal(JSON.stringify(h), before);
  assert.ok(Object.isFrozen(d));
  assert.ok(Object.isFrozen(nextOf(d)));
});
