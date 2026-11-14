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
import { randomBytes, bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import { deriveNextAuthorityCommitment, deriveNextAuthorityKeypair, encodeAuthorityPubkeys, signRotationAuthority, mintCanonicalFingerprint, canonicalPubsFromArmoredPublicKey } from '../identity/fingerprint';
import { rotationSigningInput } from '../format/envelope';
import { ownerAuthorityCommitment } from '../crypto/owner-authority-commitment';
import type { RotationSuccessorInput } from './contact-update';
import { encodeKeyRotate } from './key-rotate-wire';
import { encodeApprove, approveBody, approveSigningInput } from './approve-wire';
import { pointerClaimDigest } from './claim-digest';
import { parsePointerV2 } from './pointer-v2-wire';
import { encodePointerV2, pointerV2Prefix, pointerV2SigningInput, type HybridSig, type PointerV2Fields } from './pointer-v2-wire';
import { receive, pointerAllowance, POINTER_CEILING_STEP, PENDING_MAX_KEYS, SUCCESSOR_CONFLICT_MAX_DIGESTS, SUCCESSOR_WINDOW_MS, WEEK_MS, type HeldIdentity, type PendingEntry, type Decision } from './rotation-receive';

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
  const o1c = await makeOperational('g1c'), o1d = await makeOperational('g1d'), o1e = await makeOperational('g1e');
  const gp = await canonicalPubsFromArmoredPublicKey(g.publicKey, g.kemB64, g.sigB64);
  const held: HeldIdentity = deepFreeze({
    durableId: g.fingerprint, identityEpoch: 0, identityKeys: { edPublic: gp.signPub, dsaPublic: gp.sigPub }, operationalFingerprint: g.fingerprint,
    classicalPublicKeyArmored: g.publicKey, rotationPin: deriveNextAuthorityCommitment(master, 1), pointerEpoch: null, relay: 'https://relay.example.org',
    lastAcceptedAtMs: null, pending: [], conflicts: [], lastAdopted: null, rekeyPending: false,
  });
  const s1 = successorFor(master, g.fingerprint, 1, o1);
  const s1b = successorFor(master, g.fingerprint, 1, o1b); // a DIFFERENT valid successor for the same epoch (same master)
  const s1c = successorFor(master, g.fingerprint, 1, o1c), s1d = successorFor(master, g.fingerprint, 1, o1d), s1e = successorFor(master, g.fingerprint, 1, o1e);
  const s2 = successorFor(master, g.fingerprint, 2, o2);
  const s3 = successorFor(master, g.fingerprint, 3, o2); // only its epoch matters: it is ahead
  return { master, g, o1, o1b, o2, held, s1, s1b, s1c, s1d, s1e, s2, s3 };
}
let CH: Awaited<ReturnType<typeof chain>>;
const ch = async () => (CH ??= await chain());
const succ = (s: RotationSuccessorInput) => ({ kind: 'successor' as const, bytes: encodeKeyRotate(s) });
/** A successor takes effect only through the HOLD (Flint #7546): arrival pends, the same claim again once the window has passed adopts. */
const adopted = async (held: HeldIdentity, s: RotationSuccessorInput, now = NOW): Promise<HeldIdentity> => {
  const p = await receive(held, succ(s), now);
  assert.equal(act(p), 'pend', 'arrival only holds the claim');
  const d = await receive(deepFreeze({ ...nextOf(p) }), succ(s), now + SUCCESSOR_WINDOW_MS);
  assert.equal(act(d), 'adopt', 'the same claim after the window adopts');
  return nextOf(d);
};

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
  /** An APPROVE record for `held`, over a pointer made by `make` with an authority block; signed by the world's identity and authority secrets. */
  const approveFor = (h: HeldIdentity, pointer: { bytes: Uint8Array }, o: { epoch?: number; idSigner?: { edSecret: Uint8Array; dsaSecret: Uint8Array } } = {}) => {
    const subject = pointer.bytes;
    const verified = parsePointerV2(subject).verify({ identity: h.identityKeys, authorityPin: h.ownerAuthorityPin });
    const f = { kind: 1, durableId: hexToBytes(h.durableId), identityEpoch: o.epoch ?? h.identityEpoch, claimDigest: pointerClaimDigest(verified), subject };
    const body = approveBody(f);
    const is = o.idSigner ?? { edSecret, dsaSecret: dsa.secretKey };
    return { kind: 'approve' as const, bytes: encodeApprove(f, authPub, sign(approveSigningInput(body, 'identity'), is.edSecret, is.dsaSecret), sign(approveSigningInput(body, 'authority'), auth.edSecret, auth.dsa.secretKey)) };
  };
  return { held, make, approveFor };
}
const heldWithPointer = async (w: ReturnType<typeof ptrWorld>, e = 10, over = {}) => {
  const first = await receive(w.held({ pointerEpoch: null }), w.make({ epoch: e }), NOW);
  assert.equal(first.action, 'accept');
  return w.held({ pointerEpoch: e, heldPointerDigest: (first as { digest: string }).digest, ...over });
};

// ---------- 0. the module is pure and dark ----------
test('Q0 pure: no clock, no randomness, no storage, no network, no process; imports only the codecs, the digest helper and the canonical-keys helper', () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'rotation-receive.ts'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  for (const bad of ['Date.now', 'new Date', 'Math.random', 'getRandomValues', 'randomBytes', 'fetch(', 'indexedDB', 'localStorage', 'sessionStorage', 'process.', 'setTimeout', 'XMLHttpRequest', 'require(', 'readFileSync']) {
    assert.ok(!src.includes(bad), 'must not use ' + bad);
  }
  const imports = [...src.matchAll(/from '([^']+)'/g)].map((m) => m[1]).sort();
  assert.deepEqual(imports, ['../identity/fingerprint', './approve-wire', './claim-digest', './contact-update', './key-rotate-wire', './pointer-v2-wire']);
});

test('Q0b dark: nothing outside tests imports rotation-receive', () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
  const hits: string[] = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      if (n === 'node_modules' || n === '.next' || n === '.git') continue;
      const p = join(d, n); const st = statSync(p);
      if (st.isDirectory()) { walk(p); continue; }
      if (!/\.(ts|tsx|mjs|js)$/.test(n) || /\.test\.|\.spec\./.test(n) || p.endsWith('/src/lib/trust/rotation-receive.ts')) continue;
      if (/from ['"][^'"]*rotation-receive['"]/.test(readFileSync(p, 'utf8'))) hits.push(p);
    }
  };
  for (const d of ['src', 'app', 'scripts']) { try { walk(join(root, d)); } catch { /* absent */ } }
  assert.deepEqual(hits, []);
});

// ---------- 1. successors ----------
test('S1 hold, then adopt: arrival only RECORDS a verified successor (a phrase alone must not rotate anyone); the same claim after the window adopts, and the new state is complete', async () => {
  const c = await ch();
  const first = await receive(c.held, succ(c.s1), NOW);
  assert.equal(act(first), 'pend', 'arrival holds');
  assert.equal((first as { windowEndsAtMs: number }).windowEndsAtMs, NOW + SUCCESSOR_WINDOW_MS);
  assert.equal(SUCCESSOR_WINDOW_MS, 72 * 3600 * 1000, 'the agreed window: 72 h (Flint #7646)');
  const h1 = nextOf(first);
  assert.equal(h1.identityEpoch, 0, 'nothing adopted on arrival');
  assert.equal(h1.operationalFingerprint, c.g.fingerprint);
  assert.equal(h1.rotationPin, c.held.rotationPin);
  assert.deepEqual(h1.pending.map((e) => [e.kind, e.identityEpoch, e.epoch, e.digests.length, e.firstSeenAtMs]), [['successor', 1, 1, 1, NOW]]);
  assert.equal(c.held.pending.length, 0, 'the input is not modified');
  const d = await receive(deepFreeze({ ...h1 }), succ(c.s1), NOW + SUCCESSOR_WINDOW_MS);
  assert.equal(d.action, 'adopt');
  const n = nextOf(d);
  assert.equal(n.identityEpoch, 1);
  assert.equal(n.durableId, c.g.fingerprint, 'the durable id never changes');
  assert.equal(n.operationalFingerprint, c.o1.fingerprint);
  assert.equal(n.rotationPin, deriveNextAuthorityCommitment(c.master, 2));
  assert.equal(n.pointerEpoch, null);
  assert.equal(n.rekeyPending, true);
  assert.equal(n.lastAcceptedAtMs, NOW + SUCCESSOR_WINDOW_MS);
  assert.deepEqual(n.pending, [], 'the held entry is gone once adopted');
  assert.equal(n.lastAdopted?.epoch, 1);
  assert.equal(n.lastAdopted?.priorPin, c.held.rotationPin);
  assert.equal(n.relay, c.held.relay, 'a plain rotation does not move the relay');
  const claim = rotationSigningInput({ durable_id: c.s1.durable_id, prior_epoch: 0, prior_authority_commitment: c.held.rotationPin, successor_epoch: 1, new_fingerprint: c.o1.fingerprint, next_authority_commitment: deriveNextAuthorityCommitment(c.master, 2) });
  assert.equal(n.lastAdopted?.digest, bytesToHex(sha256(new TextEncoder().encode(claim))), 'the successor digest is SHA-256 of the canonical rotation signing input, computed here independently of the helper');
  assert.deepEqual(Array.from(n.identityKeys.dsaPublic), Array.from(b64d(c.o1.sigB64)), 'the new ML-DSA key is the one the successor carries');
  assert.equal(n.identityKeys.edPublic.length, 32);
  assert.notEqual(n, c.held);
  assert.equal(c.held.identityEpoch, 0, 'the input is not modified');
});

test('S1b adopt resets what belonged to the old keys: the held pointer, its digest, the pending list', async () => {
  const c = await ch();
  const stale = deepFreeze({ ...c.held, pointerEpoch: 7, heldPointerDigest: 'aa'.repeat(32), pending: [{ kind: 'pointer' as const, identityEpoch: 0, epoch: 9, digests: ['bb'.repeat(32)], firstSeenAtMs: NOW }] });
  const p = await receive(stale, succ(c.s1), NOW);
  assert.equal(act(p), 'pend');
  assert.deepEqual(nextOf(p).pending.map((e) => e.kind), ['pointer', 'successor'], 'while held, the pointer entry for the old keys is untouched');
  assert.equal(nextOf(p).pointerEpoch, 7, 'and so is the held pointer');
  const n = await adopted(stale, c.s1);
  assert.equal(n.pointerEpoch, null);
  assert.equal(n.heldPointerDigest, undefined);
  assert.deepEqual(n.pending, []);
});

test('S2 R7.3: the SECOND rotation of a contact verifies, because the durable id (not the operational fingerprint) is what the verifier compares', async () => {
  const c = await ch();
  const h1 = await adopted(c.held, c.s1);
  assert.notEqual(h1.operationalFingerprint, h1.durableId);
  const h2 = await adopted(deepFreeze({ ...h1 }), c.s2, NOW + 2 * SUCCESSOR_WINDOW_MS);
  assert.equal(h2.identityEpoch, 2);
  assert.equal(h2.durableId, c.g.fingerprint);
  assert.equal(h2.operationalFingerprint, c.o2.fingerprint);
});

test('S3 stale and duplicate: epoch at or below the held one changes nothing; a re-signed identical claim is a duplicate, not a conflict', async () => {
  const c = await ch();
  const h1 = deepFreeze({ ...(await adopted(c.held, c.s1)) });
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
  const h1 = deepFreeze({ ...(await adopted(c.held, c.s1)) });
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
  const h2 = await adopted(deepFreeze({ ...n }), c.s2, NOW + 3 * SUCCESSOR_WINDOW_MS);
  assert.equal(h2.conflicts.length, 1, 'the successor conflict stays recorded after the next adopt');
  // delivering the same second claim again is not a new conflict
  assert.equal(act(await receive(deepFreeze({ ...n }), succ(c.s1b), NOW + 6)), 'stale:stale-successor');
});

test('S4b (Flint #7317 a) a third, fourth, fifth different valid successor APPENDS to the conflict (the second digest is kept), up to a cap', async () => {
  const c = await ch();
  let h: HeldIdentity = deepFreeze({ ...(await adopted(c.held, c.s1)) });
  const seen: string[] = [h.lastAdopted!.digest];
  for (const [i, s] of [c.s1b, c.s1c, c.s1d].entries()) {
    const d = await receive(h, succ(s), NOW + i);
    assert.equal(d.action, 'conflict', 'claim ' + (i + 2));
    h = deepFreeze({ ...nextOf(d) });
    const ds = h.conflicts.find((x) => x.kind === 'successor')!.digests;
    assert.equal(ds.length, i + 2);
    assert.deepEqual(ds.slice(0, seen.length), seen, 'earlier digests are kept, in order');
    seen.push(ds[ds.length - 1]);
  }
  assert.equal(new Set(seen).size, SUCCESSOR_CONFLICT_MAX_DIGESTS, 'four different claims');
  assert.equal(act(await receive(h, succ(c.s1e), NOW + 9)), 'stale:stale-successor', 'past the cap there is nothing more to add');
  assert.equal(h.conflicts.find((x) => x.kind === 'successor')!.digests.length, SUCCESSOR_CONFLICT_MAX_DIGESTS);
  assert.equal(act(await receive(h, succ(c.s1c), NOW + 9)), 'stale:stale-successor', 'a claim already recorded is not added again');
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

// ---------- 1b. the HOLD (Flint #7546, Archie #7548): a successor proves the authority only, so it waits ----------
test('H1 window: a redelivery inside the window writes nothing and keeps the ORIGINAL end; at exactly the window the same claim adopts (even re-signed); a clock that goes backward cannot shorten it', async () => {
  const c = await ch();
  const h1 = deepFreeze({ ...nextOf(await receive(c.held, succ(c.s1), NOW)) });
  const end = NOW + SUCCESSOR_WINDOW_MS;
  const early = await receive(h1, succ(c.s1), end - 1);
  assert.equal(act(early), 'pend');
  assert.ok(!('next' in early), 'a redelivery inside the window writes nothing');
  assert.equal((early as { windowEndsAtMs: number }).windowEndsAtMs, end, 'the end is measured from the FIRST sight and never moved by a later arrival');
  const back = await receive(h1, succ(c.s1), NOW - 1000);
  assert.equal(act(back), 'pend', 'a clock that moved backward does not adopt');
  assert.equal((back as { windowEndsAtMs: number }).windowEndsAtMs, end);
  assert.equal(act(await receive(h1, succ(c.s1), end)), 'adopt', 'exactly at the window');
  const resigned = successorFor(c.master, c.g.fingerprint, 1, c.o1); // same claim, fresh randomized signature: the digest is of the CLAIM
  assert.equal(act(await receive(h1, succ(resigned), end)), 'adopt', 'a re-signed copy of the same claim counts as the same claim');
});

test('H2 contested: a different valid claim for the epoch makes it a contest; neither adopts however long it waits, until the receiver names one', async () => {
  const c = await ch();
  const a = await receive(c.held, succ(c.s1), NOW);
  const b = await receive(deepFreeze({ ...nextOf(a) }), succ(c.s1b), NOW + 5);
  assert.equal(b.action, 'conflict');
  const h2 = deepFreeze({ ...nextOf(b) });
  const entry = h2.pending.find((e) => e.kind === 'successor')!;
  assert.equal(entry.digests.length, 2);
  assert.equal(entry.firstSeenAtMs, NOW, 'the contest does not restart the clock');
  assert.equal(h2.identityEpoch, 0, 'nothing adopted');
  const late = NOW + 10 * SUCCESSOR_WINDOW_MS;
  assert.equal(act(await receive(h2, succ(c.s1), late)), 'refuse:conflict-open', 'waiting does not settle it');
  assert.equal(act(await receive(h2, succ(c.s1b), late)), 'refuse:conflict-open');
  assert.equal(act(await receive(h2, succ(c.s1), late, { settleDigest: 'cc'.repeat(32) })), 'refuse:conflict-open', 'a digest that is not in the contest settles nothing');
  const s = await receive(h2, succ(c.s1), NOW + 6, { settleDigest: entry.digests[0] });
  assert.equal(act(s), 'adopt', 'the receiver\'s own choice adopts at once, before the window');
  const n = nextOf(s);
  assert.equal(n.operationalFingerprint, c.o1.fingerprint);
  assert.equal(n.conflicts.length, 1);
  assert.equal(n.conflicts[0].kind, 'successor');
  assert.equal(n.conflicts[0].digests.length, 2, 'the losing claim stays as evidence of a second master holder');
  assert.equal(n.conflicts[0].digests[0], entry.digests[0], 'the chosen claim first');
  assert.deepEqual(n.pending, []);
  const other = await receive(h2, succ(c.s1b), NOW + 6, { settleDigest: entry.digests[1] });
  assert.equal(act(other), 'adopt', 'naming the other claim picks the other key');
  assert.equal(nextOf(other).operationalFingerprint, c.o1b.fingerprint);
});

test('H3 a contest keeps up to SUCCESSOR_CONFLICT_MAX_DIGESTS different claims; after that nothing more is added', async () => {
  const c = await ch();
  let h: HeldIdentity = deepFreeze({ ...nextOf(await receive(c.held, succ(c.s1), NOW)) });
  for (const [i, s] of [c.s1b, c.s1c, c.s1d].entries()) {
    const d = await receive(h, succ(s), NOW + 1 + i);
    assert.equal(d.action, 'conflict', 'claim ' + (i + 2));
    h = deepFreeze({ ...nextOf(d) });
  }
  assert.equal(h.pending.find((e) => e.kind === 'successor')!.digests.length, SUCCESSOR_CONFLICT_MAX_DIGESTS);
  const over = await receive(h, succ(c.s1e), NOW + 9);
  assert.equal(act(over), 'stale:stale-successor');
  assert.ok(!('next' in over));
});

test('H4 the successor entry is keyed by KIND: a pointer entry at the same numbers is left alone and is not mistaken for the successor', async () => {
  const c = await ch();
  const ptr: PendingEntry = { kind: 'pointer', identityEpoch: 1, epoch: 1, digests: ['dd'.repeat(32)], firstSeenAtMs: NOW - 5 };
  const d = await receive(deepFreeze({ ...c.held, pending: [ptr] }), succ(c.s1), NOW);
  assert.equal(act(d), 'pend');
  assert.deepEqual(nextOf(d).pending.map((e) => [e.kind, e.firstSeenAtMs]), [['pointer', NOW - 5], ['successor', NOW]]);
});

test('H5 only a VERIFIED claim is recorded, and the entry holds digests and a time, never the object', async () => {
  const c = await ch();
  const bad = await receive(c.held, succ({ ...c.s1, new_fingerprint: c.o1b.fingerprint }), NOW);
  assert.equal(act(bad), 'refuse:rotation-bad-authority-sig');
  assert.ok(!('next' in bad), 'a refused claim writes nothing');
  const e = nextOf(await receive(c.held, succ(c.s1), NOW)).pending[0];
  assert.deepEqual(Object.keys(e).sort(), ['digests', 'epoch', 'firstSeenAtMs', 'identityEpoch', 'kind']);
  assert.ok(JSON.stringify(e).length < 400, 'a small record, not the 6 KB object');
});

test('H6 (Flint #532 C5) the receiver floor: after adopting epoch 2, successors at epochs 1 and 0 are stale and write nothing', async () => {
  const c = await ch();
  const h1 = await adopted(c.held, c.s1);
  const h2 = deepFreeze({ ...(await adopted(deepFreeze({ ...h1 }), c.s2, NOW + 2 * SUCCESSOR_WINDOW_MS)) });
  assert.equal(h2.identityEpoch, 2);
  const cases: Array<[string, RotationSuccessorInput]> = [
    ['epoch 1, a different claim', c.s1b],
    ['epoch 1, the one that was adopted', c.s1],
    ['epoch 0', { ...c.s1, successor_epoch: 0, prior_epoch: 0 } as RotationSuccessorInput],
  ];
  for (const [label, s] of cases) {
    const d = await receive(h2, succ(s), NOW + 9 * SUCCESSOR_WINDOW_MS);
    assert.equal(act(d), 'stale:stale-successor', label);
    assert.ok(!('next' in d), label + ' writes nothing');
  }
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
  const held1 = await receive(open, succ(c.s1), NOW);
  assert.equal(act(held1), 'pend', 'an open pointer conflict does not refuse the successor: it is held like any other');
  assert.equal(nextOf(held1).conflicts.length, 1, 'the pointer conflict still stands while the successor waits');
  const d = await receive(deepFreeze({ ...nextOf(held1) }), succ(c.s1), NOW + SUCCESSOR_WINDOW_MS);
  assert.equal(act(d), 'adopt');
  assert.deepEqual(nextOf(d).conflicts, []);
  const both = deepFreeze({ ...c.held, conflicts: [{ kind: 'pointer' as const, identityEpoch: 0, epoch: 5, digests: ['aa'.repeat(32), 'bb'.repeat(32)] }, { kind: 'successor' as const, identityEpoch: 0, epoch: 0, digests: ['cc'.repeat(32), 'dd'.repeat(32)] }] });
  assert.deepEqual((await adopted(both, c.s1)).conflicts.map((x) => x.kind), ['successor'], 'a successor conflict is kept as the record it is');
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

test('P6c a conflict between the HELD pointer and an authority-signed relay change at the same epoch: settle either side; settling the relay change needs room in pending', async () => {
  const w = ptrWorld();
  const heldBytes = w.make({ epoch: 10 });
  const first = await receive(w.held({ pointerEpoch: null }), heldBytes, NOW);
  const H = (first as { digest: string }).digest;
  const h = w.held({ pointerEpoch: 10, heldPointerDigest: H });
  const X = w.make({ epoch: 10, relay: 'https://other.example.net', authority: true });
  const d = await receive(h, X, NOW + 1);
  assert.equal(d.action, 'conflict', 'an authority-signed claim at the held epoch that differs from it');
  const open = deepFreeze({ ...nextOf(d) });
  const [dH, dX] = open.conflicts[0].digests;
  assert.equal(dH, H);
  // settle the relay change: it needs a pending entry, and refuses (changing nothing) when pending is full
  const full: PendingEntry[] = Array.from({ length: PENDING_MAX_KEYS }, (_, i) => ({ kind: 'pointer', identityEpoch: 1, epoch: 100 + i, digests: [bytesToHex(sha256(Uint8Array.of(i)))], firstSeenAtMs: NOW }));
  const refused = await receive(deepFreeze({ ...open, pending: full }), X, NOW + 5, { settleDigest: dX });
  assert.equal(act(refused), 'refuse:pending-full');
  assert.ok(!('next' in refused));
  const ok = await receive(open, X, NOW + 5, { settleDigest: dX });
  assert.equal(ok.action, 'pend');
  assert.deepEqual(nextOf(ok).conflicts, []);
  assert.deepEqual(nextOf(ok).pending.map((e) => [e.epoch, e.digests, e.firstSeenAtMs]), [[10, [dX], NOW + 5]]);
  assert.equal(nextOf(ok).relay, 'https://relay.example.org', 'nothing moved the relay');
  // settle the HELD claim instead: it is accepted, the conflict ends, the pending list is untouched
  const keep = await receive(open, heldBytes, NOW + 6, { settleDigest: dH });
  assert.equal(keep.action, 'accept');
  assert.deepEqual(nextOf(keep).conflicts, []);
  assert.equal(nextOf(keep).heldPointerDigest, H);
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
  assert.equal(act(a), 'pend', 'a successor is HELD with pending full, never refused: the owner\'s escape is not lockable');
  assert.equal(nextOf(a).pending.length, PENDING_MAX_KEYS + 1, 'its entry sits outside the bound (one successor entry at most, by construction)');
  assert.equal(full.length, PENDING_MAX_KEYS, 'the input list is not modified');
  const done = await receive(deepFreeze({ ...nextOf(a) }), succ(c.s1), NOW + SUCCESSOR_WINDOW_MS);
  assert.equal(act(done), 'adopt', 'and it adopts after the window');
  assert.deepEqual(nextOf(done).pending, [], 'clearing pending: it belongs to the old keys');
});

test('P8 (Flint #7317 R2) only an AUTHORITY-signed accept clears pending entries at or below its epoch; an identity-only accept leaves a pending authority move alone', async () => {
  const w = ptrWorld();
  const mk = (identityEpoch: number, epoch: number): PendingEntry => ({ kind: 'pointer', identityEpoch, epoch, digests: ['ee'.repeat(32)], firstSeenAtMs: NOW });
  const pending = [mk(1, 11), mk(1, 12), mk(1, 20), mk(0, 11)];
  const h = await heldWithPointer(w, 10, { pending });
  const idOnly = await receive(h, w.make({ epoch: 12 }), NOW + 1);
  assert.equal(act(idOnly), 'accept');
  assert.deepEqual(nextOf(idOnly).pending.map((e) => [e.identityEpoch, e.epoch]), [[1, 11], [1, 12], [1, 20], [0, 11]], 'a phone thief\'s same-relay pointer cannot cancel the owner\'s pending move');
  assert.equal(nextOf(idOnly).pointerEpoch, 12, 'but the pointer is accepted');
  const auth = await receive(h, w.make({ epoch: 12, authority: true }), NOW + 1);
  assert.equal(act(auth), 'accept');
  assert.deepEqual(nextOf(auth).pending.map((e) => [e.identityEpoch, e.epoch]), [[1, 20], [0, 11]], 'an authority-signed accept clears at or below its epoch, for its identity epoch only');
});

test('P8b (Flint #7317 R3) an identity-only pointer at the held epoch naming another relay is REFUSED, never a conflict', async () => {
  const w = ptrWorld();
  const h = await heldWithPointer(w, 10);
  const d = await receive(h, w.make({ epoch: 10, relay: 'https://other.example.net', x: 0x55 }), NOW);
  assert.equal(act(d), 'refuse:relay-change-needs-authority');
  assert.ok(!('next' in d));
  const after = await receive(h, w.make({ epoch: 10 }), NOW);
  assert.equal(act(after), 'accept', 'and the honest same claim is still idempotent');
});

test('P6b (Flint #7317 R1) a relay-change conflict can be settled by EITHER claim; the pending entry resets to the chosen digest and pointers resume', async () => {
  const w = ptrWorld();
  const h = await heldWithPointer(w, 10);
  const A = w.make({ epoch: 11, relay: 'https://other.example.net', authority: true });
  const B = w.make({ epoch: 11, relay: 'https://third.example.net', authority: true });
  const dA = await receive(h, A, NOW + 1);
  assert.equal(dA.action, 'pend');
  const nA = deepFreeze({ ...nextOf(dA) });
  const dB = await receive(nA, B, NOW + 2);
  assert.equal(dB.action, 'conflict');
  const open = deepFreeze({ ...nextOf(dB) });
  const [digA, digB] = open.conflicts[0].digests;
  assert.equal(act(await receive(open, w.make({ epoch: 12 }), NOW + 3)), 'refuse:conflict-open', 'frozen while open');
  // settle the FIRST claim (the pending entry already holds it)
  const sA = await receive(open, A, NOW + 50, { settleDigest: digA });
  assert.equal(sA.action, 'pend', 'still a pending relay change: the window is not built');
  const nSA = nextOf(sA);
  assert.deepEqual(nSA.conflicts, [], 'the conflict is gone');
  assert.deepEqual(nSA.pending[0].digests, [digA]);
  assert.equal(nSA.pending[0].firstSeenAtMs, NOW + 1, 'the first-seen time of the chosen claim is kept');
  // settle the SECOND claim: the entry is reset to it, with a fresh first-seen time
  const sB = await receive(open, B, NOW + 60, { settleDigest: digB });
  const nSB = nextOf(sB);
  assert.deepEqual(nSB.conflicts, []);
  assert.deepEqual(nSB.pending.map((e) => e.digests), [[digB]]);
  assert.equal(nSB.pending[0].firstSeenAtMs, NOW + 60);
  assert.equal(nSB.relay, 'https://relay.example.org', 'nothing moved the relay');
  // and the contact takes pointers again
  assert.equal(act(await receive(deepFreeze({ ...nSA }), w.make({ epoch: 12 }), NOW + 70)), 'accept');
  assert.equal(act(await receive(deepFreeze({ ...nSB }), w.make({ epoch: 12 }), NOW + 70)), 'accept');
  // a digest outside the conflict still settles nothing
  assert.equal(act(await receive(open, w.make({ epoch: 11, relay: 'https://x.example.net', authority: true }), NOW + 5, { settleDigest: 'ab'.repeat(32) })), 'refuse:conflict-open');
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

// ---------- 4. APPROVE (D2 v1.6) through the one receive function ----------
const pendingAt = (epochs: number[]): PendingEntry[] => epochs.map((epoch, i) => ({ kind: 'pointer' as const, identityEpoch: 1, epoch, digests: [bytesToHex(sha256(Uint8Array.of(i, epoch)))], firstSeenAtMs: NOW }));

test('AP1 APPROVE adopts a pending relay move at once: the relay moves, W is waived, the pending entry is gone', async () => {
  const w = ptrWorld();
  const h = await heldWithPointer(w, 10);
  const X = w.make({ epoch: 11, relay: 'https://other.example.net', authority: true });
  const dP = await receive(h, X, NOW + 1);
  assert.equal(dP.action, 'pend');
  const nP = deepFreeze({ ...nextOf(dP) });
  assert.equal(nP.relay, 'https://relay.example.org');
  const d = await receive(nP, w.approveFor(nP, X), NOW + 10);
  assert.equal(d.action, 'approved');
  assert.equal((d as { idempotent: boolean }).idempotent, false);
  assert.deepEqual((d as { relayChange: unknown }).relayChange, { from: 'https://relay.example.org', to: 'https://other.example.net' });
  const n = nextOf(d);
  assert.equal(n.relay, 'https://other.example.net');
  assert.equal(n.pointerEpoch, 11);
  assert.equal(n.heldPointerDigest, (dP as { digest: string }).digest, 'the digest the pending slot used is the digest APPROVE names');
  assert.equal(n.lastAcceptedAtMs, NOW + 10);
  assert.deepEqual(n.pending, []);
  assert.equal(nP.relay, 'https://relay.example.org', 'the input is untouched');
});

test('AP2 APPROVE is exempt from pending-full; it drops pending at or below its epoch and keeps a HIGHER pending attempt', async () => {
  const w = ptrWorld();
  const pending = pendingAt([5, 6, 102, 103, 104, 105, 106, 107]);
  assert.equal(pending.length, PENDING_MAX_KEYS);
  const h = await heldWithPointer(w, 10, { pending });
  const X = w.make({ epoch: 11, relay: 'https://other.example.net', authority: true });
  assert.equal(act(await receive(h, X, NOW)), 'refuse:pending-full', 'the same move without APPROVE is refused');
  const d = await receive(h, w.approveFor(h, X), NOW + 1);
  assert.equal(d.action, 'approved', 'with APPROVE it goes through');
  assert.deepEqual(nextOf(d).pending.map((e) => e.epoch), [102, 103, 104, 105, 106, 107], 'epochs 5 and 6 dropped; the higher attempts stay under their own window');
});

test('AP3 APPROVE settles a conflict at its epoch in its claim\'s favour, even a claim never seen; a conflict above its epoch stays open', async () => {
  const w = ptrWorld();
  const h = await heldWithPointer(w, 10);
  const A = w.make({ epoch: 11, relay: 'https://other.example.net', authority: true });
  const B = w.make({ epoch: 11, relay: 'https://third.example.net', authority: true });
  const nA = deepFreeze({ ...nextOf(await receive(h, A, NOW + 1)) });
  const open = deepFreeze({ ...nextOf(await receive(nA, B, NOW + 2)) });
  assert.equal(open.conflicts.length, 1);
  assert.equal(act(await receive(open, w.make({ epoch: 12 }), NOW + 3)), 'refuse:conflict-open', 'pointers are frozen');
  const dA = await receive(open, w.approveFor(open, A), NOW + 4);
  assert.equal(dA.action, 'approved', 'APPROVE passes the conflict gate');
  assert.deepEqual(nextOf(dA).conflicts, []);
  assert.deepEqual(nextOf(dA).pending, []);
  assert.equal(nextOf(dA).relay, 'https://other.example.net');
  const C = w.make({ epoch: 11, relay: 'https://fourth.example.net', authority: true });
  const dC = await receive(open, w.approveFor(open, C), NOW + 4);
  assert.equal(dC.action, 'approved', 'a claim nobody has sent yet can be approved too');
  assert.equal(nextOf(dC).relay, 'https://fourth.example.net');
  assert.equal(act(await receive(deepFreeze({ ...nextOf(dA) }), w.make({ epoch: 12, relay: 'https://other.example.net' }), NOW + 9)), 'accept', 'pointers resume');
  // conflicts at other epochs: one at or below the approved epoch is superseded, one above stays
  const two = deepFreeze({ ...open, conflicts: [{ kind: 'pointer' as const, identityEpoch: 1, epoch: 9, digests: ['aa'.repeat(32), 'bb'.repeat(32)] }] });
  assert.deepEqual(nextOf(await receive(two, w.approveFor(two, A), NOW)).conflicts, []);
  const above = deepFreeze({ ...open, conflicts: [{ kind: 'pointer' as const, identityEpoch: 1, epoch: 20, digests: ['aa'.repeat(32), 'bb'.repeat(32)] }] });
  assert.deepEqual(nextOf(await receive(above, w.approveFor(above, A), NOW)).conflicts.map((c) => c.epoch), [20]);
});

test('AP4 the same record again, or the same claim re-approved with fresh signatures, is a no-op', async () => {
  const w = ptrWorld();
  const h = await heldWithPointer(w, 10);
  const X = w.make({ epoch: 11, relay: 'https://other.example.net', authority: true });
  const rec = w.approveFor(h, X);
  const first = await receive(h, rec, NOW);
  const n = deepFreeze({ ...nextOf(first) });
  for (const again of [rec, w.approveFor(h, X)]) {
    const d = await receive(n, again, NOW + 5);
    assert.equal(d.action, 'approved');
    assert.equal((d as { idempotent: boolean }).idempotent, true);
    assert.ok(!('next' in d), 'nothing changes');
  }
});

test('AP5 stale, ahead and refused: each is a code and changes nothing', async () => {
  const w = ptrWorld();
  const h = await heldWithPointer(w, 10);
  const X = w.make({ epoch: 11, relay: 'https://other.example.net', authority: true });
  assert.equal(act(await receive(h, w.approveFor(h, X, { epoch: 0 }), NOW)), 'stale:stale-identity-epoch');
  const ahead = await receive(h, w.approveFor(h, X, { epoch: 2 }), NOW);
  assert.equal(act(ahead), 'hold:approve-ahead');
  assert.ok(!('next' in ahead));
  const attacker = { edSecret: randomBytes(32), dsaSecret: ml_dsa87.keygen(randomBytes(32)).secretKey };
  assert.equal(act(await receive(h, w.approveFor(h, X, { idSigner: attacker }), NOW)), 'refuse:bad-identity-sig');
  const noPin = deepFreeze({ ...h, ownerAuthorityPin: undefined });
  assert.equal(act(await receive(noPin, w.approveFor(h, X), NOW)), 'refuse:no-authority-pin');
  assert.equal(act(await receive(h, w.approveFor(h, w.make({ epoch: 11, authority: false })), NOW)), 'refuse:subject-not-authority-signed');
  const older = await receive(h, w.approveFor(h, w.make({ epoch: 9, relay: 'https://other.example.net', authority: true })), NOW);
  assert.equal(act(older), 'stale:stale-pointer', 'an APPROVE cannot move the held pointer backwards');
  assert.ok(!('next' in older));
  assert.equal(act(await receive(h, { kind: 'approve', bytes: new TextEncoder().encode('MARKER-ATTACKER-STRING') }, NOW)).startsWith('refuse:malformed:'), true);
});

test('AP6 an APPROVE at the held pointer epoch with a DIFFERENT claim replaces it (the settle-the-conflict case) and applies its relay', async () => {
  const w = ptrWorld();
  const h = await heldWithPointer(w, 10);
  const X = w.make({ epoch: 10, relay: 'https://other.example.net', authority: true });
  const d = await receive(h, w.approveFor(h, X), NOW + 2);
  assert.equal(d.action, 'approved');
  assert.equal(nextOf(d).relay, 'https://other.example.net');
  assert.equal(nextOf(d).pointerEpoch, 10);
  assert.notEqual(nextOf(d).heldPointerDigest, h.heldPointerDigest);
});

test('X3 first sight: a successor whose new keys cannot be READ, or are not the keys its fingerprint names, is refused on arrival and records nothing (the authority signature alone does not get a claim into pending)', async () => {
  const c = await ch();
  // CONTROL: the genuine claim is recorded, so the refusals below are about the keys and not about the fixture.
  const ok = await receive(c.held, succ(c.s1), NOW);
  assert.equal(act(ok), 'pend');
  assert.equal(nextOf(ok).pending.length, 1);
  // 1) the right shape (header, footer, printable ASCII) around a body that is not an OpenPGP key. The authority signature covers the FINGERPRINT, so it still verifies.
  const lines = c.o1.publicKey.split('\n');
  const garbage = [lines[0], '', ...Array.from({ length: 6 }, () => 'A'.repeat(64)), lines[lines.length - 1] === '' ? lines[lines.length - 2] : lines[lines.length - 1], ''].join('\n');
  assert.notEqual(garbage, c.o1.publicKey);
  // 2) a perfectly good key of ANOTHER identity under o1's fingerprint.
  const swapped = { ...c.s1, new_public_key: c.o1b.publicKey };
  const unreadable = { ...c.s1, new_public_key: garbage };
  for (const [name, s] of [['unreadable key', unreadable], ['another identity\'s key', swapped]] as const) {
    const d = await receive(c.held, succ(s), NOW);
    assert.equal(d.action, 'refuse', name + ': ' + act(d));
    assert.ok(!('next' in d), name + ': the refusal carries no new state');
    assert.match((d as { reason: string }).reason, /^[a-z-]+$/, name + ': a reason code, no input echoed');
    // and not after the window either: a redelivery of the bad claim against a state that holds the genuine one changes nothing
    const again = await receive(deepFreeze({ ...nextOf(ok) }), succ(s), NOW + SUCCESSOR_WINDOW_MS);
    assert.equal(again.action, 'refuse', name + ' (after the window): ' + act(again));
    assert.ok(!('next' in again), name + ' (after the window): no new state');
  }
  assert.equal(c.held.pending.length, 0, 'the input is not modified');
});
