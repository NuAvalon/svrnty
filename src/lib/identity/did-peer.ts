// src/lib/identity/did-peer.ts
//
// T1 — DID + DID-Document for svrnty (C-build, Lane C / Apollo).
//
// WHAT THIS IS. svrnty's identity today is `fp = hex(SHA256(sign‖enc‖kem‖sig))` over the 4 operational
// public keys (deriveCanonicalFingerprintHex, ./fingerprint). That fp IS the identity — so a key ROTATION
// changes the fp, which changes the identity. That is exactly Peter's migratability flaw ("rotation changes
// who you are"). This module adds a DID layer whose identifier is STABLE across operational rotation, so the
// keys can change while the durable handle (and everyone's address-book entry) does not.
//
// ── THE STABLE-ANCHOR DESIGN (the crux; corrects the plan doc's did:peer numalgo-2 choice) ───────────────
//   did:peer numalgo-2 encodes the CURRENT keys INTO the id string, so rotating a key changes the id — it
//   does NOT give a stable handle. So the DID id here anchors to the ONE thing that survives operational
//   rotation: the COLD-SEED GENESIS ROTATION-AUTHORITY (epoch-0), the same cold-seed material that
//   deriveNextAuthorityKeypair/deriveNextAuthorityCommitment already manage (./fingerprint). The DID-Document
//   then lists the CURRENT operational keys as verificationMethods and is MUTABLE (add/revoke a device,
//   move a serviceEndpoint, rotate keys) — each mutation signed by the cold-seed authority key with a
//   monotonic seq (Flint X5). Identity = the anchor; the keys are just the current contents.
//
//   id = `did:svrnty:` + hex(SHA256( DID_ANCHOR_TAG ‖ authEd0[32] ‖ authDsa0[2592] ))
//   (authEd0/authDsa0 = the epoch-0 cold-seed authority pubs). Self-certifying: a DID-Doc's proof reveals
//   the authority pubs whose hash must equal the anchor embedded in the id — no registry, no lookup.
//
// ── SIGNING (reuses Flint X5 — no new crypto) ────────────────────────────────────────────────────────────
//   signed_bytes = buildSignedBytes(DOMAIN_DID_DOC, SUITE_HYBRID, canonicalize(doc, {exclude:['proof']}))
//   = LP(domain) ‖ LP(suite) ‖ canonical_input   (./crypto/sign-envelope — netstring-injective, the SAME
//   envelope + house canonicalizer every other svrnty signed object uses; cross-language reproducible for a
//   Python verifier). Signed HYBRID (ed25519 + ML-DSA-87) with the cold-seed authority keypair, byte-identical
//   to sign/verifyRotationAuthority except the domain tag.
//
// ── GATED DECISIONS (marked; pinged to Flint ☀7490 / Archie — build is to my lean, isolated swaps if flipped) ─
//   (a) canonicalizer = the house canonicalize() (NOT a new JCS lib) — it IS the deployed seam contract.
//   (b) domain = DOMAIN_DID_DOC (distinct from DOMAIN_ROTATION) — 1-const swap if Flint prefers reuse.
//   (c) key encoding = svrnty-native HEX (matches sign_pub/enc_pub/kem_pub/sig_pub) — a spec-pure multibase
//       encoder (base58btc+varint, external-resolver interop) is a post-launch drop-in behind encode/decode.
//   (d) method name = `did:svrnty` (custom, registry-free) vs did:peer numalgo-4 (hash-of-genesis short form).
//       The ANCHOR MATH is method-agnostic; only the printed prefix changes.

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { canonicalize } from '../format/canonical';
import { buildSignedBytes, SUITE_HYBRID } from '../crypto/sign-envelope';
import { DOMAIN_DID_DOC } from '../format/envelope';
import {
  SIGN_PUB_LEN,
  ENC_PUB_LEN,
  KEM_PUB_LEN,
  SIG_PUB_LEN,
  AUTH_ED25519_PUB_BYTES,
  AUTH_ML_DSA87_PUB_BYTES,
  AUTH_ED25519_SIG_BYTES,
} from './fingerprint';

// ── Method + shapes ──────────────────────────────────────────────────────────────────────────────────────
export const DID_METHOD = 'did:svrnty'; // (d) custom, registry-free; anchor math is method-agnostic
export const DID_ANCHOR_TAG = 'svrnty:did-anchor:v1'; // domain-separates the id-anchor hash preimage
export const DID_CONTEXT = 'https://www.w3.org/ns/did/v1';

// verificationMethod `type` tags. Classical types use the W3C names; PQ has no registered type yet → svrnty-native.
export const VM_TYPE_ED25519 = 'Ed25519VerificationKey2020';
export const VM_TYPE_X25519 = 'X25519KeyAgreementKey2020';
export const VM_TYPE_ML_DSA87 = 'MlDsa87VerificationKey2026';
export const VM_TYPE_ML_KEM1024 = 'MlKem1024KeyAgreementKey2026';

/** A public key inside the DID-Doc. `publicKeyHex` is svrnty-native (matches sign_pub/enc_pub/... fields). */
export interface VerificationMethod {
  id: string; // fragment relative to the DID, e.g. `${did}#phone-sign`
  type: string;
  controller: string; // the DID
  publicKeyHex: string;
}

/** A routing endpoint. serviceEndpoint carries the relay + a BLINDED rotating tag — NEVER a raw DID/key. */
export interface ServiceEndpoint {
  id: string;
  type: string; // 'SvrntyMailbox'
  purpose?: string; // 'human' | 'agent' (future-proof; launch ships single-endpoint behavior)
  serviceEndpoint: string;
}

/** The authority signature over the DID-Doc. EXCLUDED from its own canonical signed input (sign-then-attach). */
export interface DidDocProof {
  type: 'SvrntyAuthorityHybrid2026';
  domain: string; // DOMAIN_DID_DOC (informational; also bound structurally via the sign-envelope LP prefix)
  epoch: number; // cold-seed authority epoch whose key signed this (v1 launch: 0 = genesis)
  authorityPubkeys: { sign: string; pq_sig: string }; // revealed cold-seed authority pubs (hex); H(reveal) chains to the id anchor
  sig: string; // hybrid sig hex: ed25519(64B) ‖ ML-DSA-87
}

export interface DidDocument {
  '@context': string[];
  id: string;
  verificationMethod: VerificationMethod[]; // signing keys (ed25519 + ML-DSA-87), one pair per device
  keyAgreement: VerificationMethod[]; // encryption keys (x25519 + ML-KEM), one pair per device
  authentication: string[]; // fragment refs into verificationMethod (which keys may authenticate)
  service: ServiceEndpoint[];
  seq: number; // monotonic mutation counter — INSIDE the signed bytes (replay guard, Flint X5)
  proof?: DidDocProof; // attached after signing; excluded from the canonical input
}

/** The 4 operational public keys for one device, plus a short device label for VM fragments. */
export interface DeviceKeys {
  device: string; // slug for fragment ids, e.g. 'phone' → #phone-sign / #phone-enc / ...
  signPub: Uint8Array; // 32B ed25519
  encPub: Uint8Array; // 32B x25519
  kemPub: Uint8Array; // 1568B ML-KEM-1024
  sigPub: Uint8Array; // 2592B ML-DSA-87
}

const DEVICE_SLUG_RE = /^[a-z0-9][a-z0-9-]{0,31}$/; // fragment-safe, canonical

// ── id anchor ────────────────────────────────────────────────────────────────────────────────────────────
/**
 * The stable DID for an identity, anchored to its GENESIS (epoch-0) cold-seed rotation-authority pubs.
 * STABLE across operational key rotation (the cold seed does not change), which is the whole migratability
 * fix. Self-certifying: a DID-Doc's proof reveals authority pubs whose SHA256 must reproduce this anchor.
 */
export function deriveDid(authEd0Pub: Uint8Array, authDsa0Pub: Uint8Array): string {
  if (authEd0Pub.length !== AUTH_ED25519_PUB_BYTES)
    throw new Error(`deriveDid: authority ed25519 pub must be ${AUTH_ED25519_PUB_BYTES}B`);
  if (authDsa0Pub.length !== AUTH_ML_DSA87_PUB_BYTES)
    throw new Error(`deriveDid: authority ML-DSA-87 pub must be ${AUTH_ML_DSA87_PUB_BYTES}B`);
  const anchor = bytesToHex(sha256(concatBytes(utf8ToBytes(DID_ANCHOR_TAG), authEd0Pub, authDsa0Pub)));
  return `${DID_METHOD}:${anchor}`;
}

/** Recompute the id anchor from revealed authority pubs (hex) — used to check a DID-Doc against its own id. */
export function anchorFromAuthorityReveal(signHex: string, pqSigHex: string): string {
  let ed: Uint8Array;
  let dsa: Uint8Array;
  try {
    ed = hexToBytes(signHex);
    dsa = hexToBytes(pqSigHex);
  } catch {
    throw new Error('anchorFromAuthorityReveal: authority reveal is not valid hex');
  }
  return deriveDid(ed, dsa);
}

/** Extract the `did:svrnty:<anchor>` portion (drops any `#fragment`). Throws on a non-svrnty DID. */
export function parseDid(did: string): { method: string; anchorHex: string } {
  const base = did.split('#')[0];
  const prefix = `${DID_METHOD}:`;
  if (!base.startsWith(prefix)) throw new Error(`parseDid: not a ${DID_METHOD} DID: ${JSON.stringify(base)}`);
  const anchorHex = base.slice(prefix.length);
  if (!/^[0-9a-f]{64}$/.test(anchorHex)) throw new Error('parseDid: anchor is not 64-hex');
  return { method: DID_METHOD, anchorHex };
}

// ── builder ──────────────────────────────────────────────────────────────────────────────────────────────
function deviceVMs(did: string, dev: DeviceKeys): { signing: VerificationMethod[]; agreement: VerificationMethod[] } {
  if (!DEVICE_SLUG_RE.test(dev.device)) throw new Error(`buildDidDocument: device slug must match ${DEVICE_SLUG_RE}`);
  const lens: Array<[keyof DeviceKeys, number, string]> = [
    ['signPub', SIGN_PUB_LEN, 'sign'],
    ['encPub', ENC_PUB_LEN, 'enc'],
    ['kemPub', KEM_PUB_LEN, 'kem'],
    ['sigPub', SIG_PUB_LEN, 'sig'],
  ];
  for (const [k, len, label] of lens) {
    const v = dev[k] as Uint8Array;
    if (!(v instanceof Uint8Array) || v.length !== len)
      throw new Error(`buildDidDocument: device ${dev.device} ${label} pub must be ${len}B`);
  }
  const vm = (frag: string, type: string, pub: Uint8Array): VerificationMethod => ({
    id: `${did}#${dev.device}-${frag}`,
    type,
    controller: did,
    publicKeyHex: bytesToHex(pub),
  });
  return {
    signing: [vm('sign', VM_TYPE_ED25519, dev.signPub), vm('sig', VM_TYPE_ML_DSA87, dev.sigPub)],
    agreement: [vm('enc', VM_TYPE_X25519, dev.encPub), vm('kem', VM_TYPE_ML_KEM1024, dev.kemPub)],
  };
}

/**
 * Assemble an UNSIGNED DID-Document. `did` must be the stable anchor (deriveDid). `devices` is one entry per
 * device (multi-device = multiple entries). `services` are routing endpoints (blinded tags). `seq` starts at 0
 * at genesis and strictly increments on every mutation. Sign with signDidDocument() before sharing.
 */
export function buildDidDocument(params: {
  did: string;
  devices: DeviceKeys[];
  services?: ServiceEndpoint[];
  seq?: number;
}): DidDocument {
  const { did } = params;
  parseDid(did); // fail-closed on a malformed DID
  if (!params.devices.length) throw new Error('buildDidDocument: at least one device required');
  const verificationMethod: VerificationMethod[] = [];
  const keyAgreement: VerificationMethod[] = [];
  const authentication: string[] = [];
  const seenFrag = new Set<string>();
  for (const dev of params.devices) {
    if (seenFrag.has(dev.device)) throw new Error(`buildDidDocument: duplicate device slug ${dev.device}`);
    seenFrag.add(dev.device);
    const { signing, agreement } = deviceVMs(did, dev);
    verificationMethod.push(...signing);
    keyAgreement.push(...agreement);
    for (const s of signing) authentication.push(s.id); // sign keys may authenticate
  }
  const seq = params.seq ?? 0;
  if (!Number.isInteger(seq) || seq < 0) throw new Error('buildDidDocument: seq must be a non-negative integer');
  return {
    '@context': [DID_CONTEXT],
    id: did,
    verificationMethod,
    keyAgreement,
    authentication,
    service: params.services ?? [],
    seq,
  };
}

// ── multi-device mutations (return a NEW unsigned doc with seq++; re-sign before sharing) ────────────────────
/** Add a device's key set. Returns a new unsigned doc with seq incremented; caller re-signs. */
export function addDevice(doc: DidDocument, dev: DeviceKeys): DidDocument {
  if (doc.verificationMethod.some((v) => v.id.startsWith(`${doc.id}#${dev.device}-`)))
    throw new Error(`addDevice: device ${dev.device} already present`);
  const { signing, agreement } = deviceVMs(doc.id, dev);
  return {
    ...doc,
    verificationMethod: [...doc.verificationMethod, ...signing],
    keyAgreement: [...doc.keyAgreement, ...agreement],
    authentication: [...doc.authentication, ...signing.map((s) => s.id)],
    seq: doc.seq + 1,
    proof: undefined,
  };
}

/** Revoke (remove) a device's key set. Returns a new unsigned doc with seq incremented; caller re-signs. */
export function revokeDevice(doc: DidDocument, device: string): DidDocument {
  const pfx = `${doc.id}#${device}-`;
  const remaining = doc.verificationMethod.filter((v) => !v.id.startsWith(pfx));
  if (remaining.length === doc.verificationMethod.length) throw new Error(`revokeDevice: device ${device} not found`);
  if (!remaining.length) throw new Error('revokeDevice: cannot revoke the last device (identity would have no keys)');
  return {
    ...doc,
    verificationMethod: remaining,
    keyAgreement: doc.keyAgreement.filter((v) => !v.id.startsWith(pfx)),
    authentication: doc.authentication.filter((id) => !id.startsWith(pfx)),
    seq: doc.seq + 1,
    proof: undefined,
  };
}

// ── canonicalization + hybrid authority signing (mirrors sign/verifyRotationAuthority, DOMAIN_DID_DOC) ──────
/** The exact string that gets signed: house canonicalize() over the doc MINUS its own proof. */
export function canonicalDidDocInput(doc: DidDocument): string {
  return canonicalize(doc, { exclude: ['proof'] });
}

function didDocAuthorityPayload(canonicalInput: string): Uint8Array {
  return utf8ToBytes(buildSignedBytes(DOMAIN_DID_DOC, SUITE_HYBRID, canonicalInput));
}

/** Hybrid authority signature over the canonical DID-Doc input: hex(ed25519-sig 64B ‖ ML-DSA-87-sig). */
export function signDidDocAuthority(canonicalInput: string, edSecret: Uint8Array, dsaSecret: Uint8Array): string {
  const payload = didDocAuthorityPayload(canonicalInput);
  return bytesToHex(concatBytes(ed25519.sign(payload, edSecret), ml_dsa87.sign(payload, dsaSecret)));
}

/** Verify BOTH legs of a DID-Doc authority signature under the revealed authority pubs. */
export function verifyDidDocAuthority(
  canonicalInput: string,
  sigHex: string,
  signHex: string,
  pqSigHex: string,
): boolean {
  try {
    const sig = hexToBytes(sigHex);
    const edPub = hexToBytes(signHex);
    const dsaPub = hexToBytes(pqSigHex);
    if (edPub.length !== AUTH_ED25519_PUB_BYTES || dsaPub.length !== AUTH_ML_DSA87_PUB_BYTES) return false;
    if (sig.length <= AUTH_ED25519_SIG_BYTES) return false;
    const edSig = sig.subarray(0, AUTH_ED25519_SIG_BYTES);
    const dsaSig = sig.subarray(AUTH_ED25519_SIG_BYTES);
    const payload = didDocAuthorityPayload(canonicalInput);
    if (!ed25519.verify(edSig, payload, edPub)) return false;
    return ml_dsa87.verify(dsaSig, payload, dsaPub);
  } catch {
    return false;
  }
}

// ── high-level sign / verify ─────────────────────────────────────────────────────────────────────────────
/**
 * Sign an unsigned DID-Doc with the cold-seed authority keypair and attach the proof. `epoch` names the
 * authority epoch (v1 launch: 0 = genesis). The revealed authority pubs MUST hash to the DID's id anchor —
 * this function checks that (fail-closed) so you can only sign a doc with the authority that owns it.
 */
export function signDidDocument(
  doc: DidDocument,
  authority: { edPublic: Uint8Array; edSecret: Uint8Array; dsaPublic: Uint8Array; dsaSecret: Uint8Array },
  epoch: number,
): DidDocument {
  if (!Number.isInteger(epoch) || epoch < 0) throw new Error('signDidDocument: epoch must be a non-negative integer');
  const signHex = bytesToHex(authority.edPublic);
  const pqSigHex = bytesToHex(authority.dsaPublic);
  // v1 (epoch 0): the signing authority IS the genesis authority → it must reproduce the id anchor directly.
  // (Post-launch authority rotation: the reveal chains to the anchor via the lineage; verified at the edge.)
  if (epoch === 0 && anchorFromAuthorityReveal(signHex, pqSigHex) !== doc.id)
    throw new Error('signDidDocument: genesis authority pubs do not match the DID id anchor');
  const canonicalInput = canonicalDidDocInput({ ...doc, proof: undefined });
  const sig = signDidDocAuthority(canonicalInput, authority.edSecret, authority.dsaSecret);
  return {
    ...doc,
    proof: { type: 'SvrntyAuthorityHybrid2026', domain: DOMAIN_DID_DOC, epoch, authorityPubkeys: { sign: signHex, pq_sig: pqSigHex }, sig },
  };
}

export interface DidDocVerifyResult {
  ok: boolean;
  reason?: string;
  seq?: number;
  did?: string;
}

/**
 * Verify a signed DID-Doc as SELF-CONSISTENT: (1) the proof's revealed authority pubs hash to the id anchor
 * (v1/epoch-0; post-launch, the caller supplies the lineage walk), and (2) the hybrid signature verifies over
 * the canonical input. Monotonic-seq enforcement across successive docs is the EDGE's job (like
 * verifyRotationSuccessor's epoch-not-next) — pass the last-seen seq to reject stale/replayed docs.
 */
export function verifyDidDocument(doc: DidDocument, opts: { lastSeenSeq?: number } = {}): DidDocVerifyResult {
  const proof = doc.proof;
  if (!proof || proof.type !== 'SvrntyAuthorityHybrid2026') return { ok: false, reason: 'missing-or-unknown-proof' };
  if (!Number.isInteger(doc.seq) || doc.seq < 0) return { ok: false, reason: 'bad-seq' };
  if (opts.lastSeenSeq !== undefined && doc.seq <= opts.lastSeenSeq) return { ok: false, reason: 'seq-not-monotonic' };
  // (1) id-anchor self-certification (v1: genesis authority signs → reveal hashes to the id).
  if (proof.epoch === 0) {
    let anchorDid: string;
    try {
      anchorDid = anchorFromAuthorityReveal(proof.authorityPubkeys.sign, proof.authorityPubkeys.pq_sig);
    } catch (e) {
      return { ok: false, reason: e instanceof Error ? e.message : 'anchor-reveal-decode' };
    }
    if (anchorDid !== doc.id) return { ok: false, reason: 'authority-does-not-anchor-to-id' };
  } else {
    // Post-launch authority rotation: the reveal must chain to the anchor via the rotation lineage. That walk
    // lives at the edge (existing next_authority_commitment chain); this module verifies the signature only.
    return { ok: false, reason: 'rotated-authority-lineage-walk-not-yet-implemented' };
  }
  // (2) signature over the canonical input (proof excluded).
  const canonicalInput = canonicalDidDocInput(doc);
  if (!verifyDidDocAuthority(canonicalInput, proof.sig, proof.authorityPubkeys.sign, proof.authorityPubkeys.pq_sig))
    return { ok: false, reason: 'authority-sig-invalid' };
  return { ok: true, seq: doc.seq, did: doc.id };
}

// ── resolver (used by verify + future T3 edge-verify wiring) ─────────────────────────────────────────────
/** Look up a verificationMethod (signing or agreement) by its full fragment id. */
export function resolveVerificationMethod(doc: DidDocument, id: string): VerificationMethod | undefined {
  return doc.verificationMethod.find((v) => v.id === id) ?? doc.keyAgreement.find((v) => v.id === id);
}
