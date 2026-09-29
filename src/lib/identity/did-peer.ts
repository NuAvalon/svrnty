// src/lib/identity/did-peer.ts
//
// T1 — DID + DID-Document for svrnty (C-build, Lane C / Apollo). (c)-COLLAPSE REWRITE.
//
// WHAT THIS IS. svrnty's identity is `durable_id = hex(SHA256(sign32 ‖ enc32 ‖ kem1568 ‖ sig2592))` over the 4
// GENESIS operational public keys (deriveCanonicalFingerprintHex, ./fingerprint). This module adds a DID layer
// whose identifier is STABLE across operational rotation, so the keys can change while the durable handle (and
// everyone's address-book entry) does not — Peter's migratability fix.
//
// ── THE (c)-COLLAPSE ANCHOR (KB#91051/91054/91096; corrects the old authority-pubs anchor) ──────────────────
//   The DID id anchors to `durable_id` — the SAME canonical fingerprint that is the trust-graph key
//   (TrustEdge.peer_fingerprint) and the satellite `identities.fingerprint` (byte-identical by construction,
//   zero FK re-key). Identity ≠ governance key: the anchor is the genesis OPERATIONAL key bundle, NOT the
//   cold-seed authority. This is why the old self-certification (reveal authority pubs, hash == id) no longer
//   holds — H(authority pubs) ≠ id — and the verifier splits into TWO signer paths:
//
//   id = `did:svrnty:` + deriveCanonicalFingerprintHex(genesis sign, enc, kem, sig)   (no re-hash; wrap the fp)
//
// ── TWO-SIGNER VERIFY MODEL (Flint verify-model nod, KB#91096) ───────────────────────────────────────────────
//   • GENESIS DID-Doc (seq 0) = OPERATIONAL-KEY SELF-SIGN. The genesis device's own signing keys (ed25519
//     `sign` + ML-DSA-87 `sig` — the same keys that sign the identity card) sign the doc. Self-certifies:
//     deriveCanonicalFingerprintHex(the doc's genesis operational keys) == the id anchor. A contact who
//     accepted the card already trusts these keys → no cold-seed needed for the genesis doc. The genesis doc
//     COMMITS the governance authority: `nextAuthorityCommitment = H(cold-seed authority epoch-0 pubs)`.
//   • MUTATION DID-Doc (add/revoke device, endpoint move, key rotation — seq ≥ 1) = COLD-SEED AUTHORITY SIGN
//     (Flint X5 governance). The proof REVEALS the authority pubs; the verifier checks
//     H(reveal) == the prior doc's `nextAuthorityCommitment` (pre-rotation commitment chain, KERI-style) and
//     verifies the hybrid authority signature. The lineage WALK across rotations lives at the EDGE — this
//     module verifies one hop given the expected commitment; the caller threads doc_n.nextAuthorityCommitment
//     as the expected commitment for doc_{n+1}.
//
//   ★ §0-SAFE (KB#91096): a DID-Doc is verified AT THE EDGE by CONTACTS (who hold your DID), NEVER at the
//   blind relay → cold-seed-authority on a DID-Doc mutation is FINE (no mailbox↔DID leak). This is the
//   OPPOSITE of S1 owner-key (relay-verified → per-mailbox pre-rotation, no DID-authority). Rule:
//   edge-verified ⇒ authority-OK; relay-verified ⇒ no-DID-authority.
//
// ── SIGNING (reuses the SAME hybrid envelope for BOTH paths — no new crypto) ──────────────────────────────────
//   signed_bytes = buildSignedBytes(DOMAIN_DID_DOC, SUITE_HYBRID, canonicalize(doc, {exclude:['proof']}))
//   = LP(domain) ‖ LP(suite) ‖ canonical_input   (./crypto/sign-envelope — netstring-injective, the SAME
//   envelope + house canonicalizer every other svrnty signed object uses; cross-language reproducible for a
//   Python verifier). Signed HYBRID (ed25519 + ML-DSA-87). Only the KEY differs between the two paths:
//   genesis = the doc's operational (sign, sig) keypair; mutation = the cold-seed authority keypair. The
//   ed25519 `sign` operational secret is the raw 32B seed from extractRawSign — ed25519.sign(payload, seed)
//   verifies vs the operational signPub (proven in ./raw-sign), so the genesis self-sign is the SAME primitive
//   the identity card uses.

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
  deriveCanonicalFingerprintHex,
  authorityCommitmentFromReveal,
  encodeAuthorityPubkeys,
  normalizeFingerprintHex,
  type NextAuthorityKeypair,
} from './fingerprint';

// ── Method + shapes ──────────────────────────────────────────────────────────────────────────────────────
export const DID_METHOD = 'did:svrnty'; // (d) custom, registry-free; anchor math is method-agnostic
export const DID_CONTEXT = 'https://www.w3.org/ns/did/v1';
export const DID_DOC_PROOF_TYPE = 'SvrntyDidDoc2026';

// verificationMethod `type` tags. Classical types use the W3C names; PQ has no registered type yet → svrnty-native.
export const VM_TYPE_ED25519 = 'Ed25519VerificationKey2020';
export const VM_TYPE_X25519 = 'X25519KeyAgreementKey2020';
export const VM_TYPE_ML_DSA87 = 'MlDsa87VerificationKey2026';
export const VM_TYPE_ML_KEM1024 = 'MlKem1024KeyAgreementKey2026';

/** Which key signed a DID-Doc: genesis = the doc's own operational keys; mutation = the cold-seed authority. */
export type DidDocProofMode = 'genesis-operational' | 'authority-mutation';

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

/** The signature over the DID-Doc. EXCLUDED from its own canonical signed input (sign-then-attach). */
export interface DidDocProof {
  type: typeof DID_DOC_PROOF_TYPE;
  mode: DidDocProofMode;
  domain: string; // DOMAIN_DID_DOC (informational; also bound structurally via the sign-envelope LP prefix)
  // authority-mutation ONLY: the REVEALED cold-seed authority pubs (hex). H(reveal) must equal the prior
  // doc's nextAuthorityCommitment. Absent for genesis-operational (its pubs are the doc's own genesis VMs).
  authorityPubkeys?: { sign: string; pq_sig: string };
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
  // Pre-rotation commitment to the governance authority allowed to sign the NEXT doc: H(next authority pubs)
  // = deriveNextAuthorityCommitment(coldSeed, epoch). Committed at genesis (operational self-sign binds it to
  // durable_id); each doc re-commits so the edge can walk the lineage. 64-lowercase-hex.
  nextAuthorityCommitment: string;
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

/** Genesis operational signing material: the raw ed25519 seed (extractRawSign) + the ML-DSA-87 sig secret. */
export interface GenesisOperationalSigner {
  signSeed: Uint8Array; // 32B raw ed25519 seed (== extractRawSign().seed); ed25519.sign(_, seed) verifies vs signPub
  sigSecret: Uint8Array; // ML-DSA-87 secret key
}

const DEVICE_SLUG_RE = /^[a-z0-9][a-z0-9-]{0,31}$/; // fragment-safe, canonical
const HEX64_RE = /^[0-9a-f]{64}$/;

// ── id anchor (durable_id) ───────────────────────────────────────────────────────────────────────────────────
/**
 * The stable DID for an identity, anchored to its `durable_id` = deriveCanonicalFingerprintHex over the 4
 * GENESIS operational public keys. STABLE across operational key rotation is NOT provided by re-hashing keys
 * (that would change the id) — it is provided by the DID layer: the id is fixed to the genesis bundle's hash
 * and the DID-Doc's CONTENTS mutate under governance. Byte-identical to the trust-graph / satellite fingerprint.
 */
export function deriveDid(signPub: Uint8Array, encPub: Uint8Array, kemPub: Uint8Array, sigPub: Uint8Array): string {
  return `${DID_METHOD}:${deriveCanonicalFingerprintHex(signPub, encPub, kemPub, sigPub)}`;
}

/** Wrap an already-computed 64-hex durable_id (the identity's canonical fingerprint) as a did:svrnty DID. */
export function didFromFingerprint(fingerprintHex: string): string {
  const fp = normalizeFingerprintHex(fingerprintHex);
  if (!HEX64_RE.test(fp)) throw new Error('didFromFingerprint: durable_id must be 64 lowercase hex');
  return `${DID_METHOD}:${fp}`;
}

/** Extract the `did:svrnty:<durable_id>` portion (drops any `#fragment`). Throws on a non-svrnty DID. */
export function parseDid(did: string): { method: string; anchorHex: string } {
  const base = did.split('#')[0];
  const prefix = `${DID_METHOD}:`;
  if (!base.startsWith(prefix)) throw new Error(`parseDid: not a ${DID_METHOD} DID: ${JSON.stringify(base)}`);
  const anchorHex = base.slice(prefix.length);
  if (!HEX64_RE.test(anchorHex)) throw new Error('parseDid: anchor is not 64-hex');
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
 * Assemble an UNSIGNED DID-Document. `did` must be the durable_id anchor (deriveDid / didFromFingerprint).
 * `devices` is one entry per device — at GENESIS there must be exactly ONE (its 4 keys ARE the durable_id;
 * additional devices are added later via authority-signed mutations). `nextAuthorityCommitment` binds the
 * governance authority (H(cold-seed authority pubs) = deriveNextAuthorityCommitment). Sign with
 * signDidDocGenesis() (seq 0) or signDidDocMutation() (seq ≥ 1) before sharing.
 */
export function buildDidDocument(params: {
  did: string;
  devices: DeviceKeys[];
  nextAuthorityCommitment: string;
  services?: ServiceEndpoint[];
  seq?: number;
}): DidDocument {
  const { did } = params;
  parseDid(did); // fail-closed on a malformed DID
  if (!params.devices.length) throw new Error('buildDidDocument: at least one device required');
  const nextAuthorityCommitment = normalizeFingerprintHex(params.nextAuthorityCommitment);
  if (!HEX64_RE.test(nextAuthorityCommitment))
    throw new Error('buildDidDocument: nextAuthorityCommitment must be 64 lowercase hex');
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
    nextAuthorityCommitment,
  };
}

// ── multi-device mutations (return a NEW unsigned doc with seq++; re-sign with the AUTHORITY before sharing) ──
/** Add a device's key set. Returns a new unsigned doc with seq incremented; caller re-signs (mutation). */
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

/** Re-commit to a (possibly new) governance authority on the NEXT doc. seq++; caller re-signs (mutation). */
export function setNextAuthorityCommitment(doc: DidDocument, nextAuthorityCommitment: string): DidDocument {
  const c = normalizeFingerprintHex(nextAuthorityCommitment);
  if (!HEX64_RE.test(c)) throw new Error('setNextAuthorityCommitment: must be 64 lowercase hex');
  return { ...doc, seq: doc.seq + 1, nextAuthorityCommitment: c, proof: undefined };
}

// ── canonicalization + hybrid signing (shared by BOTH paths, DOMAIN_DID_DOC) ─────────────────────────────────
/** The exact string that gets signed: house canonicalize() over the doc MINUS its own proof. */
export function canonicalDidDocInput(doc: DidDocument): string {
  return canonicalize(doc, { exclude: ['proof'] });
}

function didDocHybridPayload(canonicalInput: string): Uint8Array {
  return utf8ToBytes(buildSignedBytes(DOMAIN_DID_DOC, SUITE_HYBRID, canonicalInput));
}

/**
 * Hybrid signature over the canonical DID-Doc input: hex(ed25519-sig 64B ‖ ML-DSA-87-sig). Generic over the
 * keypair — used with the genesis OPERATIONAL keys (self-sign) and with the cold-seed AUTHORITY keys (mutation).
 */
export function signDidDocHybrid(canonicalInput: string, edSecret: Uint8Array, dsaSecret: Uint8Array): string {
  const payload = didDocHybridPayload(canonicalInput);
  return bytesToHex(concatBytes(ed25519.sign(payload, edSecret), ml_dsa87.sign(payload, dsaSecret)));
}

/** Verify BOTH legs of a DID-Doc hybrid signature under the given ed25519 (32B) + ML-DSA-87 (2592B) pubs. */
export function verifyDidDocHybrid(canonicalInput: string, sigHex: string, signHex: string, pqSigHex: string): boolean {
  try {
    const sig = hexToBytes(sigHex);
    const edPub = hexToBytes(signHex);
    const dsaPub = hexToBytes(pqSigHex);
    if (edPub.length !== AUTH_ED25519_PUB_BYTES || dsaPub.length !== AUTH_ML_DSA87_PUB_BYTES) return false;
    if (sig.length <= AUTH_ED25519_SIG_BYTES) return false;
    const edSig = sig.subarray(0, AUTH_ED25519_SIG_BYTES);
    const dsaSig = sig.subarray(AUTH_ED25519_SIG_BYTES);
    const payload = didDocHybridPayload(canonicalInput);
    if (!ed25519.verify(edSig, payload, edPub)) return false;
    return ml_dsa87.verify(dsaSig, payload, dsaPub);
  } catch {
    return false;
  }
}

/**
 * Extract the SINGLE genesis device's 4 operational public keys (by VM type). Returns null unless the doc has
 * EXACTLY one of each (sign/enc/kem/sig) — i.e. the one-device genesis shape whose bundle defines durable_id.
 */
export function extractGenesisOperationalKeys(
  doc: DidDocument,
): { signPub: Uint8Array; encPub: Uint8Array; kemPub: Uint8Array; sigPub: Uint8Array } | null {
  const pick = (arr: VerificationMethod[], type: string) => arr.filter((v) => v.type === type);
  const signVMs = pick(doc.verificationMethod, VM_TYPE_ED25519);
  const sigVMs = pick(doc.verificationMethod, VM_TYPE_ML_DSA87);
  const encVMs = pick(doc.keyAgreement, VM_TYPE_X25519);
  const kemVMs = pick(doc.keyAgreement, VM_TYPE_ML_KEM1024);
  if (signVMs.length !== 1 || sigVMs.length !== 1 || encVMs.length !== 1 || kemVMs.length !== 1) return null;
  try {
    const signPub = hexToBytes(signVMs[0].publicKeyHex);
    const encPub = hexToBytes(encVMs[0].publicKeyHex);
    const kemPub = hexToBytes(kemVMs[0].publicKeyHex);
    const sigPub = hexToBytes(sigVMs[0].publicKeyHex);
    if (signPub.length !== SIGN_PUB_LEN || encPub.length !== ENC_PUB_LEN || kemPub.length !== KEM_PUB_LEN || sigPub.length !== SIG_PUB_LEN)
      return null;
    return { signPub, encPub, kemPub, sigPub };
  } catch {
    return null;
  }
}

// ── high-level sign (two paths) ──────────────────────────────────────────────────────────────────────────────
/**
 * GENESIS path — self-sign the (seq-0) DID-Doc with the identity's OWN genesis operational signing keys
 * (ed25519 `sign` + ML-DSA-87 `sig`). Fail-closed: the doc must be a single-device genesis whose operational
 * keys hash to the id anchor, and the supplied ed25519 seed must reproduce the doc's genesis sign pub. This is
 * the same key the identity card is signed with — a contact who accepted the card already trusts it.
 */
export function signDidDocGenesis(doc: DidDocument, signer: GenesisOperationalSigner): DidDocument {
  if (doc.seq !== 0) throw new Error('signDidDocGenesis: genesis doc must have seq 0');
  const keys = extractGenesisOperationalKeys(doc);
  if (!keys) throw new Error('signDidDocGenesis: genesis doc must have exactly one device (sign/enc/kem/sig)');
  const anchor = deriveCanonicalFingerprintHex(keys.signPub, keys.encPub, keys.kemPub, keys.sigPub);
  if (`${DID_METHOD}:${anchor}` !== doc.id)
    throw new Error('signDidDocGenesis: genesis operational keys do not anchor to the DID id (durable_id mismatch)');
  // fail-closed: the seed must correspond to the doc's genesis sign pub (mirrors extractRawSign's invariant).
  if (bytesToHex(ed25519.getPublicKey(signer.signSeed)) !== bytesToHex(keys.signPub))
    throw new Error('signDidDocGenesis: signSeed does not match the genesis sign pub in the doc');
  const canonicalInput = canonicalDidDocInput({ ...doc, proof: undefined });
  const sig = signDidDocHybrid(canonicalInput, signer.signSeed, signer.sigSecret);
  return { ...doc, proof: { type: DID_DOC_PROOF_TYPE, mode: 'genesis-operational', domain: DOMAIN_DID_DOC, sig } };
}

/**
 * MUTATION path — sign a (seq ≥ 1) DID-Doc with the cold-seed governance AUTHORITY keypair and REVEAL its pubs.
 * A verifier checks H(revealed pubs) == the prior doc's nextAuthorityCommitment before accepting. Use for
 * add/revoke device, endpoint move, or authority rotation.
 */
export function signDidDocMutation(doc: DidDocument, authority: NextAuthorityKeypair): DidDocument {
  if (!Number.isInteger(doc.seq) || doc.seq < 1)
    throw new Error('signDidDocMutation: a mutation must have seq ≥ 1 (genesis is operational-self-signed)');
  const authorityPubkeys = encodeAuthorityPubkeys(authority.edPublic, authority.dsaPublic);
  const canonicalInput = canonicalDidDocInput({ ...doc, proof: undefined });
  const sig = signDidDocHybrid(canonicalInput, authority.edSecret, authority.dsaSecret);
  return {
    ...doc,
    proof: { type: DID_DOC_PROOF_TYPE, mode: 'authority-mutation', domain: DOMAIN_DID_DOC, authorityPubkeys, sig },
  };
}

export interface DidDocVerifyResult {
  ok: boolean;
  reason?: string;
  seq?: number;
  did?: string;
  /** The authority commitment this doc pins for the NEXT doc — the edge threads it as the next expected commitment. */
  nextAuthorityCommitment?: string;
}

/**
 * Verify a signed DID-Doc. TWO paths:
 *   • genesis-operational (seq 0): the doc's single-device operational keys must hash to the id anchor
 *     (self-certification), and the hybrid signature must verify under those operational pubs.
 *   • authority-mutation (seq ≥ 1): H(revealed authority pubs) must equal `opts.expectedAuthorityCommitment`
 *     (the prior doc's nextAuthorityCommitment, threaded by the edge's lineage walk), and the hybrid signature
 *     must verify under the revealed authority pubs.
 * Monotonic-seq enforcement across successive docs is the EDGE's job — pass `lastSeenSeq` to reject stale/replayed docs.
 */
export function verifyDidDocument(
  doc: DidDocument,
  opts: { lastSeenSeq?: number; expectedAuthorityCommitment?: string } = {},
): DidDocVerifyResult {
  const proof = doc.proof;
  if (!proof || proof.type !== DID_DOC_PROOF_TYPE) return { ok: false, reason: 'missing-or-unknown-proof' };
  if (!Number.isInteger(doc.seq) || doc.seq < 0) return { ok: false, reason: 'bad-seq' };
  if (opts.lastSeenSeq !== undefined && doc.seq <= opts.lastSeenSeq) return { ok: false, reason: 'seq-not-monotonic' };
  if (!HEX64_RE.test(doc.nextAuthorityCommitment)) return { ok: false, reason: 'bad-next-authority-commitment' };
  let anchorHex: string;
  try {
    anchorHex = parseDid(doc.id).anchorHex;
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : 'bad-did' };
  }
  const canonicalInput = canonicalDidDocInput(doc);

  if (proof.mode === 'genesis-operational') {
    if (doc.seq !== 0) return { ok: false, reason: 'genesis-must-be-seq-0' };
    const keys = extractGenesisOperationalKeys(doc);
    if (!keys) return { ok: false, reason: 'genesis-not-single-device' };
    // (1) self-certification: the doc's own operational keys reproduce the durable_id anchor.
    if (deriveCanonicalFingerprintHex(keys.signPub, keys.encPub, keys.kemPub, keys.sigPub) !== anchorHex)
      return { ok: false, reason: 'operational-keys-do-not-anchor-to-id' };
    // (2) hybrid signature under those operational pubs.
    if (!verifyDidDocHybrid(canonicalInput, proof.sig, bytesToHex(keys.signPub), bytesToHex(keys.sigPub)))
      return { ok: false, reason: 'genesis-operational-sig-invalid' };
    return { ok: true, seq: doc.seq, did: doc.id, nextAuthorityCommitment: doc.nextAuthorityCommitment };
  }

  if (proof.mode === 'authority-mutation') {
    if (doc.seq < 1) return { ok: false, reason: 'mutation-must-advance-seq' };
    if (!proof.authorityPubkeys) return { ok: false, reason: 'mutation-missing-authority-reveal' };
    if (!opts.expectedAuthorityCommitment) return { ok: false, reason: 'authority-commitment-required' };
    // (1) the revealed authority must match the pre-rotation commitment the prior doc pinned.
    let revealedCommitment: string;
    try {
      revealedCommitment = authorityCommitmentFromReveal(proof.authorityPubkeys.sign, proof.authorityPubkeys.pq_sig);
    } catch (e) {
      return { ok: false, reason: e instanceof Error ? e.message : 'authority-reveal-decode' };
    }
    if (revealedCommitment !== normalizeFingerprintHex(opts.expectedAuthorityCommitment))
      return { ok: false, reason: 'authority-not-committed' };
    // (2) hybrid signature under the revealed authority pubs.
    if (!verifyDidDocHybrid(canonicalInput, proof.sig, proof.authorityPubkeys.sign, proof.authorityPubkeys.pq_sig))
      return { ok: false, reason: 'authority-sig-invalid' };
    return { ok: true, seq: doc.seq, did: doc.id, nextAuthorityCommitment: doc.nextAuthorityCommitment };
  }

  return { ok: false, reason: 'unknown-proof-mode' };
}

// ── resolver (used by verify + future T3 edge-verify wiring) ─────────────────────────────────────────────
/** Look up a verificationMethod (signing or agreement) by its full fragment id. */
export function resolveVerificationMethod(doc: DidDocument, id: string): VerificationMethod | undefined {
  return doc.verificationMethod.find((v) => v.id === id) ?? doc.keyAgreement.find((v) => v.id === id);
}
