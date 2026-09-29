// src/lib/identity/introduce-shell.ts
//
// INTRODUCE-SHELL — headless svrnty identity for the fleet↔Devin secure channel (Devin dogfood, KB#91090).
// Flint blessed the mechanism (#151702); Peter greenlit the direction (#151686).
//
// WHAT THIS IS. A SMALL wrapper that composes the EXISTING crypto paths (deriveCanonicalFingerprintHex,
// deriveDid, buildDidDocument, signDidDocGenesis, deriveNextAuthorityCommitment) into the introduction
// artifact a fleet agent hands out. NO divergent headless crypto (Flint REQ 2) — every byte comes from the
// same house canonicalize() + sign-envelope the interactive flow uses, so a Python verifier reproduces it.
//
// THE MODEL (KB#91090 + agent-identity discovery):
//   • Each agent mints its OWN svrnty identity (its own cold-seed genesis anchor = the T1 durable_id model),
//     NOT a device under Peter — signing as Peter's device would let it post AS Peter (blast-radius + the
//     'never post as Peter' invariant). Trust is a mutual EDGE to Peter ("these are Peter's agents").
//   • ★ subject_type is bound INTO the signed genesis DID-Doc (Flint REQ 1) — an honest, non-strippable,
//     self-declared attestation. svrnty NEVER proves embodiment (a personhood-authority = centralization /
//     §0-violation); the attestation is verified SOCIALLY (trust graph), and Peter's OUT-OF-BAND fingerprint
//     check is the anti-MITM lock. Devin = an external identity, introduced (trust-linked) in.
//
// FLOW v1: WE mint agent identities + build these introductions → Peter fp-verifies each durable_id OOB ONCE
// (KNOWN→VERIFIED) → messages are SEALED over the existing channel (reuse messaging/seal.ts `sealNoteTo` —
// classical OpenPGP seal to the peer's pubkey; the transport/serve wiring into nuavalon_send is Athena's lane).
// CUSTODY: each agent's private keys are custodied PER-AGENT (Athena's serve), never plaintext-shared.

import { deriveCanonicalFingerprintHex, deriveNextAuthorityCommitment } from './fingerprint';
import {
  DID_METHOD,
  buildDidDocument,
  deriveDid,
  signDidDocGenesis,
  verifyDidDocument,
  type DidDocument,
  type GenesisOperationalSigner,
  type ServiceEndpoint,
  type SubjectType,
} from './did-peer';

/** An agent's genesis operational public keys — the 4-key bundle that IS its durable_id (single genesis device). */
export interface AgentGenesisKeys {
  deviceSlug: string; // fragment label for the genesis device, e.g. 'genesis'
  signPub: Uint8Array; // 32B ed25519
  encPub: Uint8Array; // 32B x25519
  kemPub: Uint8Array; // 1568B ML-KEM-1024
  sigPub: Uint8Array; // 2592B ML-DSA-87
}

/** The introduction artifact: handed to Peter (fp-verify OOB once) and to the channel peer (import + verify). */
export interface AgentIntroduction {
  did: string; // did:svrnty:<durable_id>
  durableId: string; // 64-hex canonical fingerprint — the value Peter checks out-of-band
  subjectType: SubjectType; // honest self-attestation, bound inside signedDidDoc's signature
  signedDidDoc: DidDocument; // genesis, operational-self-signed, subjectType bound
}

/**
 * Build an agent's genesis introduction: its durable_id DID + a subject_type-bound, operationally self-signed
 * genesis DID-Doc. `authorityCommitment` = H(cold-seed authority epoch-0 pubs) — the caller derives it while
 * the cold seed is in hand (deriveGenesisAuthorityCommitment). `subjectType` defaults to 'agent' (fleet agents).
 * Reuses the SAME crypto paths as the interactive flow; adds no new signing primitive.
 */
export function buildAgentIntroduction(params: {
  keys: AgentGenesisKeys;
  signer: GenesisOperationalSigner; // raw ed25519 seed + ML-DSA-87 sig secret (the genesis operational keys)
  authorityCommitment: string; // deriveNextAuthorityCommitment(coldSeed, 0)
  subjectType?: SubjectType; // default 'agent'
  services?: ServiceEndpoint[];
}): AgentIntroduction {
  const { keys } = params;
  const subjectType: SubjectType = params.subjectType ?? 'agent';
  const durableId = deriveCanonicalFingerprintHex(keys.signPub, keys.encPub, keys.kemPub, keys.sigPub);
  const did = deriveDid(keys.signPub, keys.encPub, keys.kemPub, keys.sigPub);
  const doc = buildDidDocument({
    did,
    devices: [{ device: keys.deviceSlug, signPub: keys.signPub, encPub: keys.encPub, kemPub: keys.kemPub, sigPub: keys.sigPub }],
    nextAuthorityCommitment: params.authorityCommitment,
    subjectType,
    services: params.services,
    seq: 0,
  });
  const signedDidDoc = signDidDocGenesis(doc, params.signer);
  return { did, durableId, subjectType, signedDidDoc };
}

/** Convenience: the genesis (epoch-0) cold-seed authority commitment for an identity's introduction. */
export function deriveGenesisAuthorityCommitment(coldSeed: Uint8Array): string {
  return deriveNextAuthorityCommitment(coldSeed, 0);
}

export interface VerifiedIntroduction {
  did: string;
  durableId: string;
  subjectType: SubjectType;
}

/**
 * Verify a received agent introduction (import gate for a fleet peer / the channel). Checks: the genesis
 * DID-Doc self-certifies (operational keys → durable_id anchor), its id matches the claimed did/durableId, and
 * it CARRIES a subject_type attestation (an introduction without one is rejected — the whole point is the
 * honest self-declaration). Returns the verified attestation or null (never throws).
 *
 * ★ This proves the doc is internally consistent + names its subject_type. It does NOT prove embodiment —
 * Peter's OUT-OF-BAND fingerprint check on `durableId` is the anti-MITM lock that binds this to the real agent.
 */
export function verifyAgentIntroduction(intro: AgentIntroduction): VerifiedIntroduction | null {
  if (!intro || !intro.signedDidDoc) return null;
  if (intro.signedDidDoc.id !== intro.did) return null;
  if (intro.did !== `${DID_METHOD}:${intro.durableId}`) return null;
  const r = verifyDidDocument(intro.signedDidDoc);
  if (!r.ok) return null;
  if (r.did !== intro.did) return null;
  if (r.subjectType === undefined) return null; // an introduction MUST carry the honest attestation
  if (r.subjectType !== intro.subjectType) return null; // the surfaced attestation must match the signed one
  return { did: intro.did, durableId: intro.durableId, subjectType: r.subjectType };
}
