// src/lib/trust/claim-digest.ts — task #810: the ONE place a signed claim is turned into a digest.
/**
 * Pure. The digest of an object is the hash of its SIGNED CLAIM, never of its bytes: ML-DSA signatures are randomized, so the same claim
 * re-signed is different bytes and must still be the same object. Pending, conflicts and an APPROVE record all name claims by these digests,
 * so there is one helper per kind and nothing re-derives them.
 *  - pointer v2: SHA-256 of the signed prefix (pointerV2Prefix).
 *  - successor: SHA-256 of the canonical rotation signing input under the pin it was verified against.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { pointerV2Prefix, type VerifiedPointerV2 } from './pointer-v2-wire';
import type { RotationSuccessorInput } from './contact-update';
import { rotationSigningInput } from '../format/envelope';

/** Digest of a pointer's SIGNED CLAIM (the signed prefix), as 64 lowercase hex. */
export const digestOfPointer = (v: VerifiedPointerV2): string => bytesToHex(pointerClaimDigest(v));

/** The same digest as 32 raw bytes (what an APPROVE record carries). */
export const pointerClaimDigest = (v: VerifiedPointerV2): Uint8Array =>
  sha256(pointerV2Prefix({
    mailboxId: hexToBytes(v.mailboxId.slice('mbx2_'.length)),
    relay: v.relay,
    identityEpoch: v.identityEpoch,
    pointerEpoch: v.pointerEpoch,
    x25519Pub: v.x25519Pub,
    mlkem1024Ek: v.mlkem1024Ek,
    hasAuthority: v.authoritySigned,
  }));

/** Digest of a successor's SIGNED CLAIM (the canonical rotation signing input under the pin it was verified against). */
export const digestOfSuccessor = (s: Readonly<RotationSuccessorInput>, priorPin: string): string =>
  bytesToHex(sha256(utf8ToBytes(rotationSigningInput({
    durable_id: s.durable_id,
    prior_epoch: s.prior_epoch,
    prior_authority_commitment: priorPin,
    successor_epoch: s.successor_epoch,
    new_fingerprint: s.new_fingerprint,
    next_authority_commitment: s.next_authority_commitment,
  }))));
