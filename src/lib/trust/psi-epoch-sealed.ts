// src/lib/trust/psi-epoch-sealed.ts
/**
 * The plaintext inside a sealed package that carries an epoch note: the 106-byte epoch wire, then the CLAIMED sender fingerprint as 32 raw bytes
 * (the canonical 64-hex fingerprint decoded), 138 bytes exactly. Pure: no storage, no crypto beyond byte handling.
 *
 *   [ 0 .. 106 )  the epoch wire (header 0x45 0x01, e, know, trust, tag), authenticated by a MAC under the pairwise secret
 *   [ 106 .. 138 ) the claimed sender fingerprint. UNAUTHENTICATED until the MAC verifies: the MAC binds both fingerprints and the epoch.
 *
 * The wire comes first so the type is at offset 0. Dispatch reads the length and two bytes and nothing else:
 *   - exactly 138 bytes AND bytes[0..1] == 0x45 0x01  -> 'epoch'
 *   - header 0x45 0x01 with any other length            -> 'malformed' (the unverified path, no fingerprint)
 *   - anything else                                     -> 'other': not this seam's, so every other package keeps the path it has today
 *
 * Fingerprint domain: 32 raw bytes is a 64-hex fingerprint. A contact with a classical 40-hex fingerprint is not an epoch-note peer; a trailer
 * decodes to lowercase 64-hex, so it can only ever match a book entry by EXACT equality with a stored 64-hex fingerprint.
 */
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js';
import { EPOCH_NOTE_HEADER, EPOCH_NOTE_LEN } from './psi-epoch-note';

export const CLAIMED_FP_BYTES = 32;
export const EPOCH_SEALED_LEN = EPOCH_NOTE_LEN + CLAIMED_FP_BYTES; // 138

const CANONICAL_FP = /^[0-9a-f]{64}$/;

export type EpochDispatch = 'epoch' | 'malformed' | 'other';

/** Reads the length and the first two bytes only. */
export function dispatchSealed(plain: Uint8Array): EpochDispatch {
  if (!(plain instanceof Uint8Array) || plain.length < EPOCH_NOTE_HEADER.length) return 'other';
  if (plain[0] !== EPOCH_NOTE_HEADER[0] || plain[1] !== EPOCH_NOTE_HEADER[1]) return 'other';
  return plain.length === EPOCH_SEALED_LEN ? 'epoch' : 'malformed';
}

function requireEpoch(plain: Uint8Array): void {
  if (dispatchSealed(plain) !== 'epoch') throw new TypeError('psi-epoch-sealed: not an epoch plaintext (138 bytes, header 0x45 0x01)');
}

/** The 106-byte epoch wire. Only for a plaintext dispatchSealed called 'epoch'. */
export function epochWireOf(plain: Uint8Array): Uint8Array {
  requireEpoch(plain);
  return plain.slice(0, EPOCH_NOTE_LEN);
}

/** The claimed sender fingerprint as canonical lowercase 64-hex. Only for a plaintext dispatchSealed called 'epoch'. */
export function claimedFpOf(plain: Uint8Array): string {
  requireEpoch(plain);
  return bytesToHex(plain.slice(EPOCH_NOTE_LEN, EPOCH_SEALED_LEN));
}

/** The plaintext to seal: the epoch wire, then the sender's fingerprint. The fingerprint must be canonical lowercase 64-hex. */
export function buildEpochSealedPlaintext(wire: Uint8Array, senderFp: string): Uint8Array {
  if (!(wire instanceof Uint8Array) || wire.length !== EPOCH_NOTE_LEN || wire[0] !== EPOCH_NOTE_HEADER[0] || wire[1] !== EPOCH_NOTE_HEADER[1]) {
    throw new TypeError('psi-epoch-sealed: the wire must be a 106-byte epoch note');
  }
  if (typeof senderFp !== 'string' || !CANONICAL_FP.test(senderFp)) throw new TypeError('psi-epoch-sealed: the sender fingerprint must be canonical lowercase 64-hex');
  return concatBytes(wire, hexToBytes(senderFp));
}
