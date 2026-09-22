// src/sw/gd-bootstrap.ts
// Node Zero G-D — first-install PIN BOOTSTRAP (Q5a / §5). At first serve the client has no pin; it captures
// Node Zero's lineage TOFU (trust-on-first-use) from the served release delivery, which MUST carry the genesis
// pubkeys (edPub/encPub/kemPub/sigPub). We verify the delivered fingerprint is INTERNALLY CONSISTENT with the
// delivered pubkeys (publisher_fp == SHA256(pubkeys), via the canonical fingerprint derivation) before pinning
// — a malformed / substituted delivery is rejected, not pinned. This does NOT prove the pubkeys are the REAL
// Node Zero (that is the irreducible TOFU limit, verdict §4.1) — the OOB fingerprint (G-C, ≥2 channels) is the
// mitigation, surfaced here as an offered (not required, never bricking) cross-check.
//
// Never throws — the delivery is origin-served (attacker-input surface). Returns a discriminated result.

import { deriveCanonicalFingerprintHex } from '../lib/identity/fingerprint.js';
import { readPin, capturePin } from './gd-pin-store.js';

/** Genesis pubkeys as delivered (base64). Lengths are validated against the canonical fp preimage widths. */
export interface DeliveredGenesis {
  publisherFpHex: string; // claimed anchor (64-hex)
  signPubB64: string; // ed25519 32
  encPubB64: string; // x25519 32
  kemPubB64: string; // ml-kem-1024 1568
  sigPubB64: string; // ml-dsa-87 2592
  firstCounter: number; // version_counter of the release delivered at bootstrap (>=1)
}

export type BootstrapResult =
  | { status: 'already-pinned' }
  | { status: 'pinned'; publisherFpHex: string; oobFingerprintHex: string } // caller offers oobFingerprintHex for OOB cross-check
  | { status: 'rejected'; reason: string };

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// canonical fp preimage widths (§5 / identity fingerprint)
const LEN = { sign: 32, enc: 32, kem: 1568, sig: 2592 };

/**
 * Capture the pin TOFU from a first-serve delivery, iff no pin exists yet. Verifies internal consistency
 * (publisher_fp == SHA256(pubkeys)) — a delivery whose claimed fp doesn't match its pubkeys is a malformed /
 * substitution attempt and is rejected. On success the pin is captured with HWM=0 (the first accepted release's
 * counter is committed later, on verify), and the derived fingerprint is returned so the UI can OFFER the OOB
 * cross-check against the G-C-published fingerprint.
 */
export async function bootstrapPin(d: DeliveredGenesis): Promise<BootstrapResult> {
  if (await readPin()) return { status: 'already-pinned' };

  let signPub: Uint8Array, encPub: Uint8Array, kemPub: Uint8Array, sigPub: Uint8Array;
  try {
    signPub = b64ToBytes(d.signPubB64);
    encPub = b64ToBytes(d.encPubB64);
    kemPub = b64ToBytes(d.kemPubB64);
    sigPub = b64ToBytes(d.sigPubB64);
  } catch {
    return { status: 'rejected', reason: 'malformed base64 in delivered pubkeys' };
  }
  if (signPub.length !== LEN.sign || encPub.length !== LEN.enc || kemPub.length !== LEN.kem || sigPub.length !== LEN.sig) {
    return { status: 'rejected', reason: 'delivered pubkey lengths do not match the canonical preimage widths' };
  }
  if (!Number.isSafeInteger(d.firstCounter) || d.firstCounter < 1) {
    return { status: 'rejected', reason: `firstCounter must be a safe integer >= 1, got ${d.firstCounter}` };
  }

  // Substitution-reject: the anchor MUST be the canonical fingerprint of THESE pubkeys.
  let derived: string;
  try {
    derived = deriveCanonicalFingerprintHex(signPub, encPub, kemPub, sigPub);
  } catch {
    return { status: 'rejected', reason: 'genesis pubkeys failed canonical fingerprint derivation' };
  }
  if (derived.toLowerCase() !== d.publisherFpHex.toLowerCase()) {
    return { status: 'rejected', reason: 'publisher_fp != SHA256(pubkeys) — inconsistent/substituted delivery' };
  }

  const ok = await capturePin({
    publisherFpHex: derived, // pin the DERIVED fp (never the caller-claimed one) — the pubkeys are the source of truth
    signPubB64: d.signPubB64, encPubB64: d.encPubB64, kemPubB64: d.kemPubB64, sigPubB64: d.sigPubB64,
    firstCounter: d.firstCounter,
  });
  if (!ok) return { status: 'already-pinned' }; // raced another capture

  return { status: 'pinned', publisherFpHex: derived, oobFingerprintHex: derived };
}
