// src/lib/trust/trust-affirm-transport.ts
// DEPOSIT side of the mutual-trust wire — seal + deposit a signed trust-affirmation to a peer's blind
// mailbox via the EXISTING dumb relay (no new relay smarts). Mirror of messaging/transport.sendNoteToPeer.
//
// When A trusts (or breaks trust with) B, A calls this to deposit a SIGNED affirmation into B's mailbox;
// B's consume seam (trust-affirm-consume.ts) authenticates → binds-to-B → admits (A in B's book) →
// flips they_trust_me / reciprocal. The relay stays a content-blind dead-drop (opaque blob + mailbox-id,
// no sender id — I-4), exactly like over-wire notes.
//
// LANE: this is the crypto/transport half of the deposit — the FE trust button (trustContact /
// breakTrust) wires to this one call. Signing (trust-affirm.ts) + sealing (trust-affirm-seal.ts) + the
// /envelope POST all live here, so the UI handler needs no crypto knowledge.

import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { signTrustAffirm, TRUST_AFFIRM_WIRE_TYPE, type TrustAffirmWireV0 } from './trust-affirm';
import { sealTrustAffirmTo } from './trust-affirm-seal';

/**
 * Seal + deposit one trust-affirmation to a peer's mailbox (opaque blob). `trusts=true` = "I trust you"
 * (flips the peer's they_trust_me→true on consume); `trusts=false` = "I broke trust" (→false). The
 * affirmation is SIGNED before sealing (direction-bound — a trust can't be flipped to a break in transit).
 */
export async function sendTrustAffirmToPeer(args: {
  senderFingerprint: string;
  /** Sender's own openpgp identity key material — signs the affirmation so the recipient can authenticate
   *  `from_fingerprint` (fingerprintMatchesKey binds senderPublicKeyArmored ↔ senderFingerprint). */
  senderPublicKeyArmored: string;
  senderPrivateKeyArmored: string;
  passphrase: string;
  /** §5 canonical-fp binding: the sender's PQ pubkeys (base64). Thread BOTH so a CANONICAL (64-hex) sender
   *  authenticates; omit for a classical (40-hex) sender → the OpenPGP-fp path. */
  senderPqKemPublicKey?: string;
  senderPqSigPublicKey?: string;
  peerFingerprint: string;
  peerPublicKeyArmored: string;
  /** The PEER's verified ML-KEM-1024 pubkey (base64). Present ⇒ the affirmation is sealed PQ-hybrid (HNDL).
   *  ABSENT ⇒ fail-closed: NOT deposited (deposited:false), never downgraded to classical. */
  peerPqKemPublicKey?: string;
  /** true = affirm trust; false = break trust. */
  trusts: boolean;
  affirmId?: string; // inject for determinism in tests; default a fresh uuid
  sentAt?: string; // inject for determinism in tests; default now
  relayBase?: string;
  fetchImpl?: typeof fetch;
}): Promise<{ affirm_id: string; deposited: boolean }> {
  const fetchImpl = args.fetchImpl ?? fetch;
  const relayBase = args.relayBase ?? '/api/relay';
  const affirm_id = args.affirmId ?? `af_${globalThis.crypto.randomUUID()}`;
  const sent_at = args.sentAt ?? new Date().toISOString();

  const unsigned: TrustAffirmWireV0 = {
    type: TRUST_AFFIRM_WIRE_TYPE,
    affirm_id,
    from_fingerprint: args.senderFingerprint,
    to_fingerprint: args.peerFingerprint, // bound in the signed preimage — the affirmation is for this peer only
    trusts: args.trusts,
    sent_at,
  };

  // Sign BEFORE sealing so the recipient authenticates the sender AND the direction (trust vs break):
  // the signature travels inside the sealed blob (confidentiality unchanged, authenticity + direction added).
  const wire = await signTrustAffirm(
    unsigned,
    args.senderPublicKeyArmored,
    args.senderPrivateKeyArmored,
    args.passphrase,
    args.senderPqKemPublicKey, // §5: both present ⇒ canonical-fp binding; else classical path
    args.senderPqSigPublicKey,
  );
  // fail-closed: no pq_kem → skip, never downgrade (HNDL). A peer without a verified ML-KEM-1024 pubkey
  // gets NO affirmation deposit — not a classical/downgraded send.
  if (!args.peerPqKemPublicKey) {
    console.warn('[trust-affirm] fail-closed: peer has no pq_kem — affirmation NOT deposited (never downgrade, HNDL)');
    return { affirm_id, deposited: false };
  }
  const blob = await sealTrustAffirmTo(wire, args.peerPublicKeyArmored, args.peerPqKemPublicKey);
  const mailbox_id = deriveMailboxId(args.peerFingerprint);
  const res = await fetchImpl(`${relayBase}/envelope`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mailbox_id, blob }),
  });
  return { affirm_id, deposited: res.ok };
}
