// src/lib/sync/send-joiner-response.ts
// The JOINER's RETURN-CHANNEL deposit — the sender counterpart of the giver's consume (live-book-poll →
// consume-mailbox). After the joiner adds the giver (JoinerCeremony persistEdge), this signs the joiner's
// self-asserted identity claim ONCE and deposits it — E2E-encrypted to the giver — into the giver's
// return-channel mailbox. The giver polls, runs verifyJoinerResponse, and surfaces the joiner as KNOWN.
// That closes the one-directional Grow asymmetry (R1): the edge becomes MUTUAL, so the
// already-live 0.4 contact.update wire has a Bob-edge to propagate along ("connect → send").
//
// SECURITY SHAPE (mirror send-contact-update.ts — same E2E envelope, no new key material):
//  • SIGN with the joiner's OWN key — the giver's verifyJoinerResponse enforces Invariant-1
//    (joiner_fp === H(joiner_public_key)) AND the envelope signature against joiner_public_key. The
//    joiner proves possession of the key behind the fingerprint+name it claims (self-asserted TOFU).
//  • ENCRYPT to the GIVER's public key → opaque armored blob; the relay stores ciphertext only
//    (custody / I-1: it cannot read the identity or reconstruct the edge).
//  • ADDRESS by deriveMailboxId(giver fingerprint) — the same deterministic mailbox id the giver polls.
//  • BIND to THIS giver — giver_fingerprint is signed and checked === the giver's own fp on consume, so
//    a captured blob re-deposited to a different giver's mailbox is rejected there (no cross-giver replay);
//    invite_nonce (the relay code the joiner used) is the solicited-gate proof (anti-spam).
//  • IDENTITY-ONLY — carries the joiner's {fp, epoch, key, name}, NEVER contact methods. The whole
//    method-poisoning surface stays on the one already-hardened contact-update path, not duplicated here.
//  • FAIL-CLOSED — a target with no usable public key yields no deposit (null), never a downgraded send;
//    the caller (the ceremony) is fail-soft and never blocks on the return channel (I-1: any failure is
//    a local-only diagnostic, never surfaced to a peer/relay).
//
// CLASSICAL FOR LAUNCH — the 0.4 wire is classical; the hybrid-PQ suite is a named
// upgrade that swaps here (pass a pq secret to buildJoinerResponse + carry joinerPqSigPublicKey) with no
// consume-side change. Kept fetch-free/pure (buildJoinerResponseDeposit) so it is unit-testable and the
// component injects the identities.

import { deriveMailboxId } from '../relay/mailbox-auth';
import { buildJoinerResponse, encryptJoinerResponseTo } from '../trust/joiner-response';

/** The joiner's signing identity (from the unlocked vault) + self-asserted claim. Classical for launch. */
export interface JoinerResponseSender {
  /** The joiner's own durable, genesis-derived fingerprint (the sender of the response). */
  fingerprint: string;
  /** The joiner's current key epoch — the giver records it as the FUTURE contact.update replay floor.
   *  MUST equal the epoch the joiner ships contact.updates at (0 until key-rotation exists) or the
   *  giver would stale-reject the joiner's later updates. */
  epoch: number;
  /** The joiner's armored classical public key — the giver adds it AND the signature verifies against it. */
  publicKeyArmored: string;
  /** The joiner's self-asserted display name (KNOWN = unverified; may be empty). */
  displayName: string;
  privateKeyArmored: string;
  passphrase: string;
  /** §5 canonical-fp binding: the joiner's ML-KEM-1024 public (base64, 1568B). Thread with sigPublicKeyB64
   *  so the giver recomputes our 64-hex canonical id (SHA256(sign‖enc‖kem‖sig)). Optional — a classical
   *  (40-hex OpenPGP) joiner omits both; sourced from the identity's post_quantum.kem_public_key. */
  kemPublicKeyB64?: string;
  /** §5 canonical-fp binding: the joiner's ML-DSA-87 public (base64, 2592B) — the other half. */
  sigPublicKeyB64?: string;
}

/** The giver being connected back to: fingerprint (→ mailbox + binding) + pubkey (→ encrypt-to) + code. */
export interface JoinerResponseTarget {
  /** The giver's fingerprint (from the card the joiner opened) — mailbox address + response binding. */
  fingerprint: string;
  /** The giver's armored public key — the E2E encryption recipient. */
  publicKeyArmored: string;
  /** The giver's relay code the joiner used — the solicited-gate proof (invite_nonce). */
  inviteNonce: string;
}

/** Outcome of the single deposit — best-effort accounting; the caller (ceremony) is fail-soft. */
export interface JoinerResponseSendResult {
  ok: boolean;
  /** relay status on success, or the failure classifier ('encrypt-failed' | 'network-error' | HTTP status). */
  status?: number | string;
}

/**
 * Pure: build + sign + encrypt the joiner-response → one ready-to-POST deposit {mailbox_id, blob}, or
 * null if the target has no usable public key or the build/encrypt fails (never sent downgraded).
 * fetch-free so it is unit-testable; the caller POSTs it.
 */
export async function buildJoinerResponseDeposit(
  sender: JoinerResponseSender,
  target: JoinerResponseTarget,
): Promise<{ mailbox_id: string; blob: string } | null> {
  if (
    typeof target.fingerprint !== 'string' || target.fingerprint.length === 0 ||
    typeof target.publicKeyArmored !== 'string' || target.publicKeyArmored.length === 0 ||
    typeof target.inviteNonce !== 'string' || target.inviteNonce.length === 0
  ) {
    return null;
  }
  try {
    const signed = await buildJoinerResponse(
      {
        joinerFp: sender.fingerprint,
        joinerEpoch: sender.epoch,
        joinerPubKeyArmored: sender.publicKeyArmored,
        joinerName: sender.displayName,
        giverFp: target.fingerprint,
        inviteNonce: target.inviteNonce,
        // §5: carry our PQ pubkeys so the giver recomputes our 64-hex canonical id. Only when BOTH are
        // present (a canonical identity); a classical identity omits them → the giver's OpenPGP-fp path.
        ...(sender.kemPublicKeyB64 && sender.sigPublicKeyB64
          ? { joinerPqKemPublicKey: sender.kemPublicKeyB64, joinerPqSigPublicKey: sender.sigPublicKeyB64 }
          : {}),
      },
      sender.privateKeyArmored,
      sender.passphrase,
    );
    const blob = await encryptJoinerResponseTo(signed, target.publicKeyArmored);
    return { mailbox_id: deriveMailboxId(target.fingerprint), blob };
  } catch {
    // A malformed input / unreadable recipient key must not throw to the ceremony — report as no-deposit.
    return null;
  }
}

/**
 * The drop-in: build + POST the joiner-response to the giver's return-channel mailbox. Best-effort — a
 * POST failure is reported (retryable), never thrown to the ceremony (which is fail-soft and keeps the
 * local edge regardless). Each deposit is idempotent-safe at the giver: a redelivered blob re-verifies
 * to the same KNOWN joiner and the per-(code, joinerFp) accept-oracle dedups it.
 */
export async function sendJoinerResponse(
  sender: JoinerResponseSender,
  target: JoinerResponseTarget,
  opts: { fetchImpl?: typeof fetch; relayBase?: string } = {},
): Promise<JoinerResponseSendResult> {
  const doFetch = opts.fetchImpl ?? fetch;
  const relayBase = opts.relayBase ?? '/api/relay';

  const deposit = await buildJoinerResponseDeposit(sender, target);
  if (!deposit) return { ok: false, status: 'encrypt-failed' };

  try {
    const res = await doFetch(`${relayBase}/envelope`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mailbox_id: deposit.mailbox_id, blob: deposit.blob }),
    });
    return res.ok ? { ok: true, status: res.status } : { ok: false, status: res.status };
  } catch {
    return { ok: false, status: 'network-error' };
  }
}
