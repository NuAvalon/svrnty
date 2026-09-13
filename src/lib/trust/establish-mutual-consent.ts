// src/lib/trust/establish-mutual-consent.ts
// Best-effort, fail-soft owner→peer PSI-discovery consent write (POST /allowed).
//
// PSI ("who you both know") runs only when BOTH parties have each other in the satellite's
// allowed_senders (the mutual-connection privacy gate). This module writes the owner's OWN direction
// (owner consents to `peer` as an allowed sender) at the moment a real, keyed peer becomes a KNOWN
// contact — never the reverse. Each party writes only their own side; the satellite also enforces this
// cryptographically (the signature is owner-bound), so a client can't forge a peer's consent.
//
// Fail-soft by construction (mirrors depositJoinerResponse / live-book-poll): a locked session, a
// keyless peer, or a transient relay error never throws — the consent simply isn't written this tick
// and a later add/admit retries. It is called fire-and-forget (void) from the known-add sites, so the
// local edge is live regardless of whether the consent write lands. UX honesty: the discovery chord
// only lights once BOTH sides have consented ("added — pending until they add you back").
//
// ⚠ SIGNING GATED: signAllowedAdd's preimage is pending Flint's byte-exact pin (Athena #138504 Q1).
// The request body + wire format are settled ({sender_fingerprint, signature}, "{unix}:{b64sig}").

import { loadKey } from '@/lib/identity/client-store';
import { extractRawSign, signAllowedAdd } from '@/lib/identity/raw-sign';
import { toBase64 } from '@/lib/crypto/kdf';
import { decryptKey, readPrivateKey } from 'openpgp';

export interface EstablishConsentDeps {
  loadKey?: typeof loadKey;
  fetchImpl?: typeof fetch;
}

/**
 * Write owner→peer PSI-discovery consent to the satellite (POST /api/satellite/allowed/{owner}).
 * Returns true iff the satellite accepted the consent edge. Best-effort: any failure (locked session,
 * keyless/self peer, network) resolves to false without throwing. NEVER writes the reverse direction.
 */
export async function establishMutualConsent(
  ownerFp: string,
  peerFp: string,
  deps: EstablishConsentDeps = {},
): Promise<boolean> {
  // Real, distinct, keyed SVRNTY peers only. Keyless (vCard/gray) contacts carry no fingerprint and
  // never participate in PSI; a self-edge is meaningless. Guard both — silent no-op, not an error.
  if (!ownerFp || !peerFp || ownerFp === peerFp) return false;

  const load = deps.loadKey ?? loadKey;
  const doFetch = deps.fetchImpl ?? fetch;

  try {
    const key = await load(ownerFp);
    // Locked session ⇒ no signing key in memory ⇒ fail-soft (do NOT prompt, do NOT persist plaintext).
    // The consent is (re)written the next time this peer is added/admitted with the session open.
    if (!key?.privateKey || !key.passphrase) return false;

    const locked = await readPrivateKey({ armoredKey: key.privateKey });
    const decrypted = locked.isDecrypted()
      ? locked
      : await decryptKey({ privateKey: locked, passphrase: key.passphrase });
    const { seed } = extractRawSign(decrypted); // 32B Ed25519 seed — in-memory only, never persisted

    const unix = Math.floor(Date.now() / 1000);
    const sig = signAllowedAdd(seed, ownerFp, peerFp, unix); // ⚠ preimage GATED on Flint's Q1 pin
    const wire = `${unix}:${toBase64(sig)}`; // satellite parses "{unix}:{b64sig}", ±30s replay window

    const res = await doFetch(`/api/satellite/allowed/${encodeURIComponent(ownerFp)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // AllowedSenderRequest: sender_fingerprint = the peer we consent to; signature = owner-signed,
      // sender-bound (svrnty-allowed-add). Zero request-schema change (Athena #138504).
      body: JSON.stringify({ sender_fingerprint: peerFp, signature: wire }),
    });
    return res.ok;
  } catch (err) {
    // Local-only diagnostic; never surfaced to the peer/relay (I-1). One failed consent write must not
    // break the add/admit flow that triggered it — the edge is live locally regardless.
    console.error('[establish-mutual-consent] best-effort consent write failed (will retry on next add):', err);
    return false;
  }
}
