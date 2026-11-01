// src/lib/connect/joiner-response.ts
//
// The R1 return-channel deposit — SHARED by the two add paths (connect-ux
// wiring, svrnty#365): JoinerCeremony's gate-add and ConnectSheet's
// promote-to-known both close the one-directional Grow asymmetry through
// this single implementation. Never copy-paste a second one.
//
// After we add the giver, deposit a signed joiner-response to the GIVER's
// mailbox so the giver learns of us and the edge becomes MUTUAL (giver
// polls → verifyJoinerResponse → gates us → the 0.4 contact.update wire
// flows both ways). Best-effort + FAIL-SOFT: signing needs our unlocked
// private key; a locked identity or a failed deposit leaves the local
// book/gate entry standing and never surfaces to a peer (I-1). The giver's
// mailbox holds the response ~7d, so a deposit that lands on a later
// unlocked open still connects. IDENTITY-ONLY: carries our
// {fp, epoch, key, name}, never contact methods.

import { loadIdentity, loadKey } from '@/lib/identity/client-store';
import { sendJoinerResponse } from '@/lib/sync/send-joiner-response';

/** The minimal card fields the deposit binds to — the ceremony maps its
 *  PeerCard, the sheet maps its ConnectLinkCard, to this shape. */
export interface ReturnDepositPeer {
  fingerprint: string;
  publicKeyArmored: string;
  /** ML-KEM-1024 pubkey for the hybrid seal; absent → fail-closed skip
   *  inside buildJoinerResponseDeposit (never a downgraded deposit). */
  pqKemPublicKey?: string;
}

export interface ReturnDepositDeps {
  loadKey: typeof loadKey;
  loadIdentity: typeof loadIdentity;
  sendJoinerResponse: typeof sendJoinerResponse;
}

export async function depositJoinerResponse(
  ownerFp: string,
  peer: ReturnDepositPeer,
  code: string,
  deps: Partial<ReturnDepositDeps> = {},
): Promise<void> {
  const d: ReturnDepositDeps = { loadKey, loadIdentity, sendJoinerResponse, ...deps };
  try {
    if (!peer.fingerprint || !peer.publicKeyArmored || !code) return; // nothing to bind the response to
    const key = await d.loadKey(ownerFp);
    if (!key) {
      // Locked session — cannot sign. The gate/book entry is already stored; the return channel simply
      // doesn't fire this time (a later unlocked open can re-deposit within the giver's ~7d window).
      console.warn('[joiner-response] identity locked — return-channel deposit deferred (gate entry stands locally)');
      return;
    }
    const id = await d.loadIdentity(ownerFp);
    const ownPub: string = id?.identity?.public_key || '';
    if (!ownPub) return; // no own key to present — cannot build a verifiable response
    const displayName: string = id?.identity?.display_name || id?.identity?.name || '';
    const res = await d.sendJoinerResponse(
      {
        fingerprint: ownerFp,
        epoch: 0, // no key-rotation yet — the joiner ships contact.updates at epoch 0 (matches giver floor)
        publicKeyArmored: ownPub,
        displayName,
        privateKeyArmored: key.privateKey,
        passphrase: key.passphrase,
        // §5 canonical-fp binding: thread our PQ pubkeys so the giver recomputes our 64-hex canonical id.
        // Only when BOTH are present (a canonical identity); a classical identity omits them.
        ...(id?.post_quantum?.kem_public_key && id?.post_quantum?.sig_public_key
          ? { kemPublicKeyB64: id.post_quantum.kem_public_key, sigPublicKeyB64: id.post_quantum.sig_public_key }
          : {}),
      },
      {
        fingerprint: peer.fingerprint,
        publicKeyArmored: peer.publicKeyArmored,
        // HNDL: the giver's ML-KEM-1024 pubkey → hybrid seal. Absent (classical giver card) ⇒
        // buildJoinerResponseDeposit fail-closed-skips (null), never a classical/downgraded deposit.
        giverPqKemPublicKey: peer.pqKemPublicKey,
        inviteNonce: code,
      },
    );
    if (!res.ok) {
      console.warn('[joiner-response] deposit not delivered (gate entry stands locally):', res.status);
    }
  } catch (err) {
    console.warn('[joiner-response] deposit failed (gate entry stands locally):', err);
  }
}
