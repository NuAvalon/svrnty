// Assemble TripleRatchet identity/peer pubs by CALLING existing extractors.
// Does not reimplement extractRawEnc / canonicalPubs / PQ parse.

import { loadKey, loadPQKeys, getContactByFingerprint } from '@/lib/identity/client-store';
import { canonicalPubsFromArmoredPublicKey } from '@/lib/identity/fingerprint';
import type { RatchetIdentity, RatchetPeer } from '@/lib/crypto/message-ratchet';
import {
  assembleOwnerMessageKeys,
  parseStoredPqBundle,
  pqPubsFromIdentity,
  unlockArmoredIdentityKey,
} from '@/components/encrypt-decrypt/encrypt-decrypt-keys';

export async function loadOwnerRatchetIdentity(
  fingerprint: string,
  identity: unknown,
): Promise<RatchetIdentity | null> {
  const key = await loadKey(fingerprint);
  if (!key?.privateKey) return null;
  const pqStored = await loadPQKeys(fingerprint);
  const pq = parseStoredPqBundle(pqStored, pqPubsFromIdentity(identity));
  if (!pq) return null;
  try {
    const unlocked = await unlockArmoredIdentityKey(key.privateKey, key.passphrase);
    const assembled = await assembleOwnerMessageKeys(unlocked, pq);
    return {
      x25519Sec: assembled.me.x25519Sec,
      x25519Pub: assembled.me.x25519Pub,
      mlkem1024Sec: assembled.me.mlkem1024Sec,
      mlkem1024Pub: assembled.me.mlkem1024Pub,
    };
  } catch {
    return null;
  }
}

export async function peerRatchetFromCard(args: {
  publicKeyArmored: string;
  pqKemPublicKey?: string;
  pqSigPublicKey?: string;
}): Promise<RatchetPeer | null> {
  const kem = args.pqKemPublicKey?.trim();
  const sig = args.pqSigPublicKey?.trim();
  if (!args.publicKeyArmored.trim() || !kem || !sig) return null;
  try {
    const pubs = await canonicalPubsFromArmoredPublicKey(args.publicKeyArmored, kem, sig);
    if (!pubs) return null;
    return { x25519Pub: pubs.enc, mlkem1024Pub: pubs.kem };
  } catch {
    return null;
  }
}

/** Peer pubs from a book row (imported signed card). */
export async function loadPeerRatchet(
  ownerFingerprint: string,
  peerFingerprint: string,
): Promise<RatchetPeer | null> {
  const contact = await getContactByFingerprint(ownerFingerprint, peerFingerprint);
  if (!contact) return null;
  const rec = contact as {
    public_key?: string;
    peer_public_key?: string;
    pq_kem_public_key?: string;
    peer_pq_kem_public_key?: string;
    pq_sig_public_key?: string;
    peer_pq_sig_public_key?: string;
  };
  return peerRatchetFromCard({
    publicKeyArmored: String(rec.public_key || rec.peer_public_key || ''),
    pqKemPublicKey: rec.pq_kem_public_key || rec.peer_pq_kem_public_key,
    pqSigPublicKey: rec.pq_sig_public_key || rec.peer_pq_sig_public_key,
  });
}
