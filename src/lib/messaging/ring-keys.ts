// src/lib/messaging/ring-keys.ts
// Load the unlocked identity's X25519 + ML-KEM secrets, and a contact's public
// counterparts, so a ring fan-out can use the hybrid triple ratchet.
// Missing PQ material returns null — a classical-only contact cannot join a ring.

import { decryptKey, readPrivateKey } from 'openpgp';
import { base64ToUint8 } from '@/lib/crypto/pq';
import type { RatchetIdentity } from '@/lib/crypto/message-ratchet';
import { canonicalPubsFromArmoredPublicKey } from '@/lib/identity/fingerprint';
import { extractRawEnc } from '@/lib/identity/raw-sign';
import { loadKey, loadPQKeys, type ContactRecord } from '@/lib/identity/client-store';
import type { RingPeer } from './ring-session';

export async function loadRatchetIdentity(fingerprint: string): Promise<RatchetIdentity | null> {
  const key = await loadKey(fingerprint);
  if (!key?.privateKey || !key.passphrase) return null;
  const pq = await loadPQKeys(fingerprint);
  const kemSecB64 = pq?.kem?.secretKey;
  const kemPubB64 = pq?.kem?.publicKey;
  if (typeof kemSecB64 !== 'string' || typeof kemPubB64 !== 'string') return null;
  try {
    const locked = await readPrivateKey({ armoredKey: key.privateKey });
    const decrypted = await decryptKey({ privateKey: locked, passphrase: key.passphrase });
    const { encSec, encPub } = await extractRawEnc(decrypted);
    const mlkem1024Sec = base64ToUint8(kemSecB64);
    const mlkem1024Pub = base64ToUint8(kemPubB64);
    if (mlkem1024Sec.length !== 3168 || mlkem1024Pub.length !== 1568) return null;
    return { x25519Sec: encSec, x25519Pub: encPub, mlkem1024Sec, mlkem1024Pub };
  } catch {
    return null;
  }
}

/** Public X25519 + ML-KEM for an admitted contact. Null when the card has no PQ encap key. */
export async function ringPeerFromContact(contact: ContactRecord): Promise<RingPeer | null> {
  if (!contact.public_key || !contact.pq_kem_public_key || !contact.pq_sig_public_key) return null;
  if (!contact.fingerprint) return null;
  try {
    const pubs = await canonicalPubsFromArmoredPublicKey(
      contact.public_key,
      contact.pq_kem_public_key,
      contact.pq_sig_public_key,
    );
    return {
      fingerprint: contact.fingerprint,
      x25519Pub: pubs.encPub,
      mlkem1024Pub: pubs.kemPub,
    };
  } catch {
    return null;
  }
}
