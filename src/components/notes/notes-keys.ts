// Assemble sendNoteToPeer identity args from the unlocked session.
// CALLS loadKey / loadIdentity fields. Does not reimplement crypto.
// Canonical senders (64-hex fp + PQ pubs) thread kem+sig so the recipient can bind the sender.

import { readPrivateKey } from 'openpgp';
import { loadKey } from '@/lib/identity/client-store';
import { normalizeFingerprintHex } from '@/lib/identity/fingerprint';

export type OwnerNoteSender = {
  fingerprint: string;
  publicKeyArmored: string;
  privateKeyArmored: string;
  passphrase: string;
  pqKemPublicKey?: string;
  pqSigPublicKey?: string;
  canonical: boolean;
};

function pqPubsFromIdentity(identity: unknown): { kem?: string; sig?: string; publicKeyArmored?: string; fingerprint?: string } {
  const root = identity && typeof identity === 'object' ? (identity as Record<string, unknown>) : {};
  const pq = root.post_quantum && typeof root.post_quantum === 'object' ? (root.post_quantum as Record<string, unknown>) : {};
  const id = root.identity && typeof root.identity === 'object' ? (root.identity as Record<string, unknown>) : {};
  const kem = typeof pq.kem_public_key === 'string' ? pq.kem_public_key.trim() : '';
  const sig = typeof pq.sig_public_key === 'string' ? pq.sig_public_key.trim() : '';
  const publicKeyArmored =
    (typeof id.public_key === 'string' && id.public_key.trim()) ||
    (typeof root.public_key === 'string' && (root.public_key as string).trim()) ||
    '';
  const fingerprint = normalizeFingerprintHex(String(id.fingerprint || root.fingerprint || ''));
  return {
    kem: kem || undefined,
    sig: sig || undefined,
    publicKeyArmored: publicKeyArmored || undefined,
    fingerprint: fingerprint || undefined,
  };
}

export function isCanonicalNoteSender(fingerprint: string, pqKem?: string, pqSig?: string): boolean {
  return normalizeFingerprintHex(fingerprint).length === 64 && Boolean(pqKem) && Boolean(pqSig);
}

export async function loadOwnerNoteSender(
  fingerprint: string,
  identity: unknown,
): Promise<OwnerNoteSender | null> {
  const fp = normalizeFingerprintHex(fingerprint);
  if (!fp) return null;
  const key = await loadKey(fp);
  if (!key?.privateKey) return null;
  const pubs = pqPubsFromIdentity(identity);
  let publicKeyArmored = pubs.publicKeyArmored || '';
  if (!publicKeyArmored) {
    try {
      publicKeyArmored = (await readPrivateKey({ armoredKey: key.privateKey })).toPublic().armor();
    } catch {
      return null;
    }
  }
  const pqKemPublicKey = pubs.kem;
  const pqSigPublicKey = pubs.sig;
  return {
    fingerprint: fp,
    publicKeyArmored,
    privateKeyArmored: key.privateKey,
    passphrase: key.passphrase,
    pqKemPublicKey,
    pqSigPublicKey,
    canonical: isCanonicalNoteSender(fp, pqKemPublicKey, pqSigPublicKey),
  };
}
