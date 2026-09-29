// Assemble SenderKeys / MyKeys for contact-message.ts from an unlocked identity.
// CALLS fleet extractRawSign / extractRawEnc / deriveCanonicalFingerprintHex.
// Does not reimplement crypto. myFingerprint is ALWAYS the recomputed canonical id
// (Flint #155 wiring gate) — never a placeholder or a stored card field.

import { decryptKey, readPrivateKey } from 'openpgp';
import { extractRawEnc, extractRawSign } from '@/lib/identity/raw-sign';
import { deriveCanonicalFingerprintHex } from '@/lib/identity/fingerprint';
import { base64ToUint8 } from '@/lib/crypto/pq';
import type { MyKeys, SenderKeys } from '@/lib/crypto/contact-message';

export type ParsedPqMaterial = {
  sigSecret: Uint8Array;
  kemSec: Uint8Array;
  sigPub: Uint8Array;
  kemPub: Uint8Array;
};

function b64(value: unknown): Uint8Array | null {
  if (typeof value !== 'string' || !value.trim()) return null;
  try {
    const bytes = base64ToUint8(value.trim());
    return bytes.length > 0 ? bytes : null;
  } catch {
    return null;
  }
}

/**
 * Accepts the live store shape (`serializeKeypairBundle`) and the vault-bundle
 * field names. Missing any required half → null (fail closed).
 */
export function parseStoredPqBundle(pq: unknown, identityPubs?: { kemPubB64?: string; sigPubB64?: string }): ParsedPqMaterial | null {
  if (!pq || typeof pq !== 'object') return null;
  const o = pq as Record<string, unknown>;
  const signing = (o.signing && typeof o.signing === 'object' ? o.signing : null) as Record<string, unknown> | null;
  const kem = (o.kem && typeof o.kem === 'object' ? o.kem : null) as Record<string, unknown> | null;

  const sigSecret = b64(signing?.secretKey) ?? b64(o.pq_signing_secret_key);
  const kemSec = b64(kem?.secretKey) ?? b64(o.pq_kem_secret_key);
  const sigPub =
    b64(signing?.publicKey) ?? b64(o.pq_signing_public_key) ?? b64(o.sig_public_key) ?? b64(identityPubs?.sigPubB64);
  const kemPub =
    b64(kem?.publicKey) ?? b64(o.pq_kem_public_key) ?? b64(o.kem_public_key) ?? b64(identityPubs?.kemPubB64);

  if (!sigSecret || !kemSec || !sigPub || !kemPub) return null;
  return { sigSecret, kemSec, sigPub, kemPub };
}

export function pqPubsFromIdentity(identity: unknown): { kemPubB64?: string; sigPubB64?: string } {
  const root = identity && typeof identity === 'object' ? (identity as Record<string, unknown>) : {};
  const pq = root.post_quantum && typeof root.post_quantum === 'object' ? (root.post_quantum as Record<string, unknown>) : {};
  const id = root.identity && typeof root.identity === 'object' ? (root.identity as Record<string, unknown>) : {};
  const kemPubB64 =
    (typeof pq.kem_public_key === 'string' && pq.kem_public_key) ||
    (typeof id.pq_kem_public_key === 'string' && id.pq_kem_public_key) ||
    undefined;
  const sigPubB64 =
    (typeof pq.sig_public_key === 'string' && pq.sig_public_key) ||
    (typeof id.pq_sig_public_key === 'string' && id.pq_sig_public_key) ||
    undefined;
  return { kemPubB64, sigPubB64 };
}

export async function unlockArmoredIdentityKey(armoredPrivateKey: string, passphrase: string): Promise<unknown> {
  const locked = await readPrivateKey({ armoredKey: armoredPrivateKey });
  return locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase });
}

export type OwnerMessageKeys = {
  sender: SenderKeys;
  me: MyKeys;
  fingerprint: string;
};

export async function assembleOwnerMessageKeys(
  decryptedIdentityKey: unknown,
  pq: ParsedPqMaterial,
): Promise<OwnerMessageKeys> {
  const { seed: signSeed, signPub } = extractRawSign(decryptedIdentityKey);
  const { encSec, encPub } = await extractRawEnc(decryptedIdentityKey);
  const fingerprint = deriveCanonicalFingerprintHex(signPub, encPub, pq.kemPub, pq.sigPub);
  return {
    fingerprint,
    sender: {
      signSeed,
      sigSecret: pq.sigSecret,
      senderFingerprint: fingerprint,
    },
    me: {
      x25519Sec: encSec,
      mlkem1024Sec: pq.kemSec,
      x25519Pub: encPub,
      mlkem1024Pub: pq.kemPub,
      myFingerprint: fingerprint,
    },
  };
}
