// src/lib/sync/contact-update-envelope.ts
// DEMO-CLASSICAL reference E2E envelope for return-channel contact.updates. The sender encrypts a
// SignedContactUpdate to the RECIPIENT's public key (openpgp); the relay stores the armored ciphertext
// OPAQUELY (it cannot read it — custody §4 / I-1); only the recipient's private key decrypts. Reuses
// the existing openpgp identity keys — no new key material.
//
// ⚠ CRYPTO CHOICE: classical openpgp E2E — simplest, reuses the
// identity keys, and honestly "the relay can't read your contacts" (opaque blob, recipient-only decrypt;
// authenticity is the inner SignedContactUpdate). The NAMED UPGRADE is a hybrid-PQ envelope for "PQ on
// the wire". The swap is zero-caller-change AT THE CALLER (the EnvelopeDecryptor is injected) — but the
// hybrid decryptor IMPL must still be WRITTEN: crypto/hybrid.ts has the KEM primitives
// (hybridEncapsulate / hybridDecapsulate / deriveHybridSecret) + signing, NOT an encrypt-to-recipient
// wrapper — so the upgrade = write [encapsulate → derive → AES-GCM the payload → package] + the matching
// decryptor, then swap the injection. Not a one-line flag-flip; that's the artifact for the separate
// "PQ on the wire" claim graduation.

import { createMessage, encrypt, readKey, readPrivateKey, decryptKey, readMessage, decrypt } from 'openpgp';
import type { SignedContactUpdate } from '@/lib/trust/contact-update';
import type { EnvelopeDecryptor } from './consume-mailbox';
import { sealLivingBookHybrid } from '@/lib/crypto/living-book-sleeve';

/**
 * The contact-update inner-wire type-gate, exported as a `WireParser` for the SINGLE dual-read chokepoint
 * (src/lib/sync/hybrid-dual-read.ts: makeHybridOpener(openEnv, parseContactUpdateWire)). The contact-update
 * path is the consume CATCH-ALL, so there is NO inner type-tag to check here — shape (envelope.fingerprint)
 * is checked downstream by consumeOne; this returns the parsed object as-is (null only on non-JSON),
 * reproducing the EXACT current opener behaviour so no-cross-swallow is byte-identical.
 */
export function parseContactUpdateWire(innerUtf8: string): SignedContactUpdate | null {
  try {
    return JSON.parse(innerUtf8) as SignedContactUpdate;
  } catch {
    return null;
  }
}

/**
 * Sender side: encrypt a signed contact.update to the recipient → opaque armored blob. HYBRID (HNDL) when
 * the recipient's ML-KEM-1024 pubkey is supplied (wraps the ALREADY-SIGNED SignedContactUpdate with the
 * reject-classical mailbox envelope); classical OpenPGP otherwise (back-compat/tests — the SEND composer
 * buildContactUpdateDeposits fail-closed-SKIPS a recipient with no pq_kem, so production never downgrades).
 */
export async function encryptContactUpdateTo(
  signed: SignedContactUpdate,
  recipientPublicKeyArmored: string,
  recipientPqKemB64?: string,
): Promise<string> {
  if (recipientPqKemB64) {
    return sealLivingBookHybrid(new TextEncoder().encode(JSON.stringify(signed)), recipientPublicKeyArmored, recipientPqKemB64);
  }
  const encryptionKeys = await readKey({ armoredKey: recipientPublicKeyArmored });
  const message = await createMessage({ text: JSON.stringify(signed) });
  return (await encrypt({ message, encryptionKeys })) as string;
}

/**
 * Recipient side: an {@link EnvelopeDecryptor} bound to the owner's private key. Returns null on ANY
 * failure (not-for-us / corrupt / wrong key / not-JSON) so the caller drops it silently (I-1/I-2).
 * Classical-ONLY: the PQ-hybrid dual-read now lives in the SINGLE chokepoint (dualReadOpener over
 * makeHybridOpener(openEnv, parseContactUpdateWire)) composed by the consume deps builders — this opener
 * is its classical fallback. The contact-update path is the consume catch-all, so shape
 * (envelope.fingerprint) is checked by consumeOne — mirrored here by returning the parsed object as-is.
 */
export function openpgpEnvelopeDecryptor(
  recipientPrivateKeyArmored: string,
  passphrase: string,
): EnvelopeDecryptor {
  return async (blob: string): Promise<SignedContactUpdate | null> => {
    try {
      const locked = await readPrivateKey({ armoredKey: recipientPrivateKeyArmored });
      const decryptionKeys = await decryptKey({ privateKey: locked, passphrase });
      const message = await readMessage({ armoredMessage: blob });
      const { data } = await decrypt({ message, decryptionKeys });
      const text = typeof data === 'string' ? data : await streamToText(data);
      return parseContactUpdateWire(text);
    } catch {
      return null;
    }
  };
}

async function streamToText(data: unknown): Promise<string> {
  const maybe = data as { getReader?: () => ReadableStreamDefaultReader };
  if (typeof maybe?.getReader !== 'function') return String(data);
  const reader = maybe.getReader();
  const dec = new TextDecoder();
  let out = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    out += typeof value === 'string' ? value : dec.decode(value as BufferSource, { stream: true });
  }
  return out;
}
