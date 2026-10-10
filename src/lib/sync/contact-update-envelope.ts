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

/** Sender side: encrypt a signed contact.update to the recipient's public key → opaque armored blob. */
export async function encryptContactUpdateTo(
  signed: SignedContactUpdate,
  recipientPublicKeyArmored: string,
): Promise<string> {
  const encryptionKeys = await readKey({ armoredKey: recipientPublicKeyArmored });
  const message = await createMessage({ text: JSON.stringify(signed) });
  return (await encrypt({ message, encryptionKeys })) as string;
}

/**
 * Recipient side: an {@link EnvelopeDecryptor} bound to the owner's private key. Returns null on ANY
 * failure (not-for-us / corrupt / wrong key / not-JSON) so the caller drops it silently (I-1/I-2).
 */
export function openpgpEnvelopeDecryptor(recipientPrivateKeyArmored: string, passphrase: string): EnvelopeDecryptor {
  return async (blob: string): Promise<SignedContactUpdate | null> => {
    try {
      const locked = await readPrivateKey({ armoredKey: recipientPrivateKeyArmored });
      const decryptionKeys = await decryptKey({ privateKey: locked, passphrase });
      const message = await readMessage({ armoredMessage: blob });
      const { data } = await decrypt({ message, decryptionKeys });
      const text = typeof data === 'string' ? data : await streamToText(data);
      return JSON.parse(text) as SignedContactUpdate;
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
