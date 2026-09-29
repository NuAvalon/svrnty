// Thin wrapper around fleet encryptToContact / decryptFromContact.
// Maps every throw/null onto FIXED non-leaky strings — never echo crypto errors (secrets).

import {
  decryptFromContact,
  encryptToContact,
  type ContactKeys,
  type DecryptedMessage,
  type MyKeys,
  type SenderKeys,
} from '@/lib/crypto/contact-message';
import { ENCDEC_COPY } from './encrypt-decrypt-copy';

export type EncryptResult =
  | { ok: true; armored: string }
  | { ok: false; error: string };

export type DecryptResult =
  | { ok: true; result: DecryptedMessage }
  | { ok: false; error: string };

export async function encryptMessageToContact(
  message: string,
  contact: ContactKeys,
  sender: SenderKeys,
): Promise<EncryptResult> {
  try {
    const armored = await encryptToContact(message, contact, sender);
    if (!armored || typeof armored !== 'string') return { ok: false, error: ENCDEC_COPY.encryptFailed };
    return { ok: true, armored };
  } catch (e) {
    const msg = e instanceof Error ? e.message : '';
    if (/anti-poison|does not match/i.test(msg)) return { ok: false, error: ENCDEC_COPY.encryptPoisoned };
    return { ok: false, error: ENCDEC_COPY.encryptFailed };
  }
}

export async function decryptMessageFromContact(
  armored: string,
  me: MyKeys,
  senderCard?: ContactKeys,
): Promise<DecryptResult> {
  try {
    const opened = await decryptFromContact(armored, me, senderCard);
    if (!opened) return { ok: false, error: ENCDEC_COPY.decryptFailed };
    return { ok: true, result: opened };
  } catch {
    return { ok: false, error: ENCDEC_COPY.decryptFailed };
  }
}
