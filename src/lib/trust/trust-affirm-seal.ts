// src/lib/trust/trust-affirm-seal.ts
// OpenPGP envelope for mutual-trust affirmations (increment 2 of the mutual-trust wire).
// EXACT MIRROR of messaging/seal.ts (sealNoteTo / noteOpenpgpDecryptor): a trust-affirmation rides the
// SAME classical OpenPGP envelope as contact.updates + joiner-responses + over-wire notes, so the relay
// stays an opaque dead-drop (content-blind) and the mailbox's inbound types are told apart ONLY by
// WHICH type-checked decryptor returns non-null (the consume-dispatch discriminator). A trust-affirm
// blob decrypts via THIS decryptor; the note/contact-update decryptors return null on it (type mismatch),
// and this one returns null on them — the 4-way no-cross-swallow property (see consume-mailbox.ts).
//
// NOT a Double Ratchet. Hybrid-PQ wrapper is the named upgrade, not this file's job (same posture as
// seal.ts): the AUTHN is already canonical-capable (trust-affirm.ts binds PQ pubkeys via the fp-match);
// only the confidentiality envelope here is classical for v0, swappable with zero caller change.

import { createMessage, encrypt, readKey, readPrivateKey, decryptKey, readMessage, decrypt } from 'openpgp';
import { TRUST_AFFIRM_WIRE_TYPE, type TrustAffirmWireV0 } from './trust-affirm';

/**
 * Seal a signed trust-affirmation to the recipient's OpenPGP public key. The affirmation MUST already
 * carry its {public_key, signature} (signTrustAffirm) — sealing is confidentiality only; authentication
 * is the sender signature the consumer re-checks. Refuses a non-affirm wire type (fail-loud) so a
 * mis-routed object can never be sealed under the wrong discriminator.
 */
export async function sealTrustAffirmTo(
  affirm: TrustAffirmWireV0,
  recipientPublicKeyArmored: string,
): Promise<string> {
  if (affirm.type !== TRUST_AFFIRM_WIRE_TYPE) {
    throw new Error('sealTrustAffirmTo: refusing non-affirm wire type');
  }
  const encryptionKeys = await readKey({ armoredKey: recipientPublicKeyArmored });
  const message = await createMessage({ text: JSON.stringify(affirm) });
  return (await encrypt({ message, encryptionKeys })) as string;
}

/**
 * Decrypt an opaque relay blob → TrustAffirmWireV0, or null on any failure (I-1 silent drop) OR on a
 * type/shape mismatch (→ the consume path falls through to the next decryptor). The `type` gate is the
 * discriminator: a note / joiner / contact-update blob decrypts fine but fails `type !==
 * TRUST_AFFIRM_WIRE_TYPE` → null → never eaten as an affirmation. Does NOT authenticate — that is
 * verifyTrustAffirmSender's job in acceptTrustAffirm (sign-before-admit, mirroring the note path).
 */
export function trustAffirmOpenpgpDecryptor(
  recipientPrivateKeyArmored: string,
  passphrase: string,
): (blob: string) => Promise<TrustAffirmWireV0 | null> {
  return async (blob: string): Promise<TrustAffirmWireV0 | null> => {
    try {
      const locked = await readPrivateKey({ armoredKey: recipientPrivateKeyArmored });
      const decryptionKeys = await decryptKey({ privateKey: locked, passphrase });
      const message = await readMessage({ armoredMessage: blob });
      const { data } = await decrypt({ message, decryptionKeys });
      const text = typeof data === 'string' ? data : await streamToText(data);
      const parsed = JSON.parse(text) as TrustAffirmWireV0;
      if (parsed?.type !== TRUST_AFFIRM_WIRE_TYPE) return null;
      // Minimal shape gate (mirrors noteOpenpgpDecryptor): the fields the consume seam binds/reads MUST
      // be present + the right primitive type, or it is not a well-formed affirmation → null (fall through).
      if (typeof parsed.from_fingerprint !== 'string') return null;
      if (typeof parsed.to_fingerprint !== 'string') return null;
      if (typeof parsed.trusts !== 'boolean') return null;
      return parsed;
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
