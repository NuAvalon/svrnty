// src/lib/trust/discoverable-consent-seal.ts
// OpenPGP envelope for Carol's discoverable-consent (trust-PSI increment #2, TRANSPORT half).
// EXACT MIRROR of trust-affirm-seal.ts / messaging/seal.ts: a discoverable-consent rides the SAME
// classical OpenPGP envelope as contact.updates + joiner-responses + over-wire notes + trust-affirms,
// so the relay stays an opaque content-blind dead-drop and the mailbox's inbound types are told apart
// ONLY by WHICH type-checked decryptor returns non-null (the consume-dispatch discriminator). A consent
// blob decrypts via THIS decryptor; the note/affirm/contact-update decryptors return null on it (type
// mismatch), and this one returns null on them — the no-cross-swallow property (see consume-mailbox.ts).
//
// AUTH is NOT this file's job and NOT per-peer: the consent is self-authenticating — Carol signs her
// GLOBAL willingness ONCE (discoverable-consent.ts signDiscoverableConsent), and applyDiscoverableConsent
// re-verifies that signature against Carol's STORED pubkeys regardless of how the blob arrived (Flint
// #172716: transport-agnostic auth). So sealing is confidentiality only; the SAME signed object is sealed
// to each contact on publish (fan-out). Hybrid-PQ confidentiality is the named upgrade, not this file's job.

import { createMessage, encrypt, readKey, readPrivateKey, decryptKey, readMessage, decrypt } from 'openpgp';
import type { SignedDiscoverableConsent } from './discoverable-consent';

/** Wire discriminator for a discoverable-consent inside a decrypted mailbox blob (not an HTTP route). */
export const DISCOVERABLE_CONSENT_WIRE_TYPE = 'svrnty-discoverable-consent-v0';

/** The over-wire shape: the self-authenticating signed consent + a type tag for the consume discriminator. */
export interface DiscoverableConsentWireV0 extends SignedDiscoverableConsent {
  type: typeof DISCOVERABLE_CONSENT_WIRE_TYPE;
}

/**
 * Seal a signed discoverable-consent to the recipient's OpenPGP public key. The consent MUST already carry
 * its signature (signDiscoverableConsent) — sealing is confidentiality only; authenticity is Carol's
 * envelope signature the consumer re-checks in applyDiscoverableConsent. Refuses a non-consent wire type
 * (fail-loud) so a mis-routed object can never be sealed under the wrong discriminator.
 */
export async function sealDiscoverableConsentTo(
  wire: DiscoverableConsentWireV0,
  recipientPublicKeyArmored: string,
): Promise<string> {
  if (wire.type !== DISCOVERABLE_CONSENT_WIRE_TYPE) {
    throw new Error('sealDiscoverableConsentTo: refusing non-consent wire type');
  }
  const encryptionKeys = await readKey({ armoredKey: recipientPublicKeyArmored });
  const message = await createMessage({ text: JSON.stringify(wire) });
  return (await encrypt({ message, encryptionKeys })) as string;
}

/**
 * Decrypt an opaque relay blob → DiscoverableConsentWireV0, or null on any failure (silent drop) OR on a
 * type/shape mismatch (→ the consume path falls through to the next decryptor). The `type` gate is the
 * discriminator: a note / affirm / joiner / contact-update blob decrypts fine but fails `type !==
 * DISCOVERABLE_CONSENT_WIRE_TYPE` → null → never eaten as a consent. Does NOT authenticate — that is
 * applyDiscoverableConsent's job (verify-before-set against the subject's stored pubkeys).
 */
export function discoverableConsentOpenpgpDecryptor(
  recipientPrivateKeyArmored: string,
  passphrase: string,
): (blob: string) => Promise<DiscoverableConsentWireV0 | null> {
  return async (blob: string): Promise<DiscoverableConsentWireV0 | null> => {
    try {
      const locked = await readPrivateKey({ armoredKey: recipientPrivateKeyArmored });
      const decryptionKeys = await decryptKey({ privateKey: locked, passphrase });
      const message = await readMessage({ armoredMessage: blob });
      const { data } = await decrypt({ message, decryptionKeys });
      const text = typeof data === 'string' ? data : await streamToText(data);
      const parsed = JSON.parse(text) as DiscoverableConsentWireV0;
      if (parsed?.type !== DISCOVERABLE_CONSENT_WIRE_TYPE) return null;
      // Minimal shape gate (mirrors trustAffirmOpenpgpDecryptor): the fields applyDiscoverableConsent
      // reads/binds MUST be present + the right primitive type, or it is not a well-formed consent → null
      // (fall through). Crypto verification itself stays in applyDiscoverableConsent (fail-closed).
      if (typeof parsed.subject_fp !== 'string') return null;
      if (typeof parsed.epoch !== 'number') return null;
      if (typeof parsed.discoverable !== 'boolean') return null;
      if (typeof parsed.scope_tag !== 'number') return null;
      if (typeof parsed.scope_value !== 'string') return null;
      if (!parsed.sig || typeof parsed.sig !== 'object') return null;
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
