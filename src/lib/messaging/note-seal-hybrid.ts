// src/lib/messaging/note-seal-hybrid.ts
/**
 * PQ-hybrid note seal — the REPLACE-forward encrypt path for notes (Flint #141587 / #141627).
 *
 * New notes are sealed with the audited hybrid core (crypto/hybrid-seal.ts): a classical X25519 leg
 * OR-combined with an ML-KEM-1024 leg into one AES-256-GCM key. The classical leg is Flint-pinned B —
 * Ed25519→Montgomery (mutual-trust.ts:63 construction), sender-EPHEMERAL × recipient-STATIC so it
 * carries forward secrecy on the classical side. The reader (noteDecryptor) still accepts legacy
 * OpenPGP notes (seal.ts) so nothing already sent stops decrypting.
 *
 * INVARIANT (Flint #141627, mandatory): the raw Ed25519→Montgomery DH secret is a SHARED primitive
 * (note-seal, rendezvous, and any future consumer derive from the same birational map). Therefore
 * EVERY KDF consuming it MUST carry a distinct length-prefixed domain in its info. note-seal binds
 * "svrnty:note-seal:v1" (hybrid-seal.deriveHybridSealKey info) + the recipient fp; rendezvous binds
 * "svrnty-tr-rendezvous-v1". A future consumer must add its own domain or it can derive a colliding key.
 * (Note: here the classical leg is EPHEMERAL×static, so its raw secret is not even equal to rendezvous's
 * static×static S_pair precursor — the domain-sep is belt-and-suspenders, kept as the standing rule.)
 */
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { base64ToUint8 } from '@/lib/crypto/pq';
import { encapsulate, decapsulate } from '@/lib/crypto/pq';
import {
  sealHybridWithMaterials,
  openHybridWithMaterials,
  type HybridSealPackage,
} from '@/lib/crypto/hybrid-seal';
import { canonicalPubsFromArmoredPublicKey } from '@/lib/identity/fingerprint';
import { extractRawSign } from '@/lib/identity/raw-sign';
import { NOTE_WIRE_TYPE } from './domains';
import type { NoteWireV0 } from './types';

/** Domain-separation tag for the note seal — distinct from beacon + mailbox-env (C1 discipline). */
export const NOTE_SEAL_DOMAIN = 'svrnty:note-seal:v1';

/** Recipient public-key material for a hybrid note seal (sourced from their card / contact record). */
export interface HybridNoteRecipient {
  /** OpenPGP armored public key — its Ed25519 signing key becomes the X25519 static leg (toMontgomery). */
  publicKeyArmored: string;
  /** ML-KEM-1024 encapsulation public key (base64) — the card's pq_kem_public_key. */
  pqKemPublicKeyB64: string;
  /** ML-DSA-87 signing public key (base64) — needed to recompute the canonical recipient fp binding. */
  pqSigPublicKeyB64: string;
}

/** Recipient secret-key material to OPEN a hybrid note (held only by the unlocked owner). */
export interface HybridNoteSecrets {
  /** openpgp DECRYPTED private key (await decryptKey(...)) — extractRawSign → raw Ed25519 seed. */
  decryptedIdentityKey: unknown;
  /** ML-KEM-1024 secret key bytes. */
  pqKemSecretKey: Uint8Array;
  /** My canonical identity fingerprint — the package's recip_fp must equal this. */
  myFingerprint: string;
}

/** Cheap structural check that a wire string is a hybrid note package (vs legacy OpenPGP armor). */
export function isHybridNoteWire(wire: string): boolean {
  const s = wire.trimStart();
  if (s[0] !== '{') return false; // OpenPGP armor starts with '-----BEGIN PGP MESSAGE-----'
  try {
    const o = JSON.parse(wire) as Partial<HybridSealPackage>;
    return !!o && typeof o === 'object' && o.domain === NOTE_SEAL_DOMAIN && typeof o.v === 'number';
  } catch {
    return false;
  }
}

/**
 * SEAL a note to a recipient identity with the PQ-hybrid core. Returns the wire string (JSON package).
 * Classical leg: ephemeral X25519 × recipient Ed25519→Montgomery (forward-secret). PQ leg: ML-KEM-1024.
 */
export async function sealNoteHybrid(
  note: NoteWireV0,
  recipient: HybridNoteRecipient,
  senderFingerprint: string,
): Promise<string> {
  if (note.type !== NOTE_WIRE_TYPE) throw new Error('sealNoteHybrid: refusing non-note wire type');

  // Recipient canonical pubs: signPub (→ X25519 static leg), kemPub (ML-KEM), fingerprint (recip_fp).
  const pubs = await canonicalPubsFromArmoredPublicKey(
    recipient.publicKeyArmored,
    recipient.pqKemPublicKeyB64,
    recipient.pqSigPublicKeyB64,
  );

  const recipStaticX = ed25519.utils.toMontgomery(pubs.signPub); // recipient static X25519 public key
  const epkSk = x25519.utils.randomSecretKey();
  const epk = x25519.getPublicKey(epkSk);
  const ssX = x25519.getSharedSecret(epkSk, recipStaticX); // ephemeral × static (@noble throws on all-zero → fail-closed)
  const { ciphertext: kemCt, sharedSecret: ssPq } = encapsulate(pubs.kemPub); // ML-KEM-1024
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  const pkg = await sealHybridWithMaterials({
    plaintext: new TextEncoder().encode(JSON.stringify(note)),
    ssX,
    ssPq,
    epk,
    kemCt,
    domain: NOTE_SEAL_DOMAIN,
    recipFp: pubs.fingerprint,
    senderFp: senderFingerprint,
    nonce,
  });
  return JSON.stringify(pkg);
}

/**
 * Decryptor for hybrid note packages → NoteWireV0, or null on ANY failure (I-1 silent drop, mirrors
 * noteOpenpgpDecryptor). Recomputes ss_x25519 (my Ed25519→Montgomery × pkg.epk) + ss_mlkem (decap).
 */
export function hybridNoteDecryptor(
  secrets: HybridNoteSecrets,
): (wire: string) => Promise<NoteWireV0 | null> {
  return async (wire: string): Promise<NoteWireV0 | null> => {
    try {
      const pkg = JSON.parse(wire) as HybridSealPackage;
      if (pkg?.domain !== NOTE_SEAL_DOMAIN) return null;

      const { seed } = extractRawSign(secrets.decryptedIdentityKey);
      const myStaticX = ed25519.utils.toMontgomerySecret(seed);
      const epk = base64ToUint8(pkg.epk);
      const ssX = x25519.getSharedSecret(myStaticX, epk);
      const ssPq = decapsulate(base64ToUint8(pkg.kem_ct), secrets.pqKemSecretKey);

      const pt = await openHybridWithMaterials({
        pkg,
        ssX,
        ssPq,
        myFp: secrets.myFingerprint,
        expectDomain: NOTE_SEAL_DOMAIN,
      });
      if (!pt) return null;

      const parsed = JSON.parse(new TextDecoder().decode(pt)) as NoteWireV0;
      if (parsed?.type !== NOTE_WIRE_TYPE) return null;
      if (typeof parsed.body !== 'string' || typeof parsed.from_fingerprint !== 'string') return null;
      return parsed;
    } catch {
      return null;
    }
  };
}

/**
 * Reader dispatch for the REPLACE-forward migration: hybrid packages → hybrid open; legacy OpenPGP
 * armor → the OpenPGP decryptor. Both return null on failure (silent drop). Compose with
 * noteOpenpgpDecryptor(...) from ./seal for `legacy`.
 */
export function noteDecryptor(
  legacy: (blob: string) => Promise<NoteWireV0 | null>,
  hybrid: (wire: string) => Promise<NoteWireV0 | null>,
): (blob: string) => Promise<NoteWireV0 | null> {
  return async (blob: string): Promise<NoteWireV0 | null> => {
    return isHybridNoteWire(blob) ? hybrid(blob) : legacy(blob);
  };
}
