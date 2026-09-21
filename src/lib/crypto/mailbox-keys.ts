// src/lib/crypto/mailbox-keys.ts
/**
 * Mailbox keypair — the per-pair receiver keys behind a PQ-hybrid mailbox (KB#90104 item 1, Flint (b)).
 *
 * (b) = a RANDOM per-pair keypair (NOT derived from any pairwise/identity secret). Generated with the
 * library-native CSPRNG keygen — X25519 (@noble) + ML-KEM-1024 (pq.ts) — with NO seed and NO derivation.
 * Rationale (Flint ruling #141663): the ML-KEM-1024 seeded-keygen entry point (d‖z, 64B, FIPS 203) is not
 * reliably exposed across JS libs, so a derived key is a byte-portability landmine in a launch-critical
 * primitive; native random keygen sidesteps it. Blast radius: a receiver-only secret (2 mailboxes/pair) →
 * compromise of one device reads only ONE direction, never both.
 *
 * The mailbox is content-addressed: mailbox_fp = SHA256(x25519_pub[32] ‖ mlkem1024_ek[1568]) — reused
 * AS-IS from mailbox-envelope.ts (KB#90104 item 2). The secret keys NEVER leave the device (vault-held);
 * only the public keys + mailbox_fp are registered/published.
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { generateKEMKeypair } from './pq.js';
import {
  deriveMailboxFp,
  type MailboxPublicKeys,
  type MailboxSecretKeys,
} from './mailbox-envelope.js';

const X25519_LEN = 32;
const KEM_PUB_LEN = 1568; // ML-KEM-1024 encapsulation key (ek)
const KEM_SEC_LEN = 3168; // ML-KEM-1024 decapsulation key (dk)

/** A full mailbox keypair. Secret halves are vault-held and never transmitted. */
export interface MailboxKeypair {
  x25519Pub: Uint8Array; // 32
  x25519Sec: Uint8Array; // 32
  mlkem1024Pub: Uint8Array; // 1568 (ek)
  mlkem1024Sec: Uint8Array; // 3168 (dk)
}

/** Generate a fresh random mailbox keypair (native CSPRNG; no seed, no derivation). */
export function generateMailboxKeypair(): MailboxKeypair {
  const x25519Sec = x25519.utils.randomSecretKey(); // 32B CSPRNG
  const x25519Pub = x25519.getPublicKey(x25519Sec); // 32B
  const { publicKey: mlkem1024Pub, secretKey: mlkem1024Sec } = generateKEMKeypair(); // 1568 / 3168
  return { x25519Pub, x25519Sec, mlkem1024Pub, mlkem1024Sec };
}

/** The mailbox's content-address fingerprint (64 lowercase hex). */
export function mailboxFpOf(kp: Pick<MailboxKeypair, 'x25519Pub' | 'mlkem1024Pub'>): string {
  return deriveMailboxFp(kp.x25519Pub, kp.mlkem1024Pub);
}

/** Public-key view for sealing (sealToMailbox). */
export function toPublicKeys(kp: MailboxKeypair): MailboxPublicKeys {
  return { x25519Pub: kp.x25519Pub, mlkem1024Pub: kp.mlkem1024Pub };
}

/** Secret-key view for opening (openMailboxEnvelope). */
export function toSecretKeys(kp: MailboxKeypair): MailboxSecretKeys {
  return { x25519Sec: kp.x25519Sec, mlkem1024Sec: kp.mlkem1024Sec };
}

/** Serialize a keypair to hex for vault storage. Secrets included — persist ONLY inside the vault. */
export function serializeMailboxKeypair(kp: MailboxKeypair): {
  x25519_pk: string;
  x25519_sk: string;
  mlkem1024_pk: string;
  mlkem1024_sk: string;
} {
  return {
    x25519_pk: bytesToHex(kp.x25519Pub),
    x25519_sk: bytesToHex(kp.x25519Sec),
    mlkem1024_pk: bytesToHex(kp.mlkem1024Pub),
    mlkem1024_sk: bytesToHex(kp.mlkem1024Sec),
  };
}

/** Inverse of serializeMailboxKeypair, with strict length validation (throws on malformed). */
export function deserializeMailboxKeypair(data: {
  x25519_pk: string;
  x25519_sk: string;
  mlkem1024_pk: string;
  mlkem1024_sk: string;
}): MailboxKeypair {
  const kp: MailboxKeypair = {
    x25519Pub: hexToBytes(data.x25519_pk),
    x25519Sec: hexToBytes(data.x25519_sk),
    mlkem1024Pub: hexToBytes(data.mlkem1024_pk),
    mlkem1024Sec: hexToBytes(data.mlkem1024_sk),
  };
  if (kp.x25519Pub.length !== X25519_LEN || kp.x25519Sec.length !== X25519_LEN)
    throw new Error('bad x25519 key length');
  if (kp.mlkem1024Pub.length !== KEM_PUB_LEN) throw new Error(`bad ml-kem pub length ${kp.mlkem1024Pub.length}`);
  if (kp.mlkem1024Sec.length !== KEM_SEC_LEN) throw new Error(`bad ml-kem sec length ${kp.mlkem1024Sec.length}`);
  return kp;
}
