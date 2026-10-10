// src/lib/crypto/living-book-receive.ts
// Owner-side receive helper for the L7 living-book hybrid sleeve (Flint).
//
// Derives THIS owner's mailbox OPEN-material — the X25519 enc secret from the unlocked identity key + the
// ML-KEM-1024 secret from the vault PQ bundle + the mailbox fp a sender sealed to — so the ONE dual-read
// chokepoint (hybrid-dual-read.ts dualReadOpener) can open a PQ-hybrid living-book deposit at BOTH the FE
// (live-book-poll.buildConsumeDeps) AND the headless (headless-client.buildHeadlessConsumeDeps) consume deps.
// Lives in ONE shared place so neither consumer re-implements it (the headless path forgot the dual-read
// once already — the silent-loss gate; one helper, one chokepoint).
//
// FAIL-SOFT TODAY: a classical identity (no PQ material) → undefined → the chokepoint composes classical-only
// openers (correct — senders never hybrid-seal to a non-kem identity). ⚠ The LOUD-not-silent invariant for a
// kem-ADVERTISING identity that cannot load its secret (→ inbound hybrid silently lost) is enforced at the
// CALL SITE (buildConsumeDeps / buildHeadlessConsumeDeps), not here: this derivation only reports
// present-or-undefined; the caller decides advertise-but-cannot-open ⇒ LOUD.

import { readPrivateKey, decryptKey } from 'openpgp';
import { extractRawEnc } from '@/lib/identity/raw-sign';
import { base64ToUint8 } from './pq';
import { deriveMailboxFp } from './mailbox-envelope';
import type { LivingBookHybridSecrets } from './living-book-sleeve';

export async function deriveOwnerHybridSecrets(
  privateKeyArmored: string,
  passphrase: string,
  kemPublicKeyB64?: string,
  kemSecretKeyB64?: string,
): Promise<LivingBookHybridSecrets | undefined> {
  if (!kemPublicKeyB64 || !kemSecretKeyB64) return undefined; // classical identity → classical-only openers
  try {
    const locked = await readPrivateKey({ armoredKey: privateKeyArmored });
    const decrypted = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase });
    const { encSec, encPub } = await extractRawEnc(decrypted); // x25519 enc secret+pub (fail-closed invariant)
    const mlkem1024Sec = base64ToUint8(kemSecretKeyB64);
    const mlkem1024Pub = base64ToUint8(kemPublicKeyB64);
    const myFp = deriveMailboxFp(encPub, mlkem1024Pub); // MUST equal what a sender sealed to (same pubs)
    return { secrets: { x25519Sec: encSec, mlkem1024Sec }, myFp };
  } catch {
    return undefined; // never block the poll on a PQ-key read — degrade to classical openers
  }
}
