// src/lib/sync/hybrid-test-fixture.ts
// TEST-ONLY fixture (not imported by app code): mint a recipient that has BOTH the classical OpenPGP key and the
// ML-KEM-1024 material, so the send-side tests can exercise the S14 PQ-hybrid seal (fail-closed without pq_kem) and
// open it the way the real consume path does (dualReadOpener: hybrid first, classical fallback).
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { deriveOwnerHybridSecrets } from '@/lib/crypto/living-book-receive';
import { openMailboxEnvelope } from '@/lib/crypto/mailbox-envelope';
import type { LivingBookHybridSecrets } from '@/lib/crypto/living-book-sleeve';
import { uint8ToBase64 } from '@/lib/crypto/pq';
import { dualReadOpener, makeHybridOpener, type WireParser } from './hybrid-dual-read';

export interface HybridRecipient {
  fingerprint: string;
  publicKeyArmored: string;
  privateKeyArmored: string;
  passphrase: string;
  pqKemPublicKey: string;
  pqSigPublicKey: string;
  /** ML-DSA-87 signing secret (raw bytes) of the minted identity, so a test can sign hybrid (classical + PQ). */
  pqSigSecretKey: Uint8Array;
  /** base64 ML-KEM-1024 secret, as the vault PQ bundle hands it to the FE poll (lazy derivation input). */
  kemSecretKeyB64: string;
  hybrid: LivingBookHybridSecrets;
}

export async function mintHybridRecipient(): Promise<HybridRecipient> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  const privateKeyArmored = a.secret_material.classicalPrivateKey;
  const passphrase = a.secret_material.classicalKpass;
  const pqKemPublicKey: string = id.pq_kem_public_key;
  const kemSecretKeyB64 = uint8ToBase64(a.secret_material.mlkem1024Sec);
  const hybrid = await deriveOwnerHybridSecrets(privateKeyArmored, passphrase, pqKemPublicKey, kemSecretKeyB64);
  if (!hybrid) throw new Error('fixture: could not derive hybrid secrets');
  return {
    fingerprint: id.fingerprint, publicKeyArmored: id.public_key, privateKeyArmored, passphrase,
    pqKemPublicKey, pqSigPublicKey: id.pq_sig_public_key, pqSigSecretKey: a.secret_material.mldsa87Secret, kemSecretKeyB64, hybrid,
  };
}

/** The consume-side opener for one deposit type: hybrid first (my secrets), classical fallback. */
export function openerFor<T>(
  r: HybridRecipient,
  parseWire: WireParser<T>,
  classical: (blob: string) => Promise<T | null>,
): (blob: string) => Promise<T | null> {
  return dualReadOpener(
    makeHybridOpener((pkg) => openMailboxEnvelope(pkg, r.hybrid.secrets, r.hybrid.myFp), parseWire),
    classical,
  );
}
