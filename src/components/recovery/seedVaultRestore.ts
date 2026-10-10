// Thin UI adapter for v4 passphrase-free vault recovery.
// Crypto stays in fleet modules — this only orchestrates the documented 2-call seam:
//   extractRecoveryVault(data) → recoverFromSeedPhrase(kv, phrase)
// then persists the recovered classical identity into IndexedDB.
//
// Contacts / trust graph / settings live in the passphrase-encrypted BODY and are
// NOT recovered on this path (by format design). Copy must say so honestly.

import { readPrivateKey, decryptKey } from 'openpgp';
import { extractRecoveryVault } from '@/lib/sync/vault';
import { recoverFromSeedPhrase, seedPhraseToMasterSecret } from '@/lib/crypto/recovery';
import {
  storeIdentity,
  storeKey,
  storeVault,
  setActiveFingerprint,
  initSessionKey,
} from '@/lib/identity/client-store';
import {
  reconstructCanonicalIdentityForRestore,
  deriveNextAuthorityCommitment,
} from '@/lib/identity/fingerprint';

export type SeedVaultRestoreResult = {
  identity: {
    version: string;
    created_at: string;
    identity: {
      name: string;
      email: string;
      fingerprint: string;
      public_key: string;
    };
    verification: {
      status: 'unverified';
      method: null;
      verified_at: null;
    };
    metadata: {
      client_version: string;
      key_type: string;
      key_usage: string[];
      restored_via: 'seed-phrase-v4';
    };
  };
  fingerprint: string;
  /** PQ secrets came back from the KeyVault but public halves are not on this seam yet. */
  pqSecretsRecovered: boolean;
};

/**
 * Passphrase-free restore from a .svrnty v4 file + recovery phrase.
 * Calls only fleet crypto: extractRecoveryVault + recoverFromSeedPhrase.
 */
export async function restoreIdentityFromSeedVault(
  data: ArrayBuffer,
  seedPhrase: string,
  newPassphrase: string,
): Promise<SeedVaultRestoreResult> {
  const phrase = seedPhrase.trim();
  if (!phrase) {
    throw new Error('Enter your recovery code.');
  }
  // 3a-pure (Blocker-C): recovery must establish at-rest protection BEFORE keys touch disk.
  // The client-store writes are fail-closed, so a device passphrase is required here — there is
  // never a plaintext-at-rest window, not even transiently (Archie invariant #133842).
  if (!newPassphrase || newPassphrase.length < 12) {
    throw new Error('Set a device passphrase (at least 12 characters) to protect your recovered keys at rest.');
  }

  // Fleet seam — do not reimplement.
  const kv = extractRecoveryVault(data);
  const bundle = await recoverFromSeedPhrase(kv, phrase);

  // Classical PGP key carries fingerprint + userIDs (name/email) — derive, don't invent.
  const locked = await readPrivateKey({ armoredKey: bundle.classical_private_key });
  const unlocked = locked.isDecrypted()
    ? locked
    : await decryptKey({
        privateKey: locked,
        passphrase: bundle.classical_passphrase,
      });
  const publicKeyObj = unlocked.toPublic();
  const publicKey = publicKeyObj.armor();
  const primary = await unlocked.getPrimaryUser();
  const name = primary.user?.userID?.name?.trim() || 'Recovered identity';
  const email = primary.user?.userID?.email?.trim() || '';

  // Genuinely-classical (pre-canonical) backup — NO post-quantum material at all. Product decision
  // on classical restorability is pending (⚡9686), so fail honestly without presuming a remedy.
  if (!bundle.pq_kem_secret_key || !bundle.pq_signing_secret_key) {
    throw new Error('This backup uses an older identity format from before post-quantum identities and cannot be restored on this version yet.');
    // TODO(⚡9686): product decision pending on genuinely-classical (40-hex, no-PQ) restore — do NOT add user-facing remediation copy until Peter rules.
  }

  // Reconstruct the CANONICAL fingerprint from the recovered keys: sign+enc from the UNLOCKED
  // private key, PQ pubs (stored at genesis) verified against the recovered PQ secrets, and the
  // result checked against the vault's stored canonical id (kv.identity_fingerprint). A pre-fix
  // vault (PQ secrets but no stored PQ pubs) throws /re-export/ from the fn. NOT getFingerprint()
  // (which yields the 40-hex OpenPGP fp — the pre-canonical bug that downgraded restored identities).
  const { fingerprint, post_quantum } = await reconstructCanonicalIdentityForRestore({
    decryptedIdentityKey: unlocked,
    pqKemPublicKeyB64: bundle.pq_kem_public_key,
    pqSigPublicKeyB64: bundle.pq_signing_public_key,
    pqKemSecretKeyB64: bundle.pq_kem_secret_key,
    pqSigSecretKeyB64: bundle.pq_signing_secret_key,
    // The claim comes from INSIDE the seed-decrypted bundle (recoverFromSeedPhrase -> decryptVault),
    // NOT the KeyVault outer — the KeyVault never carried identity_fingerprint (that read was always
    // '' -> the #110 seed-restore integrity-fail). It rides inside the AES-GCM bundle so the .svrnty
    // stays identity-blind, and it's authenticated -> a corrupted bundle fails the recompute check below.
    claimedFingerprint: bundle.identity_fingerprint ?? '',
  });

  // T2.4 (Apollo's grounded delta): re-derive the pre-rotation authority pin from the recovered
  // seed so a seed-restored identity can verify its own rotations (mint sets this at genesis; a
  // restore that omits it = the T2.4 gap). masterSecret isn't exposed by recoverFromSeedPhrase, so
  // re-derive it from the phrase — deterministic, the same value recoverFromSeedPhrase uses
  // internally. Mirror mint exactly (browser-identity.ts:204): epoch=1.
  const _ms = seedPhraseToMasterSecret(phrase);
  const next_authority_commitment = deriveNextAuthorityCommitment(_ms, 1);
  _ms.fill(0); // zero immediately (mint's ORDER INVARIANT: derive before zero)

  const identity = {
    version: '1.0',
    created_at: new Date().toISOString(),
    identity: {
      name,
      email,
      fingerprint,
      public_key: publicKey,
    },
    verification: {
      status: 'unverified' as const,
      method: null,
      verified_at: null,
    },
    post_quantum,
    // T2.4: genesis-equivalent authority pin so rotations verify (see re-derive above).
    // durable.epoch=0 + commitment epoch=1 is correct for genesis-epoch identities (all alpha).
    next_authority_commitment,
    durable: { fingerprint, epoch: 0, next_authority_commitment },
    metadata: {
      client_version: '0.2.0',
      key_type: 'ED25519+ML-DSA-87+ML-KEM-1024',
      key_usage: ['identity', 'signing', 'key-encapsulation'],
      restored_via: 'seed-phrase-v4' as const,
    },
  };

  // 3a-pure: derive + persist the passphrase-derived session key BEFORE writing any key material,
  // so storeKey/storeVault encrypt at rest. The stores now fail-closed if this is missing.
  await initSessionKey(newPassphrase);

  await storeKey(fingerprint, bundle.classical_private_key, bundle.classical_passphrase);
  await storeVault(fingerprint, kv);
  await storeIdentity(fingerprint, identity);
  await setActiveFingerprint(fingerprint);

  // PQ: PrivateKeyBundle returns secrets only; serializeKeypairBundle needs public halves.
  // Do not invent a PQ layout here — fleet seam. Flagged in recovery README.
  const pqSecretsRecovered = !!(
    bundle.pq_signing_secret_key && bundle.pq_kem_secret_key
  );

  return { identity, fingerprint, pqSecretsRecovered };
}
