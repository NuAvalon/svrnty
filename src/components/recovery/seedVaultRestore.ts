// Thin UI adapter for v4 passphrase-free vault recovery.
// Crypto stays in fleet modules — this only orchestrates the documented 2-call seam:
//   extractRecoveryVault(data) → recoverFromSeedPhrase(kv, phrase)
// then persists the recovered classical identity into IndexedDB.
//
// Contacts / trust graph / settings live in the passphrase-encrypted BODY and are
// NOT recovered on this path (by format design). Copy must say so honestly.

import { readPrivateKey, decryptKey } from 'openpgp';
import { extractRecoveryVault } from '@/lib/sync/vault';
import { recoverFromSeedPhrase } from '@/lib/crypto/recovery';
import {
  storeIdentity,
  storeKey,
  storeVault,
  setActiveFingerprint,
} from '@/lib/identity/client-store';
import { reconstructCanonicalIdentityForRestore } from '@/lib/identity/fingerprint';

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
): Promise<SeedVaultRestoreResult> {
  const phrase = seedPhrase.trim();
  if (!phrase) {
    throw new Error('Enter your recovery code.');
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
    // extractRecoveryVault's KeyVault type narrows the seam; the runtime object (a recovery.ts
    // KeyVault) carries identity_fingerprint (the canonical id stored at genesis createKeyVault).
    claimedFingerprint: (kv as { identity_fingerprint?: string }).identity_fingerprint ?? '',
  });

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
    metadata: {
      client_version: '0.2.0',
      key_type: 'ED25519+ML-DSA-87+ML-KEM-1024',
      key_usage: ['identity', 'signing', 'key-encapsulation'],
      restored_via: 'seed-phrase-v4' as const,
    },
  };

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
