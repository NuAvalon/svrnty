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
    throw new Error('Enter your recovery phrase.');
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
  const fingerprint = publicKeyObj.getFingerprint().toUpperCase();
  const publicKey = publicKeyObj.armor();
  const primary = await unlocked.getPrimaryUser();
  const name = primary.user?.userID?.name?.trim() || 'Recovered identity';
  const email = primary.user?.userID?.email?.trim() || '';

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
    metadata: {
      client_version: '0.2.0',
      key_type: 'ED25519',
      key_usage: ['identity', 'signing'],
      restored_via: 'seed-phrase-v4' as const,
    },
  };

  await storeKey(fingerprint, bundle.classical_private_key, bundle.classical_passphrase);
  await storeVault(fingerprint, kv);
  await storeIdentity(fingerprint, identity);
  await setActiveFingerprint(fingerprint);

  // PQ: PrivateKeyBundle returns secrets only; serializeKeypairBundle needs public halves.
  // Do not invent a PQ layout here — fleet seam (Flint). Flagged in recovery README.
  const pqSecretsRecovered = !!(
    bundle.pq_signing_secret_key && bundle.pq_kem_secret_key
  );

  return { identity, fingerprint, pqSecretsRecovered };
}
