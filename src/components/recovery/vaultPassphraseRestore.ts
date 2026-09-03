// Thin restore adapter for the .svrnty "Open Vault" passphrase path — the sibling of
// seedVaultRestore.ts for the passphrase (not recovery-code) flow.
//
// unpackVault has already AES-GCM-authenticated `contents` under the passphrase. This
// adapter then, mirroring the recovery-code path's derive-don't-trust discipline:
//   (a) binds the vault's PRIVATE key to its claimed fingerprint so an untrusted .svrnty
//       ("import this vault file") can't poison the identity/keys stores with a key that
//       doesn't match its identity,
//   (b) initialises the session key from the passphrase so persisted keys are encrypted
//       at rest exactly as genesis stores them (at-rest equivalence,
//       "restore ≡ genesis at rest"), then
//   (c) persists the whole vault via client-store.importVaultContents (which enforces the
//       public-key↔fingerprint binding and routes contacts through addContact).
//
// Fixes the data-safety launch-blocker: before this, the passphrase restore only
// hydrated in-memory React state and the identity was LOST on reload.

import { readPrivateKey, decryptKey } from 'openpgp';
import type { VaultContents } from '@/lib/sync/vault';
import { normalizeFingerprintHex } from '@/lib/identity/fingerprint';
import {
  initSessionKey,
  isSessionUnlocked,
  importVaultContents,
} from '@/lib/identity/client-store';

/**
 * Persist an unlocked .svrnty vault so the restored identity survives reload.
 * @param contents        VaultContents from unpackVault (already passphrase-authenticated).
 * @param vaultPassphrase the passphrase that opened the vault = the daily-unlock passphrase.
 * @returns the DERIVED fingerprint the identity was stored under.
 */
export async function restoreIdentityFromVault(
  contents: VaultContents,
  vaultPassphrase: string,
): Promise<string> {
  const classical = contents.keys?.classical;
  if (!classical?.privateKey) {
    throw new Error('This backup is missing its identity key and cannot be restored.');
  }

  // (a) Bind the PRIVATE key to the identity fingerprint — derive, don't trust.
  //     (The public-key↔fingerprint binding is enforced inside importVaultContents.)
  let derivedFp: string;
  try {
    const locked = await readPrivateKey({ armoredKey: classical.privateKey });
    const unlocked = locked.isDecrypted()
      ? locked
      : await decryptKey({ privateKey: locked, passphrase: classical.passphrase });
    derivedFp = normalizeFingerprintHex(unlocked.toPublic().getFingerprint());
  } catch {
    throw new Error('This backup could not be verified (unreadable identity key) and was not restored.');
  }
  const claimedFp = normalizeFingerprintHex(contents.identity?.identity?.fingerprint || '');
  if (derivedFp.length !== 40 || derivedFp !== claimedFp) {
    throw new Error('This backup failed an integrity check (its key does not match its identity) and was not restored.');
  }

  // (b) At-rest equivalence: derive the session key from the passphrase BEFORE persisting
  //     so keys/pq_keys/vault are encrypted at rest. The passphrase IS the daily-unlock
  //     passphrase and initSessionKey persists the salt, so the next reload re-derives the
  //     same key and can decrypt. Don't clobber an already-unlocked session.
  if (!isSessionUnlocked()) {
    await initSessionKey(vaultPassphrase);
  }

  // (c) Persist identity + keys + pq + recovery-vault + contacts under the DERIVED fp.
  return importVaultContents(contents, derivedFp);
}
