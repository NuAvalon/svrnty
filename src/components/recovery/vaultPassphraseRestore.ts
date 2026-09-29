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
import { reconstructCanonicalIdentityForRestore } from '@/lib/identity/fingerprint';
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

  // (a) Reconstruct the CANONICAL fingerprint from recovered key material — derive, don't trust.
  //     Anti-poison for an untrusted .svrnty ("import this vault"): sign+enc come from the UNLOCKED
  //     private key (never a carried public), the PQ pubs are verified against the carried PQ secrets,
  //     and the recomputed canonical fp MUST equal the vault's claimed fp. (public_key↔fingerprint is
  //     additionally enforced inside importVaultContents.) NOT getFingerprint() (the 40-hex path that
  //     rejected canonical backups outright — the pre-canonical restore bug).
  let unlocked;
  try {
    const locked = await readPrivateKey({ armoredKey: classical.privateKey });
    unlocked = locked.isDecrypted()
      ? locked
      : await decryptKey({ privateKey: locked, passphrase: classical.passphrase });
  } catch {
    throw new Error('This backup could not be verified (unreadable identity key) and was not restored.');
  }
  const pqBundle = contents.keys?.pq as
    | { signing?: { secretKey?: string }; kem?: { secretKey?: string } }
    | null
    | undefined;
  // Genuinely-classical (pre-canonical) backup — NO post-quantum material at all (⚡9686 pending).
  if (!pqBundle?.signing?.secretKey || !pqBundle?.kem?.secretKey) {
    throw new Error('This backup uses an older identity format from before post-quantum identities and cannot be restored on this version yet.');
    // TODO(⚡9686): product decision pending on genuinely-classical (40-hex, no-PQ) restore — do NOT add user-facing remediation copy until Peter rules.
  }
  const { fingerprint: derivedFp } = await reconstructCanonicalIdentityForRestore({
    decryptedIdentityKey: unlocked,
    pqKemPublicKeyB64: contents.identity?.post_quantum?.kem_public_key,
    pqSigPublicKeyB64: contents.identity?.post_quantum?.sig_public_key,
    pqKemSecretKeyB64: pqBundle.kem.secretKey,
    pqSigSecretKeyB64: pqBundle.signing.secretKey,
    claimedFingerprint: contents.identity?.identity?.fingerprint || '',
  });

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
