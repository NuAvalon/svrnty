// src/lib/identity/browser-identity.ts
// Browser-compatible identity manager — uses IndexedDB via client-store
// Drop-in replacement for SoverentityIdentity (core.ts) without fs/homedir

// Chunked btoa — avoids stack overflow for large Uint8Arrays (>~8KB spread limit)
function uint8ToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

import { generateKey, readKey } from 'openpgp';
import {
  generatePQKeypairBundle,
  serializeKeypairBundle,
  deserializeKeypairBundle,
  publicKeyToBase64,
  type PQKeypairBundle,
} from '@/lib/crypto/pq';
import {
  createKeyVault,
  type KeyVault,
  type Shard,
  type PrivateKeyBundle,
} from '@/lib/crypto/recovery';
import {
  storeIdentity,
  loadIdentity,
  storeKey,
  loadKey,
  storePQKeys,
  loadPQKeys,
  storeVault,
  loadVault,
  setActiveFingerprint,
  getActiveFingerprint,
  hasIdentity,
  exportAll,
  importAll,
  initSessionKey,
  isSessionUnlocked,
  lockSession,
  type SovereignBackup,
} from './client-store';
import {
  encryptBackup,
  decryptBackup,
  isEncryptedSvrntyFile,
  type EncryptedSvrntyFile,
} from '@/lib/crypto/encrypted-backup';

interface UserID {
  name: string;
  email: string;
}

interface IdentityData {
  version: string;
  created_at: string;
  identity: {
    name: string;
    email: string;
    fingerprint: string;
    public_key: string;
  };
  verification: {
    status: 'unverified' | 'verified';
    method: string | null;
    verified_at: string | null;
    proof?: string;
  };
  metadata: {
    client_version: string;
    key_type: string;
    key_usage: string[];
  };
  post_quantum?: {
    sig_algorithm: 'ML-DSA-87';
    sig_public_key: string;
    kem_algorithm: 'ML-KEM-1024';
    kem_public_key: string;
  };
}

interface ExportData {
  identity: IdentityData;
  exported_at: string;
  private_key?: string;
  passphrase?: string;
}

export class BrowserIdentity {
  /**
   * Generate a new sovereign identity.
   * If unlockPassphrase is provided, private keys are encrypted at rest in IndexedDB.
   * Without it, keys are stored unencrypted (legacy behavior).
   */
  async generateIdentity({ name, email }: UserID, options?: {
    shamirThreshold?: number;
    shamirShares?: number;
    unlockPassphrase?: string;
  }): Promise<{
    identity: IdentityData;
    fingerprint: string;
    seedPhrase: string;
    shards: Shard[];
    vault: KeyVault;
  }> {
    // Initialize session encryption if passphrase provided
    if (options?.unlockPassphrase) {
      await initSessionKey(options.unlockPassphrase);
    }

    // Generate random passphrase for PGP key (internal, not user-facing)
    const passphraseBytes = new Uint8Array(32);
    crypto.getRandomValues(passphraseBytes);
    const passphrase = btoa(String.fromCharCode(...passphraseBytes));

    // Generate PGP key pair (classical)
    const { privateKey, publicKey } = await generateKey({
      type: 'ecc',
      curve: 'ed25519',
      userIDs: [{ name, email }],
      passphrase,
      format: 'armored'
    });

    const pubKeyObj = await readKey({ armoredKey: publicKey });
    const fingerprint = pubKeyObj.getFingerprint();

    // Generate post-quantum keys
    const pqBundle = generatePQKeypairBundle();

    const identity: IdentityData = {
      version: '0.2.0',
      created_at: new Date().toISOString(),
      identity: {
        name,
        email,
        fingerprint,
        public_key: publicKey,
      },
      verification: {
        status: 'unverified',
        method: null,
        verified_at: null
      },
      metadata: {
        client_version: '0.2.0',
        key_type: 'ED25519+ML-DSA-87+ML-KEM-1024',
        key_usage: ['identity', 'signing', 'key-encapsulation']
      },
      post_quantum: {
        sig_algorithm: 'ML-DSA-87',
        sig_public_key: publicKeyToBase64(pqBundle.signing.publicKey),
        kem_algorithm: 'ML-KEM-1024',
        kem_public_key: publicKeyToBase64(pqBundle.kem.publicKey),
      },
    };

    // Store everything in IndexedDB
    await storeKey(fingerprint, privateKey, passphrase);
    await storePQKeys(fingerprint, serializeKeypairBundle(pqBundle));

    // Create key vault with Shamir shards
    const threshold = options?.shamirThreshold ?? 3;
    const totalShares = options?.shamirShares ?? 5;

    const keyBundle: PrivateKeyBundle = {
      classical_private_key: privateKey,
      classical_passphrase: passphrase,
      pq_signing_secret_key: uint8ToBase64(pqBundle.signing.secretKey),
      pq_kem_secret_key: uint8ToBase64(pqBundle.kem.secretKey),
    };

    const { vault, shards, seedPhrase, masterSecret } = await createKeyVault(
      keyBundle, threshold, totalShares, fingerprint
    );

    // Store vault in IndexedDB
    await storeVault(fingerprint, vault);

    // Zero master secret
    masterSecret.fill(0);

    // Store identity
    await storeIdentity(fingerprint, identity);
    await setActiveFingerprint(fingerprint);

    return { identity, fingerprint, seedPhrase, shards, vault };
  }

  async loadIdentityData(fingerprint: string): Promise<IdentityData | null> {
    return loadIdentity(fingerprint);
  }

  async getActiveIdentity(): Promise<IdentityData | null> {
    const fp = await getActiveFingerprint();
    if (!fp) return null;
    return loadIdentity(fp);
  }

  async getActiveFingerprint(): Promise<string | null> {
    return getActiveFingerprint();
  }

  async hasIdentity(): Promise<boolean> {
    return hasIdentity();
  }

  async verifyIdentifier({ fingerprint, type }: {
    fingerprint: string;
    type: string;
    value: string;
  }): Promise<IdentityData> {
    const identity = await loadIdentity(fingerprint);
    if (!identity) throw new Error('Identity not found');

    identity.verification = {
      status: 'verified',
      method: type,
      verified_at: new Date().toISOString()
    };

    await storeIdentity(fingerprint, identity);
    return identity;
  }

  async exportIdentity(fingerprint: string, includePrivate: boolean = false): Promise<ExportData> {
    const identity = await loadIdentity(fingerprint);
    if (!identity) throw new Error('Identity not found');

    const exportData: ExportData = {
      identity,
      exported_at: new Date().toISOString()
    };

    if (includePrivate) {
      const keys = await loadKey(fingerprint);
      if (keys) {
        exportData.private_key = keys.privateKey;
        exportData.passphrase = keys.passphrase;
      }
    }

    return exportData;
  }

  async importIdentity(importData: ExportData): Promise<IdentityData> {
    const { identity } = importData;
    const fingerprint = identity.identity.fingerprint;

    await storeIdentity(fingerprint, identity);

    if (importData.private_key && importData.passphrase) {
      await storeKey(fingerprint, importData.private_key, importData.passphrase);
    }

    await setActiveFingerprint(fingerprint);
    return identity;
  }

  // ── Session key management (F1: encrypt keys at rest) ──────────

  /** Unlock the session — derive encryption key from passphrase. */
  async unlockSession(passphrase: string): Promise<void> {
    return initSessionKey(passphrase);
  }

  /** Lock the session — clear encryption key from memory. */
  lockSession(): void {
    lockSession();
  }

  /** Check if the session is unlocked. */
  isUnlocked(): boolean {
    return isSessionUnlocked();
  }

  async loadKeyData(fingerprint: string): Promise<{ privateKey: string; passphrase: string } | null> {
    return loadKey(fingerprint);
  }

  async loadPQKeyData(fingerprint: string): Promise<PQKeypairBundle | null> {
    const serialized = await loadPQKeys(fingerprint);
    if (!serialized) return null;
    return deserializeKeypairBundle(serialized);
  }

  async loadVaultData(fingerprint: string): Promise<KeyVault | null> {
    return loadVault(fingerprint);
  }

  // Full sovereign backup (identity + keys + contacts)
  async exportSovereignBackup(fingerprint: string, includePrivateKeys: boolean = true): Promise<SovereignBackup> {
    return exportAll(fingerprint, includePrivateKeys);
  }

  async importSovereignBackup(backup: SovereignBackup): Promise<string> {
    return importAll(backup);
  }

  // ── Encrypted .svrnty file operations ────────────────────────────

  /**
   * Export identity as an Argon2id-encrypted .svrnty file.
   * This is the RECOMMENDED export path — private keys are never in plaintext.
   */
  async exportEncryptedBackup(
    fingerprint: string,
    passphrase: string,
  ): Promise<EncryptedSvrntyFile> {
    const backup = await exportAll(fingerprint, true);
    return encryptBackup(backup, passphrase);
  }

  /**
   * Import from an encrypted .svrnty file.
   */
  async importEncryptedBackup(
    file: EncryptedSvrntyFile,
    passphrase: string,
  ): Promise<string> {
    const backup = await decryptBackup(file, passphrase);
    return importAll(backup);
  }

  /**
   * Import from either encrypted or plaintext backup (auto-detect).
   */
  async importFromFile(fileContents: string, passphrase?: string): Promise<string> {
    const parsed = JSON.parse(fileContents);

    if (isEncryptedSvrntyFile(parsed)) {
      if (!passphrase) {
        throw new Error('This .svrnty file is encrypted — passphrase required');
      }
      return this.importEncryptedBackup(parsed, passphrase);
    }

    // Legacy plaintext backup
    return importAll(parsed as SovereignBackup);
  }
}

// Singleton for convenience
let _instance: BrowserIdentity | null = null;
export function getBrowserIdentity(): BrowserIdentity {
  if (!_instance) _instance = new BrowserIdentity();
  return _instance;
}
