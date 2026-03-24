// src/lib/identity/browser-identity.ts
// Browser-compatible identity manager — uses IndexedDB via client-store
// Drop-in replacement for SoverentityIdentity (core.ts) without fs/homedir

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
  type SovereignBackup,
} from './client-store';

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
    sig_algorithm: 'ML-DSA-65';
    sig_public_key: string;
    kem_algorithm: 'ML-KEM-768';
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
  async generateIdentity({ name, email }: UserID, options?: {
    shamirThreshold?: number;
    shamirShares?: number;
  }): Promise<{
    identity: IdentityData;
    fingerprint: string;
    seedPhrase: string;
    shards: Shard[];
    vault: KeyVault;
  }> {
    // Generate random passphrase
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
        key_type: 'ED25519+ML-DSA-65+ML-KEM-768',
        key_usage: ['identity', 'signing', 'key-encapsulation']
      },
      post_quantum: {
        sig_algorithm: 'ML-DSA-65',
        sig_public_key: publicKeyToBase64(pqBundle.signing.publicKey),
        kem_algorithm: 'ML-KEM-768',
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
      pq_signing_secret_key: btoa(String.fromCharCode(...pqBundle.signing.secretKey)),
      pq_kem_secret_key: btoa(String.fromCharCode(...pqBundle.kem.secretKey)),
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
}

// Singleton for convenience
let _instance: BrowserIdentity | null = null;
export function getBrowserIdentity(): BrowserIdentity {
  if (!_instance) _instance = new BrowserIdentity();
  return _instance;
}
