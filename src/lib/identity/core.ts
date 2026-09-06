import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { mintCanonicalFingerprint } from './fingerprint';
import { randomBytes } from 'crypto';
import { writeFile, readFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
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

interface IdentityOptions {
  storageDir?: string;
}

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
  /** Post-quantum public keys (v0.2.0+) */
  post_quantum?: {
    sig_algorithm: 'ML-DSA-87';
    sig_public_key: string;      // base64
    kem_algorithm: 'ML-KEM-1024';
    kem_public_key: string;      // base64
  };
}

interface KeyData {
  privateKey: string;
  passphrase: string;
}

interface ExportData {
  identity: IdentityData;
  exported_at: string;
  private_key?: string;
  passphrase?: string;
}

export class SoverentityIdentity {
  private storageDir: string;
  private initialized: Promise<void>;

  constructor(options: IdentityOptions = {}) {
    this.storageDir = options.storageDir || join(homedir(), '.soverentity');
    this.initialized = this.initialize();
  }

  private async initialize(): Promise<void> {
    await mkdir(this.storageDir, { recursive: true });
  }

  async generateIdentity({ name, email }: UserID, options?: {
    /** Shamir threshold (default: 3) */
    shamirThreshold?: number;
    /** Shamir total shares (default: 5) */
    shamirShares?: number;
  }): Promise<{
    identity: IdentityData;
    fingerprint: string;
    /** Recovery seed phrase — show ONCE, user writes down. Do NOT store. */
    seedPhrase: string;
    /** Shamir shards — distribute to L3+ contacts */
    shards: Shard[];
    /** Key vault — stored locally, encrypted */
    vault: KeyVault;
  }> {
    await this.initialized;
    try {
      // Generate random passphrase for classical key
      const passphrase = randomBytes(32).toString('base64');

      // Generate PGP key pair (classical)
      const { privateKey, publicKey } = await generateKey({
        type: 'ecc', // Curve25519
        curve: 'ed25519',
        userIDs: [{ name, email }],
        passphrase,
        format: 'armored'
      });

      // Generate post-quantum keys BEFORE minting the fingerprint — the identity id
      // commits to all four public keys (sign ‖ enc ‖ kem ‖ sig).
      const pqBundle = generatePQKeypairBundle();

      const locked = await readPrivateKey({ armoredKey: privateKey });
      const unlocked = locked.isDecrypted()
        ? locked
        : await decryptKey({ privateKey: locked, passphrase });
      const { fingerprint } = await mintCanonicalFingerprint({
        decryptedIdentityKey: unlocked,
        kemPublicKey: pqBundle.kem.publicKey,
        sigPublicKey: pqBundle.signing.publicKey,
      });

      // Create identity claim (v0.2.0 with PQ)
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

      // Store classical private key (backward compat)
      await this.storeKey(fingerprint, { privateKey, passphrase });

      // Store PQ private keys
      await this.storePQKeys(fingerprint, pqBundle);

      // Create key vault with Shamir shards for recovery
      const threshold = options?.shamirThreshold ?? 3;
      const totalShares = options?.shamirShares ?? 5;

      const keyBundle: PrivateKeyBundle = {
        classical_private_key: privateKey,
        classical_passphrase: passphrase,
        pq_signing_secret_key: Buffer.from(pqBundle.signing.secretKey).toString('base64'),
        pq_kem_secret_key: Buffer.from(pqBundle.kem.secretKey).toString('base64'),
      };

      const { vault, shards, seedPhrase, masterSecret } = await createKeyVault(
        keyBundle, threshold, totalShares, fingerprint
      );

      // Store vault locally
      await this.storeVault(fingerprint, vault);

      // Zero master secret — it must not persist in memory
      masterSecret.fill(0);

      // Store identity claim
      await this.storeIdentity(fingerprint, identity);

      return { identity, fingerprint, seedPhrase, shards, vault };
    } catch (error) {
      console.error('Failed to generate identity:', error);
      throw error;
    }
  }

  async verifyIdentifier({
    fingerprint,
    type,
    value
  }: {
    fingerprint: string;
    type: string;
    value: string;
  }): Promise<IdentityData> {
    await this.initialized;
    try {
      // Load the identity
      const identity = await this.loadIdentity(fingerprint);
  
      // Verify the key exists
      await this.loadKey(fingerprint);
  
      // Use the stored email from the identity
      const storedEmail = identity.identity.email;
  
      // Update identity verification
      identity.verification = {
        status: 'verified',
        method: type,
        verified_at: new Date().toISOString()
      };
  
      await this.storeIdentity(fingerprint, identity);
      return identity;
    } catch (error) {
      console.error('Failed to verify identifier:', error);
      throw error;
    }
  }
  
  async exportIdentity(fingerprint: string, includePrivate: boolean = false): Promise<ExportData> {
    await this.initialized;
    try {
      const identity = await this.loadIdentity(fingerprint);
      const exportData: ExportData = {
        identity,
        exported_at: new Date().toISOString()
      };

      if (includePrivate) {
        const keys = await this.loadKey(fingerprint);
        exportData.private_key = keys.privateKey;
        exportData.passphrase = keys.passphrase;
      }

      return exportData;
    } catch (error) {
      console.error('Failed to export identity:', error);
      throw error;
    }
  }

  async importIdentity(importData: ExportData): Promise<IdentityData> {
    await this.initialized;
    try {
      const { identity } = importData;
      const fingerprint = identity.identity.fingerprint;

      await this.storeIdentity(fingerprint, identity);

      if (importData.private_key && importData.passphrase) {
        await this.storeKey(fingerprint, {
          privateKey: importData.private_key,
          passphrase: importData.passphrase
        });
      }

      return identity;
    } catch (error) {
      console.error('Failed to import identity:', error);
      throw error;
    }
  }

// Add to the public interface
async loadIdentityData(fingerprint: string): Promise<IdentityData> {
  return this.loadIdentity(fingerprint);
}

  // Private helper methods
  private async storeKey(fingerprint: string, { privateKey, passphrase }: KeyData): Promise<void> {
    const keyPath = join(this.storageDir, `${fingerprint}.key`);
    await writeFile(keyPath, JSON.stringify({ privateKey, passphrase }));
  }

  async loadKey(fingerprint: string): Promise<KeyData> {
    try {
      const keyPath = join(this.storageDir, `${fingerprint}.key`);
      const data = await readFile(keyPath, 'utf8');
      return JSON.parse(data);
    } catch (error) {
      console.error(`Failed to load key for fingerprint ${fingerprint}:`, error);
      throw new Error(`Failed to load key: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async storePQKeys(fingerprint: string, bundle: PQKeypairBundle): Promise<void> {
    const pqKeyPath = join(this.storageDir, `${fingerprint}.pq.key`);
    await writeFile(pqKeyPath, JSON.stringify(serializeKeypairBundle(bundle)));
  }

  async loadPQKeys(fingerprint: string): Promise<PQKeypairBundle | null> {
    try {
      const pqKeyPath = join(this.storageDir, `${fingerprint}.pq.key`);
      const data = await readFile(pqKeyPath, 'utf8');
      return deserializeKeypairBundle(JSON.parse(data));
    } catch {
      // v1 identities don't have PQ keys — return null
      return null;
    }
  }

  private async storeVault(fingerprint: string, vault: KeyVault): Promise<void> {
    const vaultPath = join(this.storageDir, `${fingerprint}.vault`);
    await writeFile(vaultPath, JSON.stringify(vault, null, 2));
  }

  async loadVault(fingerprint: string): Promise<KeyVault | null> {
    try {
      const vaultPath = join(this.storageDir, `${fingerprint}.vault`);
      const data = await readFile(vaultPath, 'utf8');
      return JSON.parse(data);
    } catch {
      return null;
    }
  }

  private async storeIdentity(fingerprint: string, identity: IdentityData): Promise<void> {
    const identityPath = join(this.storageDir, `${fingerprint}.json`);
    await writeFile(identityPath, JSON.stringify(identity, null, 2));
  }

  private async loadIdentity(fingerprint: string): Promise<IdentityData> {
    const identityPath = join(this.storageDir, `${fingerprint}.json`);
    const data = await readFile(identityPath, 'utf8');
    return JSON.parse(data);
  }
}

