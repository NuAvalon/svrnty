import { generateKey, readKey, createMessage, readMessage } from 'openpgp';
import { randomBytes } from 'crypto';
import { writeFile, readFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { fileURLToPath } from 'url';

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

  constructor(options: IdentityOptions = {}) {
    this.storageDir = options.storageDir || join(homedir(), '.soverentity');
    this.initialize();
  }

  private async initialize(): Promise<void> {
    try {
      await mkdir(this.storageDir, { recursive: true });
    } catch (error: any) {
      if (error.code !== 'EEXIST') throw error;
    }
  }

  async generateIdentity({ name, email }: UserID): Promise<{
    identity: IdentityData;
    fingerprint: string;
  }> {
    try {
      // Generate random passphrase
      const passphrase = randomBytes(32).toString('base64');

      // Generate PGP key pair
      const { privateKey, publicKey } = await generateKey({
        type: 'ecc', // Curve25519
        curve: 'ed25519',
        userIDs: [{ name, email }],
        passphrase,
        format: 'armored'
      });

      // Read the generated key for metadata
      const pubKeyObj = await readKey({ armoredKey: publicKey });
      const fingerprint = pubKeyObj.getFingerprint();

      // Create identity claim
      const identity: IdentityData = {
        version: '0.1.0',
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
          client_version: '0.1.0',
          key_type: 'ED25519',
          key_usage: ['identity', 'signing']
        }
      };

      // Store private key securely
      await this.storeKey(fingerprint, {
        privateKey,
        passphrase,
      });

      // Store identity claim
      await this.storeIdentity(fingerprint, identity);

      return {
        identity,
        fingerprint
      };
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

// Example usage
const main = async (): Promise<void> => {
  const identity = new SoverentityIdentity();
  
  // Generate new identity
  const result = await identity.generateIdentity({
    name: 'Test User',
    email: 'test@example.com'
  });
  
  console.log('Generated identity:', result);
  
  // Verify email
  const verified = await identity.verifyIdentifier({
    fingerprint: result.fingerprint,
    type: 'email',
    value: 'test@example.com'
  });
  
  console.log('Verified identity:', verified);
};

// ES modules way to check if file is being run directly
if (import.meta.url === fileURLToPath(import.meta.url)) {
  main().catch(console.error);
}