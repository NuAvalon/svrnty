import { generateKey, readKey, createMessage, readMessage } from 'openpgp';
import { randomBytes } from 'crypto';
import { writeFile, readFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { fileURLToPath } from 'url';
import { decryptKey } from 'openpgp';
import { sign } from 'openpgp';


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
  claims?: IdentityClaim[];  // Add this line
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

// Add this with other interfaces at the top of core.ts
interface IdentityClaim {
  type: 'email' | 'phone';
  value: string;  // Hashed value
  verified: boolean;
  proof: {
    type: 'pgp_signed_otp';
    timestamp: string;
    signature: string;  // PGP signature of proof
  };
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
        identity: {
          ...identity, // ✅ Ensures correct structure
        },
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

  async generateVerificationChallenge(
    fingerprint: string,
    claimType: 'email' | 'phone',
    value: string
  ): Promise<{
    challenge: string;
    otp: string;
    expires: Date;
  }> {
    try {
      // Load the identity's private key
      const keys = await this.loadKey(fingerprint);
      
      // Parse the private key
      const privateKey = await readKey({ armoredKey: keys.privateKey });

      // Decrypt the private key
      const decryptedPrivateKey = await decryptKey({
        privateKey,
        passphrase: keys.passphrase
      });
            
      // Generate OTP
      const otp = randomBytes(3).toString('hex').toUpperCase();
      
      // Create challenge data
      const challengeData = {
        fingerprint,
        claimType,
        value,
        otp,
        timestamp: new Date().toISOString(),
        expires: new Date(Date.now() + 15 * 60 * 1000) // 15 minutes
      };
  
      // Sign challenge with identity's key
      const message = await createMessage({
        text: JSON.stringify(challengeData)
      });
  
      // Use the parsed private key for signing

      const signedChallenge = await sign({
        message,
        signingKeys: decryptedPrivateKey, // ✅ Correct way to pass the key
        format: 'armored' // ✅ Ensures the output is in proper PGP format
      });
      
      console.log("Signed Challenge:", signedChallenge); // Debugging
      
      return {
        challenge: signedChallenge, // ✅ Ensure it's properly armored
        otp,
        expires: challengeData.expires
      };
      
    } catch (error) {
      console.error('Failed to generate challenge:', error);
      throw error;
    }
  }

  // Should be updated to:
  async verifySignedOTP(
    fingerprint: string,
    claimType: 'email' | 'phone',
    value: string,
    otp: string,
    signedChallenge: string
  ): Promise<IdentityClaim> {
    try {
      console.log('Starting verification with:', { fingerprint, claimType, value, otp });
      console.log('Signed challenge:', signedChallenge);
  
      const identity = await this.loadIdentity(fingerprint);
      const publicKey = await readKey({ armoredKey: identity.identity.public_key });
      
      // Parse the signed message
      const message = await readMessage({ armoredMessage: signedChallenge });
      console.log('Parsed message:', message);
  
      // Get the message content directly
      const messageContent = await message.getText();
      console.log('Message content:', messageContent);
  
      if (!messageContent) {
        throw new Error('No message content found');
      }
  
      const verificationResult = await message.verify([publicKey]);
      if (!verificationResult.length) {
        throw new Error('Invalid challenge signature');
      }
  
      const challengeData = JSON.parse(messageContent);
      console.log('Challenge data:', challengeData);
  
      // Verify OTP matches
      if (challengeData.otp !== otp) {
        throw new Error('Invalid OTP');
      }
  
      // Create claim
      const claim: IdentityClaim = {
        type: claimType,
        value,
        verified: true,
        proof: {
          type: 'pgp_signed_otp',
          timestamp: new Date().toISOString(),
          signature: signedChallenge
        }
      };
  
      // Update identity with new claim
      identity.claims = identity.claims || [];
      identity.claims.push(claim);
      identity.verification.status = 'verified';
      identity.verification.method = claimType;
      identity.verification.verified_at = new Date().toISOString();
      
      await this.storeIdentity(fingerprint, identity);
  
      return claim;
    } catch (error) {
      console.error('Failed to verify OTP:', error);
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

  private async loadKey(fingerprint: string): Promise<KeyData> {
    const keyPath = join(this.storageDir, `${fingerprint}.key`);
    const data = await readFile(keyPath, 'utf8');
    return JSON.parse(data);
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

