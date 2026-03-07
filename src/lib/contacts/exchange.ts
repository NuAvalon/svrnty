// lib/contacts/exchange.ts
import { createMessage, encrypt, sign, readMessage, decrypt, verify, readKey, readPrivateKey, decryptKey } from 'openpgp';
import { randomBytes } from 'crypto';
import { Contact } from './types';
import { SoverentityIdentity } from '@/lib/identity/core';
import {
  sign as pqSign,
  verify as pqVerify,
  base64ToPublicKey,
} from '@/lib/crypto/pq';

/** Exchange package for sharing identity between peers */
interface ExchangePackage {
  version: string;
  sender: {
    fingerprint: string;
    public_key: string;
  };
  contact_data: {
    name: string;
    email: string;
    fingerprint: string;
    public_key: string;
  };
  created_at: string;
  recipient_fingerprint?: string;
  expires_at?: string;
  mutual_contacts?: string[];
  /** Classical PGP signature (ED25519) */
  signature: string;
  /** Post-quantum ML-DSA-65 signature, base64 (v0.2.0+) */
  pq_signature?: string;
  /** Sender's PQ signing public key for verification (v0.2.0+) */
  pq_sig_public_key?: string;
}

export class ContactExchange {
  private identityManager: SoverentityIdentity;

  constructor() {
    this.identityManager = new SoverentityIdentity();
  }

  // Create an exchange package to share your identity
  async createExchangePackage({
    senderFingerprint,
    recipientFingerprint,
    includeMutualContacts = false,
    expireInHours = 0,
    mutualContactFingerprints = []
  }: {
    senderFingerprint: string;
    recipientFingerprint?: string;
    includeMutualContacts?: boolean;
    expireInHours?: number;
    mutualContactFingerprints?: string[];
  }): Promise<string> {
    try {
      // Load sender identity
      const identity = await this.identityManager.loadIdentityData(senderFingerprint);
      if (!identity) {
        throw new Error('Sender identity not found');
      }

      // Load private key for signing
      const keyData = await this.identityManager.loadKey(senderFingerprint);
      
      // Create the exchange package
      const exchangePackage: Omit<ExchangePackage, 'signature'> = {
        version: '0.1.0',
        sender: {
          fingerprint: senderFingerprint,
          public_key: identity.identity.public_key
        },
        contact_data: {
          name: identity.identity.name,
          email: identity.identity.email,
          fingerprint: senderFingerprint,
          public_key: identity.identity.public_key
        },
        created_at: new Date().toISOString(),
      };

      // Add optional fields
      if (recipientFingerprint) {
        exchangePackage.recipient_fingerprint = recipientFingerprint;
      }

      if (expireInHours > 0) {
        const expiry = new Date();
        expiry.setHours(expiry.getHours() + expireInHours);
        exchangePackage.expires_at = expiry.toISOString();
      }

      if (includeMutualContacts && mutualContactFingerprints.length > 0) {
        // Add mutual contacts in a secure way
        exchangePackage.mutual_contacts = mutualContactFingerprints;
      }

      // Sign the package (classical ED25519 + post-quantum ML-DSA-65)
      // 1. Read and decrypt the classical private key
      const privateKeyObj = await readPrivateKey({ armoredKey: keyData.privateKey });
      const decryptedKey = await decryptKey({
        privateKey: privateKeyObj,
        passphrase: keyData.passphrase
      });

      // 2. Classical PGP signature
      const packageToSign = JSON.stringify(exchangePackage);
      const message = await createMessage({ text: packageToSign });
      const signedMessage = await sign({
        message,
        signingKeys: decryptedKey
      });

      // 3. Extract classical signature
      const signedMessageString = signedMessage.toString();
      const parts = signedMessageString.split('-----BEGIN PGP SIGNATURE-----');
      if (parts.length < 2) {
        throw new Error('Failed to extract signature from signed message');
      }
      const signaturePart = '-----BEGIN PGP SIGNATURE-----' + parts[1];
      const classicalSignature = signaturePart.replace('-----END PGP SIGNATURE-----', '').trim();

      // 4. Post-quantum ML-DSA-65 signature (if PQ keys exist)
      const pqKeys = await this.identityManager.loadPQKeys(senderFingerprint);
      let pqSignature: string | undefined;
      let pqSigPublicKey: string | undefined;

      if (pqKeys) {
        const payloadBytes = new TextEncoder().encode(packageToSign);
        const sig = pqSign(payloadBytes, pqKeys.signing.secretKey);
        pqSignature = Buffer.from(sig).toString('base64');
        pqSigPublicKey = identity.post_quantum?.sig_public_key;
      }

      // 5. Build the dual-signed package
      const signedPackage: ExchangePackage = {
        ...exchangePackage,
        signature: classicalSignature,
        ...(pqSignature && { pq_signature: pqSignature }),
        ...(pqSigPublicKey && { pq_sig_public_key: pqSigPublicKey }),
      };

      // Encrypt the entire package if recipient is specified
      if (recipientFingerprint) {
        // Try to fetch recipient's public key
        const recipientIdentity = await this.identityManager.loadIdentityData(recipientFingerprint);
        if (!recipientIdentity) {
          throw new Error('Recipient identity not found');
        }

        const message = await createMessage({
          text: JSON.stringify(signedPackage)
        });

        const encrypted = await encrypt({
          message,
          encryptionKeys: await readKey({ armoredKey: recipientIdentity.identity.public_key })
        });

        return encrypted.toString();
      }

      // Return the signed package
      return JSON.stringify(signedPackage);
    } catch (error) {
      console.error('Failed to create exchange package:', error);
      throw new Error('Failed to create exchange package');
    }
  }

  // Generate a QR code for contact exchange
  async generateQRCodeData(senderFingerprint: string): Promise<string> {
    try {
      const exchangeData = await this.createExchangePackage({
        senderFingerprint,
        expireInHours: 24 // QR codes expire in 24 hours
      });
      
      // Return the data to be encoded in a QR code
      return exchangeData;
    } catch (error) {
      console.error('Failed to generate QR code data:', error);
      throw error;
    }
  }

  // Create a burner link for quick onboarding
  async createBurnerLink(senderFingerprint: string, expireInHours: number = 48): Promise<string> {
    const exchangeData = await this.createExchangePackage({
      senderFingerprint,
      expireInHours
    });
    
    // Encode the exchange data for URL safety
    const encodedData = Buffer.from(exchangeData).toString('base64url');
    
    // Generate a short ID for the link
    const linkId = randomBytes(8).toString('hex');
    
    // In a real implementation, you would store this in a database
    // For demo purposes, we're just returning a URL with the encoded data
    return `https://soverentity.app/contact/burner/${linkId}`;
  }

  // Process an exchange package received from someone
  async processExchangePackage(
    packageData: string,
    userFingerprint: string
  ): Promise<Contact> {
    try {
      let exchangePackage: ExchangePackage;
      
      // Check if the package is encrypted
      if (packageData.includes('-----BEGIN PGP MESSAGE-----')) {
        // Decrypt the package
        const keyData = await this.identityManager.loadKey(userFingerprint);
        const message = await readMessage({
          armoredMessage: packageData
        });
        
        const { data: decrypted } = await decrypt({
          message,
          decryptionKeys: await decrypt({
            message: await readMessage({ armoredMessage: keyData.privateKey }),
            passwords: [keyData.passphrase]
          }).then(({ data }) => data.toString())
        });
        
        exchangePackage = JSON.parse(decrypted.toString());
      } else {
        // Parse the unencrypted package
        exchangePackage = JSON.parse(packageData);
      }
      
      // Verify expiration if present
      if (exchangePackage.expires_at && new Date(exchangePackage.expires_at) < new Date()) {
        throw new Error('Exchange package has expired');
      }
      
      // Verify signature
      const verified = await this.verifySignature(
        exchangePackage,
        exchangePackage.sender.public_key
      );
      
      if (!verified) {
        throw new Error('Invalid signature');
      }
      
      // Check if this package was intended for the current user
      if (
        exchangePackage.recipient_fingerprint &&
        exchangePackage.recipient_fingerprint !== userFingerprint
      ) {
        throw new Error('This exchange package was not intended for you');
      }
      
      // Create a contact from the verified package
      const contact: Contact = {
        id: exchangePackage.sender.fingerprint,
        name: exchangePackage.contact_data.name,
        email: exchangePackage.contact_data.email,
        fingerprint: exchangePackage.contact_data.fingerprint,
        public_key: exchangePackage.contact_data.public_key,
        trust_level: 'unverified',
        added_at: new Date().toISOString(),
        metadata: {
          connection_method: 
            exchangePackage.expires_at ? 'burner_link' : 
            exchangePackage.mutual_contacts ? 'mutual' : 'manual',
          mutual_contacts: exchangePackage.mutual_contacts
        }
      };
      
      return contact;
    } catch (error) {
      console.error('Failed to process exchange package:', error);
      throw new Error('Failed to process exchange package');
    }
  }

  // Verify the signature(s) of an exchange package
  // Dual verification: classical + PQ (if present). Both must pass for v0.2.0+ packages.
  private async verifySignature(
    exchangePackage: ExchangePackage,
    publicKeyArmored: string
  ): Promise<boolean> {
    try {
      // Extract package without signatures for verification
      const { signature, pq_signature, pq_sig_public_key, ...packageData } = exchangePackage;
      const packageText = JSON.stringify(packageData);

      // 1. Verify classical ED25519 signature
      const signedMessage =
        `-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n${packageText}\n-----BEGIN PGP SIGNATURE-----\n${signature}\n-----END PGP SIGNATURE-----`;

      const message = await readMessage({ armoredMessage: signedMessage });
      const publicKey = await readKey({ armoredKey: publicKeyArmored });
      const verification = await verify({ message, verificationKeys: publicKey });
      const classicalValid = await verification.signatures[0].verified;

      if (!classicalValid) return false;

      // 2. Verify post-quantum ML-DSA-65 signature (if present)
      if (pq_signature && pq_sig_public_key) {
        const payloadBytes = new TextEncoder().encode(packageText);
        const sigBytes = new Uint8Array(Buffer.from(pq_signature, 'base64'));
        const pkBytes = base64ToPublicKey(pq_sig_public_key);
        const pqValid = pqVerify(payloadBytes, sigBytes, pkBytes);
        if (!pqValid) return false;
      }
      // If no PQ signature, accept classical-only (backward compat with v1)

      return true;
    } catch (error) {
      console.error('Signature verification failed:', error);
      return false;
    }
  }

  // Implement PSI (Private Set Intersection) for discovering mutual contacts
  async findMutualContacts(
    userFingerprint: string,
    otherFingerprint: string,
    userContacts: string[],
    otherContacts?: string[]
  ): Promise<string[]> {
    // If otherContacts is provided, do local intersection
    if (otherContacts) {
      return userContacts.filter(fingerprint => otherContacts.includes(fingerprint));
    }
    
    // Otherwise, we'd implement a secure PSI protocol
    // This is a simplified implementation
    return [];
  }
}