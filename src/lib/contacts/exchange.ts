// lib/contacts/exchange.ts
import { createMessage, encrypt, sign, readMessage, decrypt, verify, readKey } from 'openpgp';
import { randomBytes } from 'crypto';
import { Contact } from './types';
import { SoverentityIdentity } from '@/lib/identity/core';

interface ExchangePackage {
  version: string;
  sender: {
    fingerprint: string;
    public_key: string;
  };
  recipient_fingerprint?: string; // Optional, only for directed exchanges
  contact_data: {
    name: string;
    email: string;
    fingerprint: string;
    public_key: string;
  };
  expires_at?: string; // For burner links
  mutual_contacts?: string[]; // Encrypted list of fingerprints for PSI
  signature: string;
  created_at: string;
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

      // Sign the package with sender's private key
      const privateKey = await decrypt({
        message: await readMessage({ armoredMessage: keyData.privateKey }),
        passwords: [keyData.passphrase]
      }).then(({ data }) => data.toString());

      const packageToSign = JSON.stringify(exchangePackage);
      const signedMessage = await sign({
        message: await createMessage({ text: packageToSign }),
        signingKeys: privateKey
      });

      // Extract signature
      const signature = signedMessage.toString().split('-----BEGIN PGP SIGNATURE-----')[1].split('-----END PGP SIGNATURE-----')[0].trim();

      // Add signature to the package
      const signedPackage: ExchangePackage = {
        ...exchangePackage,
        signature: signature
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
    const exchangeData = await this.createExchangePackage({
      senderFingerprint,
      expireInHours: 24 // QR codes expire in 24 hours
    });
    
    // Return the data to be encoded in a QR code
    return exchangeData;
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

  // Verify the signature of an exchange package
  private async verifySignature(
    exchangePackage: ExchangePackage,
    publicKeyArmored: string
  ): Promise<boolean> {
    try {
      // Extract package without signature
      const { signature, ...packageData } = exchangePackage;
      const packageText = JSON.stringify(packageData);
      
      // Reconstruct signed message
      const signedMessage = 
        `-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n${packageText}\n-----BEGIN PGP SIGNATURE-----\n${signature}\n-----END PGP SIGNATURE-----`;
      
      // Verify signature
      const message = await readMessage({
        armoredMessage: signedMessage
      });
      
      const publicKey = await readKey({ armoredKey: publicKeyArmored });
      
      const verification = await verify({
        message,
        verificationKeys: publicKey
      });
      
      const { verified } = verification.signatures[0];
      return verified;
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