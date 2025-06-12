// src/lib/contacts/crypto-util.ts
import { encrypt, decrypt, readKey, readMessage, createMessage } from 'openpgp';
import { Contact } from './types';
import { RobustDecrypt } from './robust-decrypt';

interface ContactExportOptions {
  /** Whether to include full public keys in the export */
  includePublicKeys?: boolean;
  /** Whether to use the user's PGP key for encryption (if false, password encryption is used) */
  usePgpEncryption?: boolean;
  /** Password to use for symmetric encryption (only used if usePgpEncryption is false) */
  password?: string;
}

interface ContactImportOptions {
  /** Whether to overwrite existing contacts with the same fingerprint */
  overwriteExisting?: boolean;
  /** Password to use for symmetric decryption (only used for password-encrypted exports) */
  password?: string;
}

const DEFAULT_EXPORT_OPTIONS: ContactExportOptions = {
  includePublicKeys: true,
  usePgpEncryption: true
};

const DEFAULT_IMPORT_OPTIONS: ContactImportOptions = {
  overwriteExisting: false
};

/**
 * Utility for securely exporting and importing contacts with encryption
 */
export class ContactCryptoUtil {
  /**
   * Create an encrypted export of contacts
   * 
   * @param contacts The contacts to export
   * @param userPublicKey The user's public key (for encryption)
   * @param options Export options
   * @returns Encrypted contacts data as a string
   */
  public static async exportContacts(
    contacts: Contact[],
    userPublicKey: string,
    options: ContactExportOptions = DEFAULT_EXPORT_OPTIONS
  ): Promise<string> {
    try {
      console.log('Starting contact export process...');
      
      // Clone and sanitize contacts if needed
      const exportContacts = contacts.map(contact => {
        const { public_key, ...rest } = contact;
        
        return options.includePublicKeys 
          ? contact 
          : { ...rest, public_key: '<redacted>' };
      });

      // Create export package with metadata
      const exportPackage = {
        version: '1.0.0',
        exported_at: new Date().toISOString(),
        encrypted: true,
        encryption_method: options.usePgpEncryption ? 'pgp' : 'password',
        contact_count: exportContacts.length,
        contacts: exportContacts
      };

      // Convert to JSON
      const exportJson = JSON.stringify(exportPackage, null, 2);
      console.log(`Prepared JSON export of ${exportContacts.length} contacts`);

      // Encrypt the export
      if (options.usePgpEncryption) {
        console.log('Using PGP encryption with public key');
        // Use PGP encryption with user's public key
        const message = await createMessage({ text: exportJson });
        const publicKey = await readKey({ armoredKey: userPublicKey });
        
        const encrypted = await encrypt({
          message,
          encryptionKeys: publicKey
        });
        
        return encrypted.toString();
      } else {
        // Use symmetric encryption with password
        if (!options.password) {
          throw new Error('Password is required for symmetric encryption');
        }
        
        console.log('Using symmetric password encryption');
        const message = await createMessage({ text: exportJson });
        
        const encrypted = await encrypt({
          message,
          passwords: [options.password]
        });
        
        return encrypted.toString();
      }
    } catch (error) {
      console.error('Failed to export contacts:', error);
      throw new Error(`Failed to export contacts: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
  
  /**
   * Import contacts from an encrypted export
   * 
   * @param encryptedData The encrypted contacts data
   * @param userPrivateKey The user's private key (for decryption)
   * @param passphrase The passphrase for the private key
   * @param options Import options
   * @returns The imported contacts
   */
  public static async importContacts(
    encryptedData: string,
    userPrivateKey: string,
    passphrase: string,
    options: ContactImportOptions = DEFAULT_IMPORT_OPTIONS
  ): Promise<{ contacts: Contact[], isPassword: boolean }> {
    try {
      console.log('Starting robust contact import process...');
      
      // Check if this looks like PGP data
      const isPgpMessage = encryptedData.includes('-----BEGIN PGP MESSAGE-----');
      
      if (!isPgpMessage) {
        console.log('Data does not appear to be encrypted, attempting to parse as JSON');
        // Attempt to parse as JSON directly (unencrypted)
        try {
          const parsedData = JSON.parse(encryptedData);
          
          if (Array.isArray(parsedData)) {
            // Simple array of contacts
            return { 
              contacts: parsedData, 
              isPassword: false 
            };
          } else if (parsedData.contacts && Array.isArray(parsedData.contacts)) {
            // Export package with metadata
            return { 
              contacts: parsedData.contacts, 
              isPassword: false 
            };
          } else {
            throw new Error('Invalid contacts data format');
          }
        } catch (e) {
          console.error('Failed to parse as JSON:', e);
          throw new Error('Invalid data format - not a valid PGP message or JSON');
        }
      }
      
      console.log('Data appears to be PGP encrypted');
      // Decrypt the data using our robust approach
      let decrypted: string;
      let isPassword = false;
      
      // First try with password if provided
      if (options.password) {
        try {
          console.log('Attempting password decryption first...');
          decrypted = await RobustDecrypt.decryptWithPassword(encryptedData, options.password);
          isPassword = true;
          console.log('Successfully decrypted with password');
        } catch (passwordError) {
          console.log('Password decryption failed, trying PGP key...');
          // Try PGP key decryption instead
          decrypted = await RobustDecrypt.decryptData(encryptedData, userPrivateKey, passphrase);
          console.log('Successfully decrypted with PGP key');
        }
      } else {
        // No password provided, try PGP key directly
        decrypted = await RobustDecrypt.decryptData(encryptedData, userPrivateKey, passphrase);
      }
      
      // Parse the decrypted data
      try {
        const parsed = JSON.parse(decrypted);
        
        if (Array.isArray(parsed)) {
          // Simple array of contacts
          return { contacts: parsed, isPassword };
        } else if (parsed.contacts && Array.isArray(parsed.contacts)) {
          // Export package with metadata
          return { contacts: parsed.contacts, isPassword };
        } else {
          throw new Error('Invalid contacts data format');
        }
      } catch (parseError) {
        console.error('Failed to parse decrypted data:', parseError);
        throw new Error('Failed to parse decrypted data');
      }
    } catch (error) {
      console.error('Failed to import contacts:', error);
      throw new Error(`Failed to import contacts: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Check if data appears to be password-encrypted
   * 
   * @param encryptedData The encrypted data to check
   * @returns True if the data appears to be password encrypted
   */
  public static isPasswordEncrypted(encryptedData: string): boolean {
    // This is a best-effort guess since we can't know for sure without trying to decrypt
    const isPgpMessage = encryptedData.includes('-----BEGIN PGP MESSAGE-----');
    
    if (!isPgpMessage) {
      return false;
    }
    
    // Look for hints that suggest password encryption vs. public key encryption
    // This is not foolproof but can give a hint
    return encryptedData.includes('PASSPHRASE') || encryptedData.includes('SYMMETRIC');
  }
}