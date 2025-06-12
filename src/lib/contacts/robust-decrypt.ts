// src/lib/contacts/robust-decrypt.ts
import { readKey, createMessage, readMessage, decrypt, decryptKey } from 'openpgp';

/**
 * Utility for robustly decrypting PGP content with various fallback strategies
 */
export class RobustDecrypt {
  /**
   * Attempts to decrypt a private key with its passphrase to prepare it for decryption use
   * 
   * @param privateKeyArmored - The armored private key
   * @param passphrase - The passphrase for the private key
   * @returns The decrypted key as a string or Key object
   */
  public static async preparePrivateKey(privateKeyArmored: string, passphrase: string): Promise<any> {
    try {
      console.log('Attempting to prepare private key...');
      
      // First approach: Read the private key directly
      const privateKey = await readKey({ armoredKey: privateKeyArmored });
      
      // Check if it's already decrypted
      if (privateKey.isDecrypted()) {
        console.log('Private key is already decrypted');
        return privateKey;
      }
      
      // Try to decrypt the private key with the passphrase
      console.log('Private key is encrypted, attempting to decrypt...');
      const decryptedKey = await decryptKey({
        privateKey,
        passphrase
      });
      
      console.log('Successfully decrypted private key');
      return decryptedKey;
      
    } catch (directError) {
      console.log('Direct key reading failed, trying alternative approach...');
      console.error('Direct error:', directError);
      
      try {
        // Alternative approach - try reading as a message first
        console.log('Attempting to read private key as encrypted message...');
        const privateKeyMsg = await readMessage({ armoredMessage: privateKeyArmored });
        const { data } = await decrypt({
          message: privateKeyMsg,
          passwords: [passphrase]
        });
        
        // Now read the decrypted data as a key
        const decryptedKey = await readKey({ armoredKey: data.toString() });
        console.log('Successfully prepared private key via message decryption');
        return decryptedKey;
        
      } catch (messageError) {
        console.error('Message approach also failed:', messageError);
        
        // Final fallback - return the original armored key
        console.log('Falling back to original armored key');
        try {
          const key = await readKey({ armoredKey: privateKeyArmored });
          // Try one more time to decrypt it
          try {
            await key.decrypt(passphrase);
            return key;
          } catch (decryptErr) {
            console.warn('Could not decrypt key, returning as-is');
            return key;
          }
        } catch (finalError) {
          console.error('All private key preparation methods failed:', finalError);
          throw new Error('Failed to prepare private key for decryption');
        }
      }
    }
  }
  
  /**
   * Attempts to decrypt PGP data with a private key using multiple fallback approaches
   * 
   * @param encryptedData - The encrypted data to decrypt
   * @param privateKeyArmored - The armored private key
   * @param passphrase - The passphrase for the private key
   * @returns The decrypted data as a string
   */
  public static async decryptData(
    encryptedData: string, 
    privateKeyArmored: string, 
    passphrase: string
  ): Promise<string> {
    console.log('Attempting to decrypt data with robust approach...');
    
    try {
      // First, prepare the private key
      const preparedKey = await this.preparePrivateKey(privateKeyArmored, passphrase);
      
      // Then attempt decryption
      const message = await readMessage({ armoredMessage: encryptedData });
      
      console.log('Attempting decryption with prepared key...');
      try {
        // Try decryption with prepared key
        const { data } = await decrypt({
          message,
          decryptionKeys: preparedKey
        });
        
        console.log('Successfully decrypted data');
        return data.toString();
      } catch (decryptError) {
        console.log('Direct decryption failed, trying alternative approaches...');
        console.error('Decrypt error:', decryptError);
        
        // Try using the private key in different ways
        try {
          // Approach 2: Re-read the private key and ensure it's decrypted
          const privateKey = await readKey({ armoredKey: privateKeyArmored });
          
          if (!privateKey.isDecrypted()) {
            const decryptedKey = await decryptKey({
              privateKey,
              passphrase
            });
            
            const result = await decrypt({
              message,
              decryptionKeys: decryptedKey
            });
            
            return result.data.toString();
          } else {
            const result = await decrypt({
              message,
              decryptionKeys: privateKey
            });
            
            return result.data.toString();
          }
        } catch (altError) {
          console.error('Alternative decryption approach failed:', altError);
          
          // Final attempt: Try with array of keys
          try {
            const privateKey = await readKey({ armoredKey: privateKeyArmored });
            if (!privateKey.isDecrypted()) {
              await privateKey.decrypt(passphrase);
            }
            
            const result = await decrypt({
              message,
              decryptionKeys: [privateKey]
            });
            
            return result.data.toString();
          } catch (finalError) {
            console.error('All decryption methods failed:', finalError);
            throw new Error(`Failed to decrypt data: ${finalError instanceof Error ? finalError.message : 'Unknown error'}`);
          }
        }
      }
    } catch (error) {
      console.error('Robust decryption completely failed:', error);
      throw error;
    }
  }
  
  /**
   * Attempts to decrypt a PGP message with a password
   * 
   * @param encryptedData - The encrypted data
   * @param password - The password used for encryption
   * @returns The decrypted data as a string
   */
  public static async decryptWithPassword(encryptedData: string, password: string): Promise<string> {
    try {
      console.log('Attempting password decryption...');
      const message = await readMessage({ armoredMessage: encryptedData });
      
      const { data } = await decrypt({
        message,
        passwords: [password]
      });
      
      console.log('Successfully decrypted with password');
      return data.toString();
    } catch (error) {
      console.error('Failed to decrypt with password:', error);
      throw new Error('Failed to decrypt with password');
    }
  }
}