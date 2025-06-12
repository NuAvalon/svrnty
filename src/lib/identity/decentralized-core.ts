// src/lib/identity/decentralized-core.ts

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
  
  interface EncryptedKeyData {
    encrypted_private_key: string;
    key_derivation: {
      algorithm: string;
      salt: string;
      iterations: number;
    };
  }
  
  interface ExportData {
    identity: IdentityData;
    encrypted_key_data: EncryptedKeyData;
    exported_at: string;
  }
  
  /**
   * Fully decentralized identity management using only browser APIs
   * No server dependencies - everything stored in browser storage
   */
  export class DecentralizedIdentityCore {
    private static readonly IDENTITY_STORAGE_KEY = 'soverentity_identity_';
    private static readonly KEY_STORAGE_KEY = 'soverentity_key_';
    private isClient: boolean;
    private openpgp: any = null;
    
    constructor() {
      this.isClient = typeof window !== 'undefined';
    }
  
    /**
     * Dynamically import OpenPGP only when needed on client side
     */
    private async getOpenPGP() {
      if (!this.isClient) {
        throw new Error('OpenPGP can only be used in browser environment');
      }
      
      if (!this.openpgp) {
        try {
          this.openpgp = await import('openpgp');
          console.log('OpenPGP loaded successfully');
        } catch (error) {
          console.error('Failed to load OpenPGP:', error);
          throw new Error('Failed to load cryptographic library');
        }
      }
      
      return this.openpgp;
    }
  
    /**
     * Check if we're running in a browser environment
     */
    private ensureClientSide(): void {
      if (!this.isClient) {
        throw new Error('This operation can only be performed in a browser environment');
      }
    }
  
    /**
     * Enhanced crypto availability check with detailed debugging
     */
    private ensureCryptoAvailable(): void {
      this.ensureClientSide();
      
      console.log('Crypto availability check:', {
        hasWindow: typeof window !== 'undefined',
        hasCrypto: typeof crypto !== 'undefined',
        hasGlobalCrypto: typeof globalThis.crypto !== 'undefined',
        hasWindowCrypto: typeof window?.crypto !== 'undefined',
        cryptoSubtle: typeof crypto?.subtle,
        windowCryptoSubtle: typeof window?.crypto?.subtle,
        isSecureContext: window?.isSecureContext,
        protocol: window?.location?.protocol
      });
  
      // Try multiple ways to access crypto
      let cryptoAPI = null;
      let subtleAPI = null;
  
      // Method 1: Global crypto
      if (typeof crypto !== 'undefined' && crypto.subtle) {
        cryptoAPI = crypto;
        subtleAPI = crypto.subtle;
        console.log('Using global crypto API');
      }
      // Method 2: Window crypto
      else if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
        cryptoAPI = window.crypto;
        subtleAPI = window.crypto.subtle;
        console.log('Using window.crypto API');
      }
      // Method 3: GlobalThis crypto
      else if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
        cryptoAPI = globalThis.crypto;
        subtleAPI = globalThis.crypto.subtle;
        console.log('Using globalThis.crypto API');
      }
  
      if (!cryptoAPI || !subtleAPI) {
        const errorDetails = {
          isSecureContext: window?.isSecureContext,
          protocol: window?.location?.protocol,
          userAgent: navigator?.userAgent,
          cryptoExists: typeof crypto !== 'undefined',
          subtleExists: typeof crypto?.subtle !== 'undefined'
        };
        
        console.error('Web Crypto API not available. Details:', errorDetails);
        
        if (window?.location?.protocol === 'http:' && window?.location?.hostname !== 'localhost') {
          throw new Error('Web Crypto API requires HTTPS. Please use HTTPS or localhost for development.');
        }
        
        throw new Error(`Web Crypto API is not available in this browser. Details: ${JSON.stringify(errorDetails)}`);
      }
  
      // Test that subtle crypto actually works
      try {
        const testArray = new Uint8Array(1);
        if (typeof cryptoAPI.getRandomValues === 'function') {
          cryptoAPI.getRandomValues(testArray);
          console.log('Crypto API test successful');
        } else {
          throw new Error('getRandomValues not available');
        }
      } catch (testError) {
        console.error('Crypto API test failed:', testError);
        throw new Error('Web Crypto API is not functioning properly');
      }
    }
    
    /**
     * Generate a new identity completely in the browser
     */
    async generateIdentity({ name, email }: UserID, masterPassword?: string): Promise<{
      identity: IdentityData;
      fingerprint: string;
    }> {
      console.log('Starting identity generation...');
      this.ensureClientSide();
      this.ensureCryptoAvailable();
  
      try {
        console.log('Loading OpenPGP...');
        const openpgp = await this.getOpenPGP();
        
        // Generate a secure passphrase for the PGP key
        console.log('Generating secure passphrase...');
        const pgpPassphrase = this.generateSecurePassphrase();
  
        console.log('Generating PGP key pair...');
        // Generate PGP key pair
        const { privateKey, publicKey } = await openpgp.generateKey({
          type: 'ecc',
          curve: 'ed25519',
          userIDs: [{ name, email }],
          passphrase: pgpPassphrase,
          format: 'armored'
        });
  
        console.log('Reading generated key for fingerprint...');
        // Read the generated key for metadata
        const pubKeyObj = await openpgp.readKey({ armoredKey: publicKey });
        const fingerprint = pubKeyObj.getFingerprint();
  
        console.log('Creating identity data structure...');
        // Create identity claim
        const identity: IdentityData = {
          version: '1.0.0',
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
            client_version: '1.0.0',
            key_type: 'ED25519',
            key_usage: ['identity', 'signing', 'encryption']
          }
        };
  
        console.log('Encrypting and storing private key...');
        // Encrypt and store the private key
        await this.storeEncryptedKey(fingerprint, privateKey, pgpPassphrase, masterPassword);
        
        console.log('Storing identity data...');
        // Store identity data
        await this.storeIdentity(fingerprint, identity);
  
        console.log(`✅ Generated decentralized identity: ${fingerprint}`);
  
        return {
          identity,
          fingerprint
        };
      } catch (error) {
        console.error('Failed to generate identity:', error);
        throw error;
      }
    }
  
    /**
     * Load an identity from browser storage
     */
    async loadIdentityData(fingerprint: string): Promise<IdentityData | null> {
      this.ensureClientSide();
  
      try {
        const stored = localStorage.getItem(`${DecentralizedIdentityCore.IDENTITY_STORAGE_KEY}${fingerprint}`);
        if (!stored) {
          return null;
        }
        
        const identity = JSON.parse(stored);
        console.log(`Loaded identity from browser storage: ${fingerprint}`);
        return identity;
      } catch (error) {
        console.error('Failed to load identity:', error);
        return null;
      }
    }
  
    /**
     * Load decrypted key data (requires master password if set)
     */
    async loadKey(fingerprint: string, masterPassword?: string): Promise<{
      privateKey: string;
      passphrase: string;
    }> {
      this.ensureClientSide();
      this.ensureCryptoAvailable();
  
      try {
        const stored = localStorage.getItem(`${DecentralizedIdentityCore.KEY_STORAGE_KEY}${fingerprint}`);
        if (!stored) {
          throw new Error('Key data not found');
        }
        
        const encryptedKeyData: EncryptedKeyData = JSON.parse(stored);
        
        // Decrypt the private key data
        const decryptedData = await this.decryptKeyData(encryptedKeyData, masterPassword);
        
        console.log(`Loaded and decrypted key for: ${fingerprint}`);
        return decryptedData;
      } catch (error) {
        console.error('Failed to load key:', error);
        throw error;
      }
    }
  
    /**
     * Store identity data in browser localStorage
     */
    private async storeIdentity(fingerprint: string, identity: IdentityData): Promise<void> {
      this.ensureClientSide();
  
      try {
        const storageKey = `${DecentralizedIdentityCore.IDENTITY_STORAGE_KEY}${fingerprint}`;
        localStorage.setItem(storageKey, JSON.stringify(identity));
        console.log(`Stored identity in browser: ${fingerprint}`);
      } catch (error) {
        console.error('Failed to store identity:', error);
        throw new Error('Failed to store identity data');
      }
    }
  
    /**
     * Store encrypted private key in browser localStorage
     */
    private async storeEncryptedKey(
      fingerprint: string, 
      privateKey: string, 
      pgpPassphrase: string,
      masterPassword?: string
    ): Promise<void> {
      this.ensureClientSide();
      this.ensureCryptoAvailable();
  
      try {
        // Create key data object
        const keyData = {
          privateKey,
          passphrase: pgpPassphrase
        };
  
        // Encrypt the key data
        const encryptedKeyData = await this.encryptKeyData(keyData, masterPassword);
        
        const storageKey = `${DecentralizedIdentityCore.KEY_STORAGE_KEY}${fingerprint}`;
        localStorage.setItem(storageKey, JSON.stringify(encryptedKeyData));
        
        console.log(`Stored encrypted key in browser: ${fingerprint}`);
      } catch (error) {
        console.error('Failed to store encrypted key:', error);
        throw new Error('Failed to store key data');
      }
    }
  
    /**
     * Encrypt key data using Web Crypto API with better error handling
     */
    private async encryptKeyData(
      keyData: { privateKey: string; passphrase: string }, 
      masterPassword?: string
    ): Promise<EncryptedKeyData> {
      this.ensureCryptoAvailable();
  
      console.log('Starting key data encryption...');
      const dataToEncrypt = JSON.stringify(keyData);
      
      if (!masterPassword) {
        // No master password - store with a random key derived from browser entropy
        masterPassword = this.generateSecurePassphrase();
      }
      
      try {
        // Get crypto API
        const cryptoAPI = this.getCryptoAPI();
        
        console.log('Generating salt and deriving key...');
        // Generate salt
        const salt = cryptoAPI.getRandomValues(new Uint8Array(16));
        const iterations = 100000;
        
        // Derive key from master password
        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(masterPassword);
        
        const importedKey = await cryptoAPI.subtle.importKey(
          'raw',
          passwordBuffer,
          { name: 'PBKDF2' },
          false,
          ['deriveBits', 'deriveKey']
        );
        
        const derivedKey = await cryptoAPI.subtle.deriveKey(
          {
            name: 'PBKDF2',
            salt: salt,
            iterations: iterations,
            hash: 'SHA-256'
          },
          importedKey,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt']
        );
        
        console.log('Encrypting data...');
        // Encrypt the data
        const iv = cryptoAPI.getRandomValues(new Uint8Array(12));
        const encodedData = encoder.encode(dataToEncrypt);
        
        const encryptedBuffer = await cryptoAPI.subtle.encrypt(
          { name: 'AES-GCM', iv: iv },
          derivedKey,
          encodedData
        );
        
        // Combine IV and encrypted data
        const combined = new Uint8Array(iv.length + encryptedBuffer.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encryptedBuffer), iv.length);
        
        console.log('Key data encryption completed successfully');
        return {
          encrypted_private_key: this.arrayBufferToBase64(combined),
          key_derivation: {
            algorithm: 'PBKDF2-SHA256-AES-GCM',
            salt: this.arrayBufferToBase64(salt),
            iterations: iterations
          }
        };
      } catch (error) {
        console.error('Key encryption failed:', error);
        throw new Error(`Failed to encrypt key data: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
  
    /**
     * Get the appropriate crypto API
     */
    private getCryptoAPI(): Crypto {
      if (typeof crypto !== 'undefined' && crypto.subtle) {
        return crypto;
      }
      if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
        return window.crypto;
      }
      if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
        return globalThis.crypto;
      }
      throw new Error('No crypto API available');
    }
  
    /**
     * Decrypt key data using Web Crypto API
     */
    private async decryptKeyData(
      encryptedKeyData: EncryptedKeyData, 
      masterPassword?: string
    ): Promise<{ privateKey: string; passphrase: string }> {
      this.ensureCryptoAvailable();
  
      if (!masterPassword) {
        throw new Error('Master password required to decrypt keys');
      }
      
      try {
        const cryptoAPI = this.getCryptoAPI();
        
        // Parse the encrypted data
        const combined = this.base64ToArrayBuffer(encryptedKeyData.encrypted_private_key);
        const iv = combined.slice(0, 12);
        const encryptedData = combined.slice(12);
        
        const salt = this.base64ToArrayBuffer(encryptedKeyData.key_derivation.salt);
        const iterations = encryptedKeyData.key_derivation.iterations;
        
        // Derive the same key
        const encoder = new TextEncoder();
        const decoder = new TextDecoder();
        const passwordBuffer = encoder.encode(masterPassword);
        
        const importedKey = await cryptoAPI.subtle.importKey(
          'raw',
          passwordBuffer,
          { name: 'PBKDF2' },
          false,
          ['deriveBits', 'deriveKey']
        );
        
        const derivedKey = await cryptoAPI.subtle.deriveKey(
          {
            name: 'PBKDF2',
            salt: salt,
            iterations: iterations,
            hash: 'SHA-256'
          },
          importedKey,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt']
        );
        
        // Decrypt the data
        const decryptedBuffer = await cryptoAPI.subtle.decrypt(
          { name: 'AES-GCM', iv: iv },
          derivedKey,
          encryptedData
        );
        
        const decryptedText = decoder.decode(decryptedBuffer);
        const keyData = JSON.parse(decryptedText);
        
        return keyData;
      } catch (error) {
        console.error('Key decryption failed:', error);
        throw new Error(`Failed to decrypt key data: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
  
    /**
     * Export identity for backup/transfer
     */
    async exportIdentity(fingerprint: string, masterPassword?: string): Promise<ExportData> {
      this.ensureClientSide();
  
      try {
        const identity = await this.loadIdentityData(fingerprint);
        if (!identity) {
          throw new Error('Identity not found');
        }
        
        // Get encrypted key data directly from storage
        const stored = localStorage.getItem(`${DecentralizedIdentityCore.KEY_STORAGE_KEY}${fingerprint}`);
        if (!stored) {
          throw new Error('Key data not found');
        }
        
        const encryptedKeyData = JSON.parse(stored);
        
        return {
          identity,
          encrypted_key_data: encryptedKeyData,
          exported_at: new Date().toISOString()
        };
      } catch (error) {
        console.error('Failed to export identity:', error);
        throw error;
      }
    }
  
    /**
     * Import identity from backup
     */
    async importIdentity(importData: ExportData): Promise<IdentityData> {
      this.ensureClientSide();
  
      try {
        const fingerprint = importData.identity.identity.fingerprint;
        
        // Store the identity
        await this.storeIdentity(fingerprint, importData.identity);
        
        // Store the encrypted key data
        const keyStorageKey = `${DecentralizedIdentityCore.KEY_STORAGE_KEY}${fingerprint}`;
        localStorage.setItem(keyStorageKey, JSON.stringify(importData.encrypted_key_data));
        
        console.log(`Imported identity: ${fingerprint}`);
        return importData.identity;
      } catch (error) {
        console.error('Failed to import identity:', error);
        throw error;
      }
    }
  
    /**
     * Get all stored identity fingerprints
     */
    getAllStoredFingerprints(): string[] {
      this.ensureClientSide();
  
      const fingerprints: string[] = [];
      const prefix = DecentralizedIdentityCore.IDENTITY_STORAGE_KEY;
      
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith(prefix)) {
          const fingerprint = key.substring(prefix.length);
          fingerprints.push(fingerprint);
        }
      }
      
      return fingerprints;
    }
  
    /**
     * Delete an identity completely
     */
    async deleteIdentity(fingerprint: string): Promise<void> {
      this.ensureClientSide();
  
      try {
        localStorage.removeItem(`${DecentralizedIdentityCore.IDENTITY_STORAGE_KEY}${fingerprint}`);
        localStorage.removeItem(`${DecentralizedIdentityCore.KEY_STORAGE_KEY}${fingerprint}`);
        console.log(`Deleted identity: ${fingerprint}`);
      } catch (error) {
        console.error('Failed to delete identity:', error);
        throw error;
      }
    }
  
    /**
     * Verify an identifier using the stored private key
     */
    async verifyIdentifier(fingerprint: string, type: string, value: string, masterPassword?: string): Promise<IdentityData> {
      this.ensureClientSide();
  
      try {
        const identity = await this.loadIdentityData(fingerprint);
        if (!identity) {
          throw new Error('Identity not found');
        }
        
        // Update verification status
        identity.verification = {
          status: 'verified',
          method: type,
          verified_at: new Date().toISOString()
        };
        
        // Store updated identity
        await this.storeIdentity(fingerprint, identity);
        
        return identity;
      } catch (error) {
        console.error('Failed to verify identifier:', error);
        throw error;
      }
    }
  
    // Utility methods
    private generateSecurePassphrase(): string {
      this.ensureCryptoAvailable();
      const cryptoAPI = this.getCryptoAPI();
      const array = new Uint8Array(32);
      cryptoAPI.getRandomValues(array);
      return btoa(String.fromCharCode(...array));
    }
  
    private arrayBufferToBase64(buffer: ArrayBuffer): string {
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    }
  
    private base64ToArrayBuffer(base64: string): Uint8Array {
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    }
  }