// src/lib/identity/persistent-manager.ts

interface StoredIdentity {
    fingerprint: string;
    name: string;
    email: string;
    created_at: string;
    verification_status: string;
    last_used: string;
  }
  
  interface IdentityBackup {
    version: string;
    identity: any;
    encrypted_key_data: any;
    created_at: string;
    backup_type: 'full' | 'identity_only';
    contacts?: string; // Optional encrypted contacts
  }
  
  /**
   * Fully decentralized identity management using only browser storage
   * No servers, no backends - pure peer-to-peer sovereignty
   */
  export class PersistentIdentityManager {
    private static readonly STORAGE_KEY = 'soverentity_identities';
    private static readonly CURRENT_IDENTITY_KEY = 'soverentity_current_identity';
    private identityCore: any = null;
    private isClient: boolean;
  
    constructor() {
      this.isClient = typeof window !== 'undefined';
    }
  
    /**
     * Dynamically import the identity core only when needed
     */
    private async getIdentityCore() {
      if (!this.isClient) {
        throw new Error('Identity core can only be used in browser environment');
      }
      
      if (!this.identityCore) {
        try {
          const { DecentralizedIdentityCore } = await import('./decentralized-core');
          this.identityCore = new DecentralizedIdentityCore();
          console.log('Identity core loaded successfully');
        } catch (error) {
          console.error('Failed to load identity core:', error);
          throw new Error('Failed to load identity management system');
        }
      }
      
      return this.identityCore;
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
     * Get all stored identities (metadata only, not private keys)
     */
    public getStoredIdentities(): StoredIdentity[] {
      if (!this.isClient) {
        return [];
      }
  
      try {
        const stored = localStorage.getItem(PersistentIdentityManager.STORAGE_KEY);
        return stored ? JSON.parse(stored) : [];
      } catch (error) {
        console.error('Failed to load stored identities:', error);
        return [];
      }
    }
  
    /**
     * Get the currently active identity fingerprint
     */
    public getCurrentIdentityFingerprint(): string | null {
      if (!this.isClient) {
        return null;
      }
      return localStorage.getItem(PersistentIdentityManager.CURRENT_IDENTITY_KEY);
    }
  
    /**
     * Set the currently active identity
     */
    public setCurrentIdentity(fingerprint: string): void {
      this.ensureClientSide();
      
      localStorage.setItem(PersistentIdentityManager.CURRENT_IDENTITY_KEY, fingerprint);
      
      // Update last_used timestamp
      const identities = this.getStoredIdentities();
      const updated = identities.map(id => 
        id.fingerprint === fingerprint 
          ? { ...id, last_used: new Date().toISOString() }
          : id
      );
      this.saveIdentities(updated);
    }
  
    /**
     * Check if we have any stored identities
     */
    public hasStoredIdentities(): boolean {
      return this.getStoredIdentities().length > 0;
    }
  
    /**
     * Create a new decentralized identity (no servers involved)
     */
    public async createIdentity(name: string, email: string, masterPassword?: string): Promise<{
      identity: any;
      fingerprint: string;
    }> {
      this.ensureClientSide();
  
      try {
        console.log('Creating decentralized sovereign identity...');
        
        const identityCore = await this.getIdentityCore();
        
        // Generate the identity using pure browser crypto
        const result = await identityCore.generateIdentity({ name, email }, masterPassword);
        
        // Store identity metadata in localStorage for quick access
        const identityMeta: StoredIdentity = {
          fingerprint: result.fingerprint,
          name,
          email,
          created_at: new Date().toISOString(),
          verification_status: result.identity.verification.status,
          last_used: new Date().toISOString()
        };
  
        // Add to stored identities
        const identities = this.getStoredIdentities();
        identities.push(identityMeta);
        this.saveIdentities(identities);
  
        // Set as current identity
        this.setCurrentIdentity(result.fingerprint);
  
        console.log(`✅ Created sovereign identity: ${result.fingerprint}`);
        return result;
      } catch (error) {
        console.error('Failed to create decentralized identity:', error);
        throw error;
      }
    }
  
    /**
     * Load an identity from browser storage
     */
    public async loadIdentity(fingerprint: string, masterPassword?: string): Promise<any> {
      this.ensureClientSide();
  
      try {
        const identityCore = await this.getIdentityCore();
        
        // Load from the decentralized identity system (browser-only)
        const identity = await identityCore.loadIdentityData(fingerprint);
        
        if (identity) {
          // Update as current identity
          this.setCurrentIdentity(fingerprint);
          
          // Update last used
          const identities = this.getStoredIdentities();
          const updated = identities.map(id => 
            id.fingerprint === fingerprint 
              ? { ...id, last_used: new Date().toISOString() }
              : id
          );
          this.saveIdentities(updated);
          
          console.log(`✅ Loaded sovereign identity: ${fingerprint}`);
        }
        
        return identity;
      } catch (error) {
        console.error(`Failed to load identity ${fingerprint}:`, error);
        throw error;
      }
    }
  
    /**
     * Load key data for an identity
     */
    public async loadKey(fingerprint: string, masterPassword?: string): Promise<{
      privateKey: string;
      passphrase: string;
    }> {
      this.ensureClientSide();
  
      try {
        const identityCore = await this.getIdentityCore();
        return await identityCore.loadKey(fingerprint, masterPassword);
      } catch (error) {
        console.error(`Failed to load key for ${fingerprint}:`, error);
        throw error;
      }
    }
  
    /**
     * Delete an identity completely from browser storage
     */
    public async deleteIdentity(fingerprint: string): Promise<void> {
      this.ensureClientSide();
  
      try {
        // Remove from stored identities list
        const identities = this.getStoredIdentities();
        const filtered = identities.filter(id => id.fingerprint !== fingerprint);
        this.saveIdentities(filtered);
  
        // Clear current identity if it was the one being deleted
        if (this.getCurrentIdentityFingerprint() === fingerprint) {
          localStorage.removeItem(PersistentIdentityManager.CURRENT_IDENTITY_KEY);
        }
  
        // Delete from decentralized storage
        const identityCore = await this.getIdentityCore();
        await identityCore.deleteIdentity(fingerprint);
        
        console.log(`✅ Deleted sovereign identity: ${fingerprint}`);
      } catch (error) {
        console.error('Failed to delete identity:', error);
        throw error;
      }
    }
  
    /**
     * Create a complete backup of an identity for portability
     */
    public async createIdentityBackup(
      fingerprint: string, 
      includeContacts: boolean = true,
      masterPassword?: string
    ): Promise<string> {
      this.ensureClientSide();
  
      try {
        console.log('Creating decentralized backup...');
        
        const identityCore = await this.getIdentityCore();
        
        // Export the identity (fully self-contained)
        const identityExport = await identityCore.exportIdentity(fingerprint, masterPassword);
        
        const backup: IdentityBackup = {
          version: '1.0.0',
          identity: identityExport.identity,
          encrypted_key_data: identityExport.encrypted_key_data,
          created_at: new Date().toISOString(),
          backup_type: includeContacts ? 'full' : 'identity_only'
        };
  
        if (includeContacts) {
          // TODO: Add encrypted contacts export here
          // This will be a self-contained encrypted blob
          backup.contacts = '';
        }
  
        console.log('✅ Created portable sovereign backup');
        return JSON.stringify(backup, null, 2);
      } catch (error) {
        console.error('Failed to create identity backup:', error);
        throw error;
      }
    }
  
    /**
     * Restore an identity from a portable backup
     */
    public async restoreFromBackup(backupData: string, masterPassword?: string): Promise<{
      identity: any;
      fingerprint: string;
    }> {
      this.ensureClientSide();
  
      try {
        console.log('Restoring from decentralized backup...');
        
        const backup: IdentityBackup = JSON.parse(backupData);
        
        const identityCore = await this.getIdentityCore();
        
        // Import the identity into decentralized storage
        const identity = await identityCore.importIdentity({
          identity: backup.identity,
          encrypted_key_data: backup.encrypted_key_data,
          exported_at: backup.created_at
        });
        
        const fingerprint = identity.identity.fingerprint;
  
        // Store identity metadata
        const identityMeta: StoredIdentity = {
          fingerprint,
          name: identity.identity.name,
          email: identity.identity.email,
          created_at: backup.created_at,
          verification_status: identity.verification.status,
          last_used: new Date().toISOString()
        };
  
        // Add to stored identities (check for duplicates)
        const identities = this.getStoredIdentities();
        const exists = identities.some(id => id.fingerprint === fingerprint);
        
        if (!exists) {
          identities.push(identityMeta);
          this.saveIdentities(identities);
        }
  
        // Set as current identity
        this.setCurrentIdentity(fingerprint);
  
        console.log(`✅ Restored sovereign identity: ${fingerprint}`);
        return { identity, fingerprint };
      } catch (error) {
        console.error('Failed to restore from backup:', error);
        throw error;
      }
    }
  
    /**
     * Get the most recently used identity
     */
    public getMostRecentIdentity(): StoredIdentity | null {
      const identities = this.getStoredIdentities();
      if (identities.length === 0) return null;
  
      return identities.reduce((most, current) => 
        new Date(current.last_used) > new Date(most.last_used) ? current : most
      );
    }
  
    /**
     * Auto-load the most appropriate identity
     */
    public async autoLoadIdentity(masterPassword?: string): Promise<any | null> {
      if (!this.isClient) {
        return null;
      }
  
      try {
        // First, try to load the current identity
        const currentFingerprint = this.getCurrentIdentityFingerprint();
        if (currentFingerprint) {
          try {
            return await this.loadIdentity(currentFingerprint, masterPassword);
          } catch (error) {
            console.warn('Failed to load current identity, trying most recent');
          }
        }
  
        // If no current identity or it failed to load, try the most recent
        const mostRecent = this.getMostRecentIdentity();
        if (mostRecent) {
          try {
            return await this.loadIdentity(mostRecent.fingerprint, masterPassword);
          } catch (error) {
            console.warn('Failed to load most recent identity');
          }
        }
  
        return null;
      } catch (error) {
        console.error('Auto-load identity failed:', error);
        return null;
      }
    }
  
    /**
     * Update verification status for an identity
     */
    public updateVerificationStatus(fingerprint: string, status: string): void {
      this.ensureClientSide();
  
      const identities = this.getStoredIdentities();
      const updated = identities.map(id => 
        id.fingerprint === fingerprint 
          ? { ...id, verification_status: status }
          : id
      );
      this.saveIdentities(updated);
    }
  
    /**
     * Verify an identifier (like email) in a decentralized way
     */
    public async verifyIdentifier(fingerprint: string, type: string, value: string, masterPassword?: string): Promise<any> {
      this.ensureClientSide();
  
      try {
        const identityCore = await this.getIdentityCore();
        const updatedIdentity = await identityCore.verifyIdentifier(fingerprint, type, value, masterPassword);
        
        // Update metadata
        this.updateVerificationStatus(fingerprint, updatedIdentity.verification.status);
        
        return updatedIdentity;
      } catch (error) {
        console.error('Failed to verify identifier:', error);
        throw error;
      }
    }
  
    /**
     * Save identities to localStorage
     */
    private saveIdentities(identities: StoredIdentity[]): void {
      this.ensureClientSide();
  
      try {
        localStorage.setItem(PersistentIdentityManager.STORAGE_KEY, JSON.stringify(identities));
      } catch (error) {
        console.error('Failed to save identities to localStorage:', error);
        throw new Error('Failed to save identity data');
      }
    }
  
    /**
     * Clear all stored identity data (for testing or reset)
     */
    public async clearAllData(): Promise<void> {
      this.ensureClientSide();
  
      // Clear metadata
      localStorage.removeItem(PersistentIdentityManager.STORAGE_KEY);
      localStorage.removeItem(PersistentIdentityManager.CURRENT_IDENTITY_KEY);
      
      try {
        const identityCore = await this.getIdentityCore();
        // Clear all individual identity and key data
        const fingerprints = identityCore.getAllStoredFingerprints();
        for (const fingerprint of fingerprints) {
          await identityCore.deleteIdentity(fingerprint);
        }
      } catch (error) {
        console.warn('Failed to clear some identity data:', error);
      }
      
      console.log('✅ Cleared all sovereign identity data');
    }
  
    /**
     * Get storage information for transparency
     */
    public getStorageInfo(): {
      totalIdentities: number;
      storageUsed: number;
      storageLocation: 'browser-localStorage';
      decentralized: true;
    } {
      if (!this.isClient) {
        return {
          totalIdentities: 0,
          storageUsed: 0,
          storageLocation: 'browser-localStorage',
          decentralized: true
        };
      }
  
      const identities = this.getStoredIdentities();
      let storageUsed = 0;
      
      // Estimate storage usage
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith('soverentity_')) {
          const value = localStorage.getItem(key);
          if (value) {
            storageUsed += key.length + value.length;
          }
        }
      }
      
      return {
        totalIdentities: identities.length,
        storageUsed: storageUsed,
        storageLocation: 'browser-localStorage',
        decentralized: true
      };
    }
  }