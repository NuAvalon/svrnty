// src/lib/contacts/robust-db.ts
import { readFile, writeFile, mkdir, access, constants } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { 
  createMessage, 
  encrypt, 
  readMessage, 
  decrypt, 
  readKey,
  decryptKey
} from 'openpgp';
import { randomUUID } from 'crypto';
import { Contact } from './types';

// For browser compatibility
const isServer = typeof window === 'undefined';

// Helper function to read and decrypt private key
async function readPrivateKey({ armoredKey, passphrase }: { armoredKey: string, passphrase: string }) {
  try {
    return await decryptKey({
      privateKey: await readKey({ armoredKey }),
      passphrase
    });
  } catch (error) {
    console.error('Error reading private key:', error);
    // If decryption fails, try a different approach
    try {
      // Try using the key directly
      const privateKey = await readKey({ armoredKey });
      return privateKey;
    } catch (directReadError) {
      console.error('Failed to read key directly:', directReadError);
      throw new Error('Could not read private key');
    }
  }
}

export class RobustContactManager {
  private storageDir: string;
  private userFingerprint: string;
  private userPublicKey: string;
  private userPrivateKey: string;
  private userPassphrase: string;
  private memoryCache: Contact[] | null = null;
  private isInitialized = false;
  private initializationPromise: Promise<void> | null = null;

  constructor({
    storageDir,
    userFingerprint,
    userPublicKey,
    userPrivateKey,
    userPassphrase
  }: {
    storageDir?: string;
    userFingerprint: string;
    userPublicKey: string;
    userPrivateKey: string;
    userPassphrase: string;
  }) {
    // Default to in-memory storage if not on server
    this.storageDir = isServer 
      ? (storageDir || join(homedir(), '.soverentity', 'contacts'))
      : 'memory-only';
    
    this.userFingerprint = userFingerprint;
    this.userPublicKey = userPublicKey;
    this.userPrivateKey = userPrivateKey;
    this.userPassphrase = userPassphrase;
    
    // Initialize immediately for browser
    if (!isServer) {
      this.memoryCache = [];
      this.isInitialized = true;
    }
  }

  async initialize(): Promise<void> {
    // Prevent multiple initializations
    if (this.isInitialized) {
      return;
    }

    // If initialization is already in progress, wait for it
    if (this.initializationPromise) {
      return this.initializationPromise;
    }

    // Set up initialization promise
    this.initializationPromise = this._initialize();
    await this.initializationPromise;
    this.isInitialized = true;
  }

  // Private actual initialization implementation
  private async _initialize(): Promise<void> {
    // Skip directory creation if using memory storage
    if (this.storageDir === 'memory-only') {
      console.log('Using in-memory storage for contacts');
      if (this.memoryCache === null) {
        this.memoryCache = [];
      }
      return;
    }
    
    try {
      console.log(`Initializing RobustContactManager with storage dir: ${this.storageDir}`);
      await mkdir(this.storageDir, { recursive: true });
      console.log('Storage directory created/verified');
      
      // Check if the contacts file exists
      const filePath = join(this.storageDir, `${this.userFingerprint}.contacts.enc`);
      try {
        await access(filePath, constants.F_OK);
        console.log('Contacts file exists');
      } catch (accessError) {
        // File doesn't exist, create an empty contacts file
        console.log('Contacts file does not exist, creating an empty one');
        // Use internal _saveContacts method to avoid recursion
        await this._saveContacts([]);
      }
    } catch (error: any) {
      console.error('Error initializing contact storage directory:', error);
      if (error.code !== 'EEXIST') {
        console.error('Falling back to in-memory storage');
        this.storageDir = 'memory-only';
        this.memoryCache = [];
      }
    }
  }

  private async getContactsFilePath(): Promise<string> {
    await this.initialize();
    return this.storageDir === 'memory-only' 
      ? 'memory' 
      : join(this.storageDir, `${this.userFingerprint}.contacts.enc`);
  }

  async addContact(contactData: Omit<Contact, 'id' | 'added_at'>): Promise<Contact> {
    const contacts = await this.loadContacts();
    
    // Check if contact already exists
    const existingContact = contacts.find(c => c.fingerprint === contactData.fingerprint);
    if (existingContact) {
      console.error('Contact already exists with fingerprint:', contactData.fingerprint);
      throw new Error(`Contact with fingerprint ${contactData.fingerprint} already exists`);
    }

    // More precise validation
    if (!contactData.name || !contactData.email || !contactData.fingerprint || !contactData.public_key) {
      const missingFields = [];
      if (!contactData.name) missingFields.push('name');
      if (!contactData.email) missingFields.push('email');
      if (!contactData.fingerprint) missingFields.push('fingerprint');
      if (!contactData.public_key) missingFields.push('public_key');
      
      console.error('Missing required fields:', missingFields);
      throw new Error(`Missing required fields: ${missingFields.join(', ')}`);
    }

    // Verify fingerprint matches key
    const publicKey = await readKey({ armoredKey: contactData.public_key });
    const actualFingerprint = publicKey.getFingerprint().toUpperCase();
    if (actualFingerprint !== contactData.fingerprint.toUpperCase()) {
      throw new Error(`Fingerprint mismatch: provided "${contactData.fingerprint}" but key has "${actualFingerprint}"`);
    }

    const newContact: Contact = {
      ...contactData,
      id: randomUUID(),
      added_at: new Date().toISOString(),
    };

    contacts.push(newContact);
    await this.saveContacts(contacts);
    return newContact;
  }

  async updateContact(id: string, updates: Partial<Omit<Contact, 'id' | 'fingerprint'>>): Promise<Contact> {
    const contacts = await this.loadContacts();
    const contactIndex = contacts.findIndex(c => c.id === id);
    
    if (contactIndex === -1) {
      throw new Error('Contact not found');
    }

    const updatedContact = {
      ...contacts[contactIndex],
      ...updates,
    };

    contacts[contactIndex] = updatedContact;
    await this.saveContacts(contacts);
    return updatedContact;
  }

  async removeContact(id: string): Promise<void> {
    const contacts = await this.loadContacts();
    const updatedContacts = contacts.filter(c => c.id !== id);
    
    if (updatedContacts.length === contacts.length) {
      throw new Error('Contact not found');
    }

    await this.saveContacts(updatedContacts);
  }

  async getContact(id: string): Promise<Contact | null> {
    const contacts = await this.loadContacts();
    return contacts.find(c => c.id === id) || null;
  }

  async getContactByFingerprint(fingerprint: string): Promise<Contact | null> {
    const contacts = await this.loadContacts();
    return contacts.find(c => c.fingerprint === fingerprint) || null;
  }

  async getAllContacts(): Promise<Contact[]> {
    return this.loadContacts();
  }

  async searchContacts(query: string): Promise<Contact[]> {
    const contacts = await this.loadContacts();
    query = query.toLowerCase();
    
    return contacts.filter(c => 
      c.name.toLowerCase().includes(query) || 
      c.email.toLowerCase().includes(query) ||
      c.fingerprint.toLowerCase().includes(query) ||
      c.metadata?.tags?.some(tag => tag.toLowerCase().includes(query))
    );
  }

  async filterByTrustLevel(trustLevel: Contact['trust_level']): Promise<Contact[]> {
    const contacts = await this.loadContacts();
    return contacts.filter(c => c.trust_level === trustLevel);
  }

  private async loadContacts(): Promise<Contact[]> {
    // If we're in memory-only mode, return the cache
    if (this.storageDir === 'memory-only') {
      console.log('Loading contacts from memory cache');
      return this.memoryCache || [];
    }
    
    try {
      const filePath = await this.getContactsFilePath();
      if (filePath === 'memory') {
        return this.memoryCache || [];
      }
      
      try {
        const encryptedData = await readFile(filePath, 'utf8');
        
        // Check if the file exists but is empty or invalid
        if (!encryptedData || encryptedData.trim() === '') {
          console.log('Contacts file exists but is empty, returning empty array');
          return [];
        }
        
        // Check if this looks like armored PGP data
        if (!encryptedData.includes('-----BEGIN PGP MESSAGE-----')) {
          console.warn('File does not contain armored PGP data, returning empty array');
          return [];
        }
        
        try {
          // Use a more straightforward approach for decryption
          console.log('Attempting to decrypt contacts file');
          
          // Read the private key (we don't need to decrypt it here)
          const privateKey = await readPrivateKey({
            armoredKey: this.userPrivateKey,
            passphrase: this.userPassphrase
          });
          
          // Read the message
          const message = await readMessage({
            armoredMessage: encryptedData
          });
          
          // Decrypt the message with the private key
          const { data } = await decrypt({
            message,
            decryptionKeys: privateKey
          });
          
          const contactsString = data.toString();
          try {
            console.log('Successfully decrypted contacts file');
            return JSON.parse(contactsString);
          } catch (parseError) {
            console.error('Failed to parse decrypted contacts data:', parseError);
            return [];
          }
        } catch (decryptError) {
          console.error('Failed to decrypt contacts file:', decryptError);
          // Fallback to empty contacts if decryption fails
          return [];
        }
      } catch (error: any) {
        if (error.code === 'ENOENT') {
          // File doesn't exist yet, return empty array
          return [];
        }
        console.error('Failed to read contacts file:', error);
        // Fallback to in-memory for any file reading errors
        this.storageDir = 'memory-only';
        this.memoryCache = [];
        return [];
      }
    } catch (error) {
      console.error('Unhandled error in loadContacts:', error);
      // Ultimate fallback
      return [];
    }
  }

  private async saveContacts(contacts: Contact[]): Promise<void> {
    // If we're in memory-only mode, just update the cache
    if (this.storageDir === 'memory-only') {
      console.log('Saving contacts to memory cache');
      this.memoryCache = [...contacts];
      return;
    }
    
    try {
      const filePath = await this.getContactsFilePath();
      if (filePath === 'memory') {
        this.memoryCache = [...contacts];
        return;
      }
      
      // Try to encrypt and save
      try {
        console.log(`Saving ${contacts.length} contacts to ${filePath}`);
        
        // Create message with the contacts data
        const message = await createMessage({
          text: JSON.stringify(contacts, null, 2)
        });
        
        // Encrypt using a simpler approach
        try {
          // Just read the public key
          const publicKey = await readKey({ armoredKey: this.userPublicKey });
          
          // Encrypt the message
          const encrypted = await encrypt({
            message,
            encryptionKeys: publicKey
          });
          
          // Write to file
          await writeFile(filePath, encrypted);
          console.log('Contacts saved successfully');
        } catch (encryptError) {
          console.error('Failed to encrypt with public key:', encryptError);
          throw encryptError;
        }
      } catch (encryptError) {
        console.error('Failed to encrypt contacts:', encryptError);
        // Fallback to memory cache on encryption failure
        this.storageDir = 'memory-only';
        this.memoryCache = [...contacts];
      }
    } catch (error) {
      console.error('Failed to save contacts:', error);
      // Fallback to memory
      this.storageDir = 'memory-only';
      this.memoryCache = [...contacts];
    }
  }

  // Add a private _saveContacts method for initialization
  private async _saveContacts(contacts: Contact[]): Promise<void> {
    if (this.storageDir === 'memory-only') {
      this.memoryCache = [...contacts];
      return;
    }
    
    const filePath = join(this.storageDir, `${this.userFingerprint}.contacts.enc`);
    try {
      console.log(`Saving ${contacts.length} contacts during initialization`);
      
      const message = await createMessage({
        text: JSON.stringify(contacts, null, 2)
      });
      
      const publicKey = await readKey({ armoredKey: this.userPublicKey });
      const encrypted = await encrypt({
        message,
        encryptionKeys: publicKey
      });
      
      await writeFile(filePath, encrypted);
      console.log('Initial contacts file created successfully');
    } catch (error) {
      console.error('Failed to create initial contacts file:', error);
      this.storageDir = 'memory-only';
      this.memoryCache = [];
    }
  }

  async exportContacts(includePrivateKeys: boolean = false): Promise<string> {
    const contacts = await this.loadContacts();
    
    // Filter out private information if not requested
    const exportedContacts = contacts.map(contact => {
      const { public_key, ...rest } = contact;
      return includePrivateKeys ? contact : { ...rest, public_key: '<redacted>' };
    });
    
    return JSON.stringify(exportedContacts, null, 2);
  }

  async importContacts(contactsJson: string, overwrite: boolean = false): Promise<number> {
    try {
      const importedContacts = JSON.parse(contactsJson) as Contact[];
      const existingContacts = await this.loadContacts();
      
      let importCount = 0;
      for (const contact of importedContacts) {
        const exists = existingContacts.some(c => c.fingerprint === contact.fingerprint);
        
        if (!exists || overwrite) {
          if (exists && overwrite) {
            // Remove existing contact first
            const existingIndex = existingContacts.findIndex(c => c.fingerprint === contact.fingerprint);
            existingContacts.splice(existingIndex, 1);
          }
          
          // Add the imported contact
          existingContacts.push({
            ...contact,
            id: exists ? contact.id : randomUUID(),
            added_at: exists ? contact.added_at : new Date().toISOString()
          });
          
          importCount++;
        }
      }
      
      if (importCount > 0) {
        await this.saveContacts(existingContacts);
      }
      
      return importCount;
    } catch (error) {
      console.error('Failed to import contacts:', error);
      throw new Error('Failed to import contacts: Invalid format');
    }
  }
}