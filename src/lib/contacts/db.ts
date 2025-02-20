// lib/contacts/db.ts
import { readFile, writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { createMessage, encrypt, readMessage, decrypt, readKey } from 'openpgp';
import { randomUUID } from 'crypto';
import { Contact } from './types';

export class ContactManager {
  private storageDir: string;
  private userFingerprint: string;
  private userPublicKey: string;
  private userPrivateKey: string;
  private userPassphrase: string;

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
    this.storageDir = storageDir || join(homedir(), '.soverentity', 'contacts');
    this.userFingerprint = userFingerprint;
    this.userPublicKey = userPublicKey;
    this.userPrivateKey = userPrivateKey;
    this.userPassphrase = userPassphrase;
    this.initialize();
  }

  private async initialize(): Promise<void> {
    try {
      console.log(`Initializing ContactManager with storage dir: ${this.storageDir}`);
      await mkdir(this.storageDir, { recursive: true });
      console.log('Storage directory created/verified');
    } catch (error: any) {
      console.error('Error initializing contact storage directory:', error);
      if (error.code !== 'EEXIST') {
        console.error('Critical error initializing storage:', error);
        throw error;
      }
    }
  }

  private async getContactsFilePath(): Promise<string> {
    return join(this.storageDir, `${this.userFingerprint}.contacts.enc`);
  }

  async addContact(contactData: Omit<Contact, 'id' | 'added_at'>): Promise<Contact> {
    const contacts = await this.loadContacts();
    
    // Check if contact already exists
    const existingContact = contacts.find(c => c.fingerprint === contactData.fingerprint);
    if (existingContact) {
      throw new Error('Contact with this fingerprint already exists');
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
    try {
      const filePath = await this.getContactsFilePath();
      try {
        const encryptedData = await readFile(filePath, 'utf8');
        
        // Decrypt the contacts file
        const message = await readMessage({
          armoredMessage: encryptedData
        });
        
        const { data: decrypted } = await decrypt({
          message,
          decryptionKeys: await decrypt({
            message: await readMessage({ armoredMessage: this.userPrivateKey }),
            passwords: [this.userPassphrase]
          }).then(({ data }) => data.toString())
        });
        
        return JSON.parse(decrypted.toString());
      } catch (error: any) {
        if (error.code === 'ENOENT') {
          // File doesn't exist yet, return empty array
          return [];
        }
        throw error;
      }
    } catch (error) {
      console.error('Failed to load contacts:', error);
      throw new Error('Failed to load contacts');
    }
  }

  private async saveContacts(contacts: Contact[]): Promise<void> {
    try {
      const filePath = await this.getContactsFilePath();
      
      // Encrypt the contacts data with user's public key
      const message = await createMessage({
        text: JSON.stringify(contacts, null, 2)
      });
      
      const publicKey = await readKey({ armoredKey: this.userPublicKey });
      
      const encrypted = await encrypt({
        message,
        encryptionKeys: publicKey
      });
      
      await writeFile(filePath, encrypted);
    } catch (error) {
      console.error('Failed to save contacts:', error);
      throw new Error('Failed to save contacts');
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