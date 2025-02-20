// app/api/contacts/route.ts
import { NextResponse } from 'next/server';
import { ContactManager } from '@/lib/contacts/db';
import { SoverentityIdentity } from '@/lib/identity/core';
import { RobustContactManager } from '@/lib/contacts/robust-db';

const identityManager = new SoverentityIdentity();

// In-memory fallback storage for reliability
const inMemoryContacts: Record<string, any[]> = {};

// Helper to initialize ContactManager with user details
async function getContactManager(fingerprint: string) {
  try {
    console.log(`[getContactManager] Loading identity for fingerprint: ${fingerprint}`);
    // Load user identity
    const identity = await identityManager.loadIdentityData(fingerprint);
    if (!identity) {
      console.log('[getContactManager] Identity not found');
      throw new Error('Identity not found');
    }

    console.log('[getContactManager] Loading private key');
    try {
      // Load private key
      const keyData = await identityManager.loadKey(fingerprint);
      console.log('[getContactManager] Successfully loaded key data');
      
      // Try the robust contact manager first for better error handling
      try {
        console.log('[getContactManager] Initializing RobustContactManager');
        const robustManager = new RobustContactManager({
          userFingerprint: fingerprint,
          userPublicKey: identity.identity.public_key,
          userPrivateKey: keyData.privateKey,
          userPassphrase: keyData.passphrase
        });
        
        // Initialize it explicitly
        await robustManager.initialize();
        return robustManager;
      } catch (robustError) {
        console.error('[getContactManager] Failed to initialize robust manager:', robustError);
        
        // Fallback to regular ContactManager if robust fails
        console.log('[getContactManager] Falling back to regular ContactManager');
        return new ContactManager({
          userFingerprint: fingerprint,
          userPublicKey: identity.identity.public_key,
          userPrivateKey: keyData.privateKey,
          userPassphrase: keyData.passphrase
        });
      }
    } catch (keyError) {
      console.error('[getContactManager] Failed to load key:', keyError);
      throw new Error(`Failed to load encryption key: ${keyError instanceof Error ? keyError.message : 'Unknown error'}`);
    }
  } catch (error) {
    console.error('[getContactManager] Error:', error);
    throw error;
  }
}

// GET /api/contacts?fingerprint=<user_fingerprint>
export async function GET(request: Request) {
  console.log('[GET /api/contacts] Request received');
  
  try {
    // Get query parameters
    const url = new URL(request.url);
    const fingerprint = url.searchParams.get('fingerprint');
    const trustLevel = url.searchParams.get('trust_level');
    const query = url.searchParams.get('query');
    
    console.log(`[GET /api/contacts] Parameters: fingerprint=${fingerprint}, trustLevel=${trustLevel}, query=${query}`);
    
    if (!fingerprint) {
      console.log('[GET /api/contacts] Missing fingerprint parameter');
      return NextResponse.json(
        { success: false, error: 'Fingerprint is required' },
        { status: 400 }
      );
    }
    
    // Try to get contacts from the regular system first
    try {
      console.log('[GET /api/contacts] Getting contact manager');
      const contactManager = await getContactManager(fingerprint);
      console.log('[GET /api/contacts] Contact manager initialized successfully');
      
      console.log('[GET /api/contacts] Fetching contacts');
      let contacts;
      if (trustLevel) {
        console.log(`[GET /api/contacts] Filtering by trust level: ${trustLevel}`);
        contacts = await contactManager.filterByTrustLevel(
          trustLevel as 'unverified' | 'verified' | 'trusted'
        );
      } else if (query) {
        console.log(`[GET /api/contacts] Searching for: ${query}`);
        contacts = await contactManager.searchContacts(query);
      } else {
        console.log('[GET /api/contacts] Getting all contacts');
        contacts = await contactManager.getAllContacts();
      }
      
      console.log(`[GET /api/contacts] Found ${contacts.length} contacts`);
      return NextResponse.json({ 
        success: true, 
        contacts,
        storage: 'encrypted'
      });
    } catch (encryptedError) {
      // If encrypted storage fails, fall back to in-memory
      console.error('[GET /api/contacts] Encrypted storage failed:', encryptedError);
      console.log('[GET /api/contacts] Falling back to in-memory storage');
      
      const contacts = inMemoryContacts[fingerprint] || [];
      return NextResponse.json({ 
        success: true, 
        contacts,
        storage: 'in-memory',
        fallbackReason: encryptedError instanceof Error ? encryptedError.message : 'Unknown error'
      });
    }
    
  } catch (error) {
    console.error('[GET /api/contacts] Unhandled error:', error);
    return NextResponse.json(
      { 
        success: false, 
        error: error instanceof Error ? error.message : 'Failed to get contacts',
        errorDetails: JSON.stringify(error)
      },
      { status: 500 }
    );
  }
}

// POST /api/contacts
export async function POST(request: Request) {
  console.log('[POST /api/contacts] Request received');
  
  try {
    const body = await request.json();
    console.log('[POST /api/contacts] Received request body');
    
    // Fix: Make sure we extract these variables from the body
    const { fingerprint, contact } = body;
    
    if (!fingerprint || !contact) {
      return NextResponse.json(
        { success: false, error: 'Fingerprint and contact data are required' },
        { status: 400 }
      );
    }
    
    // Try encrypted storage first
    try {
      console.log('[POST /api/contacts] Attempting to add contact with encrypted storage');
      // This line had the error - fingerprint wasn't defined in this scope
      const contactManager = await getContactManager(fingerprint);
      
      // Debug the contact data
      console.log('[POST /api/contacts] Contact data to add:', contact);
      
      // Check for possible validation issues
      if (!contact.name || !contact.email || !contact.fingerprint || !contact.public_key) {
        console.warn('[POST /api/contacts] Contact data validation issue - missing required fields');
      }
      
      if (contact.fingerprint === fingerprint) {
        console.warn('[POST /api/contacts] Attempting to add yourself as a contact');
      }
      
      // Try to add the contact
      const newContact = await contactManager.addContact(contact);
      console.log('[POST /api/contacts] Contact successfully added:', newContact.id);
      
      return NextResponse.json({
        success: true,
        contact: newContact,
        storage: 'encrypted'
      });
    } catch (encryptedError) {
      // More detailed error logging
      console.error('[POST /api/contacts] Failed to add contact with encrypted storage:', encryptedError);
      console.error('[POST /api/contacts] Error type:', encryptedError instanceof Error ? encryptedError.constructor.name : typeof encryptedError);
      console.error('[POST /api/contacts] Stack trace:', encryptedError instanceof Error ? encryptedError.stack : 'No stack trace');
      
      // Fall back to in-memory if encrypted fails
      console.error('[POST /api/contacts] Encrypted storage failed:', encryptedError);
      
      // Initialize in-memory storage if needed
      if (!inMemoryContacts[fingerprint]) {
        inMemoryContacts[fingerprint] = [];
      }
      
      // Create a new contact with ID
      const newContact = {
        ...contact,
        id: Math.random().toString(36).substring(2, 11),
        added_at: new Date().toISOString()
      };
      
      inMemoryContacts[fingerprint].push(newContact);
      
      return NextResponse.json({
        success: true,
        contact: newContact,
        storage: 'in-memory',
        fallbackReason: encryptedError instanceof Error ? encryptedError.message : 'Unknown error'
      });
    }
    
  } catch (error) {
    console.error('[POST /api/contacts] Unhandled error:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to add contact' },
      { status: 500 }
    );
  }
}

// PUT /api/contacts/:id
export async function PUT(request: Request) {
  console.log('[PUT /api/contacts] Request received');
  
  try {
    const body = await request.json();
    console.log('[PUT /api/contacts] Received update request');
    
    const { fingerprint, contactId, updates } = body;
    
    if (!fingerprint || !contactId || !updates) {
      return NextResponse.json(
        { success: false, error: 'Fingerprint, contactId and updates are required' },
        { status: 400 }
      );
    }
    
    // Try encrypted storage first
    try {
      const contactManager = await getContactManager(fingerprint);
      const updatedContact = await contactManager.updateContact(contactId, updates);
      
      return NextResponse.json({
        success: true,
        contact: updatedContact,
        storage: 'encrypted'
      });
    } catch (encryptedError) {
      // Fall back to in-memory
      console.error('[PUT /api/contacts] Encrypted storage failed:', encryptedError);
      
      // Check if we have this contact in memory
      if (!inMemoryContacts[fingerprint]) {
        return NextResponse.json(
          { success: false, error: 'Contact not found in memory storage' },
          { status: 404 }
        );
      }
      
      const contactIndex = inMemoryContacts[fingerprint].findIndex(c => c.id === contactId);
      if (contactIndex === -1) {
        return NextResponse.json(
          { success: false, error: 'Contact not found in memory storage' },
          { status: 404 }
        );
      }
      
      // Update the contact
      const updatedContact = {
        ...inMemoryContacts[fingerprint][contactIndex],
        ...updates
      };
      
      inMemoryContacts[fingerprint][contactIndex] = updatedContact;
      
      return NextResponse.json({
        success: true,
        contact: updatedContact,
        storage: 'in-memory',
        fallbackReason: encryptedError instanceof Error ? encryptedError.message : 'Unknown error'
      });
    }
    
  } catch (error) {
    console.error('[PUT /api/contacts] Unhandled error:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to update contact' },
      { status: 500 }
    );
  }
}

// DELETE /api/contacts?fingerprint=<user_fingerprint>&contactId=<contact_id>
export async function DELETE(request: Request) {
  console.log('[DELETE /api/contacts] Request received');
  
  try {
    const url = new URL(request.url);
    const fingerprint = url.searchParams.get('fingerprint');
    const contactId = url.searchParams.get('contactId');
    
    if (!fingerprint || !contactId) {
      return NextResponse.json(
        { success: false, error: 'Fingerprint and contactId are required' },
        { status: 400 }
      );
    }
    
    // Try encrypted storage first
    try {
      const contactManager = await getContactManager(fingerprint);
      await contactManager.removeContact(contactId);
      
      return NextResponse.json({
        success: true,
        message: 'Contact deleted successfully',
        storage: 'encrypted'
      });
    } catch (encryptedError) {
      // Fall back to in-memory
      console.error('[DELETE /api/contacts] Encrypted storage failed:', encryptedError);
      
      // Check if we have contacts for this fingerprint
      if (!inMemoryContacts[fingerprint]) {
        return NextResponse.json(
          { success: false, error: 'No contacts found for this fingerprint' },
          { status: 404 }
        );
      }
      
      // Find and remove the contact
      const initialLength = inMemoryContacts[fingerprint].length;
      inMemoryContacts[fingerprint] = inMemoryContacts[fingerprint].filter(
        c => c.id !== contactId
      );
      
      if (inMemoryContacts[fingerprint].length === initialLength) {
        return NextResponse.json(
          { success: false, error: 'Contact not found in memory storage' },
          { status: 404 }
        );
      }
      
      return NextResponse.json({
        success: true,
        message: 'Contact deleted successfully',
        storage: 'in-memory',
        fallbackReason: encryptedError instanceof Error ? encryptedError.message : 'Unknown error'
      });
    }
    
  } catch (error) {
    console.error('[DELETE /api/contacts] Unhandled error:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to delete contact' },
      { status: 500 }
    );
  }
}