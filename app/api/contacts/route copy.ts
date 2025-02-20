// app/api/contacts/route.ts
import { NextResponse } from 'next/server';
import { ContactManager } from '@/lib/contacts/db';
import { SoverentityIdentity } from '@/lib/identity/core';

const identityManager = new SoverentityIdentity();

console.log('Contacts API route module loaded');

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
      
      console.log('[getContactManager] Initializing ContactManager');
      return new ContactManager({
        userFingerprint: fingerprint,
        userPublicKey: identity.identity.public_key,
        userPrivateKey: keyData.privateKey,
        userPassphrase: keyData.passphrase
      });
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
    
    console.log('[GET /api/contacts] Getting contact manager');
    let contactManager;
    try {
      contactManager = await getContactManager(fingerprint);
      console.log('[GET /api/contacts] Contact manager initialized successfully');
    } catch (managerError) {
      console.error('[GET /api/contacts] Failed to initialize contact manager:', managerError);
      return NextResponse.json(
        { 
          success: false, 
          error: managerError instanceof Error ? managerError.message : 'Failed to initialize contact manager' 
        },
        { status: 500 }
      );
    }
    
    console.log('[GET /api/contacts] Fetching contacts');
    let contacts;
    try {
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
    } catch (fetchError) {
      console.error('[GET /api/contacts] Error fetching contacts:', fetchError);
      return NextResponse.json(
        { 
          success: false, 
          error: fetchError instanceof Error ? fetchError.message : 'Failed to fetch contacts' 
        },
        { status: 500 }
      );
    }
    
    console.log('[GET /api/contacts] Returning successful response');
    return NextResponse.json({ 
      success: true, 
      contacts 
    });
    
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

// The rest of your API methods (POST, PUT, DELETE) remain the same


// PUT /api/contacts/:id
export async function PUT(request: Request) {
  console.log('API route hit: /api/contacts [PUT]');
  
  try {
    const body = await request.json();
    console.log('Received update request:', body);
    
    const { fingerprint, contactId, updates } = body;
    
    if (!fingerprint || !contactId || !updates) {
      return NextResponse.json(
        { success: false, error: 'Fingerprint, contactId and updates are required' },
        { status: 400 }
      );
    }
    
    const contactManager = await getContactManager(fingerprint);
    const updatedContact = await contactManager.updateContact(contactId, updates);
    
    return NextResponse.json({
      success: true,
      contact: updatedContact
    });
    
  } catch (error) {
    console.error('Failed to update contact:', error);
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : 'Failed to update contact' },
      { status: 500 }
    );
  }
}

// DELETE /api/contacts?fingerprint=<user_fingerprint>&contactId=<contact_id>
export async function DELETE(request: Request) {
  console.log('API route hit: /api/contacts [DELETE]');
  
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
    
    const contactManager = await getContactManager(fingerprint);
    await contactManager.removeContact(contactId);
    
    return NextResponse.json({
      success: true,
      message: 'Contact deleted successfully'
    });
    
  } catch (error) {
    console.error('Failed to delete contact:', error);
    return NextResponse.json(
      { success: false, error: error instanceof Error ? error.message : 'Failed to delete contact' },
      { status: 500 }
    );
  }
}