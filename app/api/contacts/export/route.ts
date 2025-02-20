// app/api/contacts/export/route.ts
import { NextResponse } from 'next/server';
import { ContactManager } from '@/lib/contacts/db';
import { SoverentityIdentity } from '@/lib/identity/core';

const identityManager = new SoverentityIdentity();

// Helper to initialize ContactManager with user details
async function getContactManager(fingerprint: string) {
  // Load user identity
  const identity = await identityManager.loadIdentityData(fingerprint);
  if (!identity) {
    throw new Error('Identity not found');
  }

  // Load private key
  const keyData = await identityManager.loadKey(fingerprint);
  
  return new ContactManager({
    userFingerprint: fingerprint,
    userPublicKey: identity.identity.public_key,
    userPrivateKey: keyData.privateKey,
    userPassphrase: keyData.passphrase
  });
}

export async function GET(request: Request) {
  console.log('API route hit: /api/contacts/export [GET]');
  
  try {
    // Get query parameters
    const url = new URL(request.url);
    const fingerprint = url.searchParams.get('fingerprint');
    const includePrivate = url.searchParams.get('includePrivate') === 'true';
    
    if (!fingerprint) {
      return NextResponse.json(
        { error: 'Fingerprint is required' },
        { status: 400 }
      );
    }
    
    const contactManager = await getContactManager(fingerprint);
    const exportedContacts = await contactManager.exportContacts(includePrivate);
    
    return NextResponse.json({
      success: true,
      contacts: exportedContacts
    });
    
  } catch (error) {
    console.error('Failed to export contacts:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to export contacts' },
      { status: 500 }
    );
  }
}

// app/api/contacts/import/route.ts
import { NextResponse } from 'next/server';
import { ContactManager } from '@/lib/contacts/db';
import { SoverentityIdentity } from '@/lib/identity/core';

const identityManager = new SoverentityIdentity();

// Helper to initialize ContactManager with user details (shared with export route)
async function getContactManager(fingerprint: string) {
  // Load user identity
  const identity = await identityManager.loadIdentityData(fingerprint);
  if (!identity) {
    throw new Error('Identity not found');
  }

  // Load private key
  const keyData = await identityManager.loadKey(fingerprint);
  
  return new ContactManager({
    userFingerprint: fingerprint,
    userPublicKey: identity.identity.public_key,
    userPrivateKey: keyData.privateKey,
    userPassphrase: keyData.passphrase
  });
}

export async function POST(request: Request) {
  console.log('API route hit: /api/contacts/import [POST]');
  
  try {
    const body = await request.json();
    console.log('Received import request');
    
    const { fingerprint, contactsData, overwrite = false } = body;
    
    if (!fingerprint || !contactsData) {
      return NextResponse.json(
        { error: 'Fingerprint and contacts data are required' },
        { status: 400 }
      );
    }
    
    const contactManager = await getContactManager(fingerprint);
    const importCount = await contactManager.importContacts(contactsData, overwrite);
    
    return NextResponse.json({
      success: true,
      importCount,
      message: `Successfully imported ${importCount} contacts`
    });
    
  } catch (error) {
    console.error('Failed to import contacts:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to import contacts' },
      { status: 500 }
    );
  }
}