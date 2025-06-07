// app/api/contacts/secure-export/route.ts
import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';
import { ContactManager } from '@/lib/contacts/db';
import { ContactCryptoUtil } from '@/lib/contacts/crypto-util';

const identityManager = new SoverentityIdentity();

export async function GET(request: Request) {
  console.log('API route hit: /api/contacts/secure-export [GET]');
  
  try {
    // Get query parameters
    const url = new URL(request.url);
    const fingerprint = url.searchParams.get('fingerprint');
    const includePublicKeys = url.searchParams.get('includePublicKeys') === 'true';
    const usePassword = url.searchParams.get('usePassword') === 'true';
    const password = url.searchParams.get('password');
    
    if (!fingerprint) {
      return NextResponse.json(
        { error: 'Fingerprint is required' },
        { status: 400 }
      );
    }
    
    // Load user identity
    const identity = await identityManager.loadIdentityData(fingerprint);
    if (!identity) {
      return NextResponse.json(
        { error: 'Identity not found' },
        { status: 404 }
      );
    }

    // Load key data
    const keyData = await identityManager.loadKey(fingerprint);
    
    // Initialize contact manager
    const contactManager = new ContactManager({
      userFingerprint: fingerprint,
      userPublicKey: identity.identity.public_key,
      userPrivateKey: keyData.privateKey,
      userPassphrase: keyData.passphrase
    });
    
    // Get all contacts
    const contacts = await contactManager.getAllContacts();
    
    // Create encrypted export
    const encryptedExport = await ContactCryptoUtil.exportContacts(
      contacts,
      identity.identity.public_key,
      {
        includePublicKeys,
        usePgpEncryption: !usePassword,
        password: usePassword ? password || undefined : undefined
      }
    );
    
    return NextResponse.json({
      success: true,
      encryptedContacts: encryptedExport,
      count: contacts.length,
      encryptionMethod: usePassword ? 'password' : 'pgp'
    });
    
  } catch (error) {
    console.error('Failed to export contacts securely:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to export contacts' },
      { status: 500 }
    );
  }
}