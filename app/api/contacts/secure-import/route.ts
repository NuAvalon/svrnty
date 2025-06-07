// app/api/contacts/secure-import/route.ts
import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';
import { ContactManager } from '@/lib/contacts/db';
import { ContactCryptoUtil } from '@/lib/contacts/crypto-util';

const identityManager = new SoverentityIdentity();

export async function POST(request: Request) {
  console.log('API route hit: /api/contacts/secure-import [POST]');
  
  try {
    const body = await request.json();
    console.log('Received import request');
    
    const { 
      fingerprint, 
      encryptedContacts, 
      overwrite = false,
      password = null
    } = body;
    
    if (!fingerprint || !encryptedContacts) {
      return NextResponse.json(
        { error: 'Fingerprint and encrypted contacts data are required' },
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
    
    // Decrypt the contacts
    try {
      const { contacts, isPassword } = await ContactCryptoUtil.importContacts(
        encryptedContacts,
        keyData.privateKey,
        keyData.passphrase,
        {
          overwriteExisting: overwrite,
          password: password
        }
      );
      
      // Initialize contact manager
      const contactManager = new ContactManager({
        userFingerprint: fingerprint,
        userPublicKey: identity.identity.public_key,
        userPrivateKey: keyData.privateKey,
        userPassphrase: keyData.passphrase
      });
      
      // Import the contacts
      const importCount = await contactManager.importContacts(
        JSON.stringify(contacts),
        overwrite
      );
      
      return NextResponse.json({
        success: true,
        importCount,
        encryptionType: isPassword ? 'password' : 'pgp',
        message: `Successfully imported ${importCount} contacts`
      });
    } catch (decryptError) {
      console.error('Failed to decrypt contacts:', decryptError);
      return NextResponse.json(
        { 
          success: false, 
          error: decryptError instanceof Error 
            ? decryptError.message 
            : 'Failed to decrypt contacts data'
        },
        { status: 400 }
      );
    }
    
  } catch (error) {
    console.error('Failed to import contacts securely:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to import contacts' },
      { status: 500 }
    );
  }
}