// app/api/contacts/secure-import/route.ts
import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';
import { ContactManager } from '@/lib/contacts/db';
import { ContactCryptoUtil } from '@/lib/contacts/crypto-util';
import { RobustContactManager } from '@/lib/contacts/robust-db';
import { RobustDecrypt } from '@/lib/contacts/robust-decrypt';

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
    
    // Decrypt the contacts using our robust approach
    try {
      // First, detect if this is a PGP message or plain JSON
      const isPgpMessage = encryptedContacts.includes('-----BEGIN PGP MESSAGE-----');
      let contacts;
      let isPassword = false;
      
      if (!isPgpMessage) {
        // Not encrypted, try to parse as JSON directly
        try {
          console.log('Data does not appear to be PGP encrypted, attempting to parse as JSON');
          const parsedData = JSON.parse(encryptedContacts);
          
          if (Array.isArray(parsedData)) {
            contacts = parsedData;
          } else if (parsedData.contacts && Array.isArray(parsedData.contacts)) {
            contacts = parsedData.contacts;
          } else {
            throw new Error('Invalid contacts data format');
          }
        } catch (jsonError) {
          console.error('Failed to parse as JSON:', jsonError);
          throw new Error('Invalid data format - not a valid PGP message or JSON');
        }
      } else {
        // This is a PGP message, try to decrypt it
        console.log('Data appears to be PGP encrypted');
        
        // First check if it's password-encrypted
        if (password) {
          try {
            console.log('Attempting password decryption...');
            const decrypted = await RobustDecrypt.decryptWithPassword(encryptedContacts, password);
            const parsed = JSON.parse(decrypted);
            
            if (Array.isArray(parsed)) {
              contacts = parsed;
            } else if (parsed.contacts && Array.isArray(parsed.contacts)) {
              contacts = parsed.contacts;
            } else {
              throw new Error('Invalid contacts data format after password decryption');
            }
            
            isPassword = true;
            console.log('Successfully decrypted with password');
          } catch (passwordError) {
            console.log('Password decryption failed, trying PGP key decryption...');
            // Fall through to PGP decryption
          }
        }
        
        // If password decryption didn't work or wasn't attempted, try PGP decryption
        if (!contacts) {
          try {
            console.log('Attempting PGP key decryption...');
            const decrypted = await RobustDecrypt.decryptData(
              encryptedContacts,
              keyData.privateKey,
              keyData.passphrase
            );
            
            const parsed = JSON.parse(decrypted);
            
            if (Array.isArray(parsed)) {
              contacts = parsed;
            } else if (parsed.contacts && Array.isArray(parsed.contacts)) {
              contacts = parsed.contacts;
            } else {
              throw new Error('Invalid contacts data format after PGP decryption');
            }
            
            console.log('Successfully decrypted with PGP key');
          } catch (pgpError) {
            console.error('PGP decryption failed:', pgpError);
            throw new Error('Failed to decrypt contacts: ' + 
              (pgpError instanceof Error ? pgpError.message : 'Unknown error'));
          }
        }
      }
      
      // Initialize contact manager
      console.log('Initializing RobustContactManager for import');
      const contactManager = new RobustContactManager({
        userFingerprint: fingerprint,
        userPublicKey: identity.identity.public_key,
        userPrivateKey: keyData.privateKey,
        userPassphrase: keyData.passphrase
      });
      
      // Explicitly initialize
      await contactManager.initialize();
      
      // Import the contacts
      console.log(`Importing ${contacts.length} contacts`);
      const importCount = await contactManager.importContacts(
        JSON.stringify(contacts),
        overwrite
      );
      
      return NextResponse.json({
        success: true,
        importCount,
        encryptionType: isPassword ? 'password' : isPgpMessage ? 'pgp' : 'none',
        message: `Successfully imported ${importCount} contacts`
      });
    } catch (decryptError) {
      console.error('Failed to decrypt or import contacts:', decryptError);
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