// app/api/test-contact/route.ts
import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';
import { ContactManager } from '@/lib/contacts/db';
import { RobustContactManager } from '@/lib/contacts/robust-db';
import { readFile } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';

export async function GET(request: Request) {
  console.log('[GET /api/test-contact] Starting contact diagnostic');
  
  const results = {
    success: false,
    identityLoaded: false,
    keyLoaded: false,
    managerInitialized: false,
    contactsLoaded: false,
    contactAdded: false,
    errors: [] as string[],
    contacts: [] as any[],
    addedContact: null as any
  };
  
  try {
    // Get fingerprint from query
    const url = new URL(request.url);
    const fingerprint = url.searchParams.get('fingerprint');
    
    if (!fingerprint) {
      results.errors.push('No fingerprint provided');
      return NextResponse.json(results);
    }
    
    // 1. Load identity
    const identityManager = new SoverentityIdentity();
    try {
      const identity = await identityManager.loadIdentityData(fingerprint);
      if (!identity) {
        results.errors.push('Identity not found');
        return NextResponse.json(results);
      }
      results.identityLoaded = true;
      
      // 2. Load key
      try {
        const keyData = await identityManager.loadKey(fingerprint);
        results.keyLoaded = true;
        
        // 3. Create contact manager and test loading
        try {
          const contactManager = new RobustContactManager({
            userFingerprint: fingerprint,
            userPublicKey: identity.identity.public_key,
            userPrivateKey: keyData.privateKey,
            userPassphrase: keyData.passphrase
          });
          
          await contactManager.initialize();
          results.managerInitialized = true;
          
          // 4. Try to load contacts
          try {
            const contacts = await contactManager.getAllContacts();
            results.contactsLoaded = true;
            results.contacts = contacts;
            
            // 5. Try to add a test contact
            try {
              const testContact = {
                name: `Test Contact ${new Date().toISOString()}`,
                email: `test${Date.now()}@example.com`,
                fingerprint: `test${Date.now().toString(16)}`,
                public_key: '-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: OpenPGP.js v4.10.10\nComment: https://openpgpjs.org\n\nxjMEYoJC6RYJKwYBBAHaRw8BAQdA7W8Ky0UiSvP01iwpZHdFs/2EysSPKQJy\nOPMLDnUbiZDNGVRlc3QgPHRlc3RAZXhhbXBsZS5jb20+wo8EExYIADcWIQTo\nzXXVSmhJPQrbMhDLhYgQCGtlhAUCYoJC6QIbAwULCQgHAgYVCAkKCwIFFgID\nAQAAFgkQy4WIEAhrZYR/IACrK+F5wQQQiGyJBjH9zqhXhDTdnVhqP02XQhxG\nj+HJl5RKKvb4jksCkzYVOAUZ8KC3dA0X8iEZ4D0sH50CCjY6JKqkqFhE9F3C\nOARigkLpEgorBgEEAZdVAQUBAQdA54TVkfiPsJpblCiIh7f5Wui8hFNBKEHE\nRUGNGw0PMpgDAQgHwngEGBYIACAWIQTozXXVSmhJPQrbMhDLhYgQCGtlhAUC\nYoJC6QIbDAAA/wTFcAEBCQnoyoBP48fBD9KE/R/8EqJ9V6reZnKpZQVPJAKb\nt6i8D6i5XDaRGBdlNyAj8zsiqQ==\n=P/Bc\n-----END PGP PUBLIC KEY BLOCK-----',
                trust_level: 'unverified' as const
              };
              
              const addedContact = await contactManager.addContact(testContact);
              results.contactAdded = true;
              results.addedContact = addedContact;
              
              // Overall success
              results.success = true;
            } catch (addError) {
              results.errors.push(`Failed to add contact: ${addError instanceof Error ? addError.message : 'Unknown error'}`);
            }
          } catch (loadError) {
            results.errors.push(`Failed to load contacts: ${loadError instanceof Error ? loadError.message : 'Unknown error'}`);
          }
        } catch (managerError) {
          results.errors.push(`Failed to initialize contact manager: ${managerError instanceof Error ? managerError.message : 'Unknown error'}`);
        }
      } catch (keyError) {
        results.errors.push(`Failed to load key: ${keyError instanceof Error ? keyError.message : 'Unknown error'}`);
      }
    } catch (identityError) {
      results.errors.push(`Failed to load identity: ${identityError instanceof Error ? identityError.message : 'Unknown error'}`);
    }
    
    return NextResponse.json(results);
    
  } catch (error) {
    results.errors.push(`Unhandled error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    return NextResponse.json(results);
  }
}