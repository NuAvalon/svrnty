// app/api/list-contacts/route.ts
import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';
import { RobustContactManager } from '@/lib/contacts/robust-db';

export async function GET(request: Request) {
  try {
    const url = new URL(request.url);
    const fingerprint = url.searchParams.get('fingerprint');
    
    if (!fingerprint) {
      return NextResponse.json({
        success: false,
        error: 'Fingerprint is required'
      }, { status: 400 });
    }
    
    console.log(`Listing contacts for fingerprint: ${fingerprint}`);
    const identityManager = new SoverentityIdentity();
    
    // Load identity
    const identity = await identityManager.loadIdentityData(fingerprint);
    if (!identity) {
      return NextResponse.json({
        success: false,
        error: 'Identity not found'
      }, { status: 404 });
    }
    
    // Load key
    const keyData = await identityManager.loadKey(fingerprint);
    
    // Initialize contact manager
    const contactManager = new RobustContactManager({
      userFingerprint: fingerprint,
      userPublicKey: identity.identity.public_key,
      userPrivateKey: keyData.privateKey,
      userPassphrase: keyData.passphrase
    });
    
    await contactManager.initialize();
    
    // Load all contacts
    const contacts = await contactManager.getAllContacts();
    
    return NextResponse.json({
      success: true,
      identity: {
        name: identity.identity.name,
        email: identity.identity.email,
        fingerprint: identity.identity.fingerprint,
        verification: identity.verification
      },
      contacts,
      count: contacts.length
    });
    
  } catch (error) {
    console.error('Error listing contacts:', error);
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 });
  }
}