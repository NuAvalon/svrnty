// app/api/contacts/process/route.ts
import { NextResponse } from 'next/server';
import { ContactExchange } from '@/lib/contacts/exchange';
import { ContactManager } from '@/lib/contacts/db';
import { SoverentityIdentity } from '@/lib/identity/core';

const contactExchange = new ContactExchange();
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

export async function POST(request: Request) {
  console.log('API route hit: /api/contacts/process [POST]');
  
  try {
    const body = await request.json();
    console.log('Received process request');
    
    const { fingerprint, exchangeData } = body;
    
    if (!fingerprint || !exchangeData) {
      return NextResponse.json(
        { error: 'Fingerprint and exchange data are required' },
        { status: 400 }
      );
    }
    
    // Process the exchange package
    const contact = await contactExchange.processExchangePackage(
      exchangeData,
      fingerprint
    );
    
    // Add the contact to the user's contacts
    const contactManager = await getContactManager(fingerprint);
    const addedContact = await contactManager.addContact(contact);
    
    return NextResponse.json({
      success: true,
      contact: addedContact
    });
    
  } catch (error) {
    console.error('Failed to process contact exchange:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to process contact exchange' },
      { status: 500 }
    );
  }
}