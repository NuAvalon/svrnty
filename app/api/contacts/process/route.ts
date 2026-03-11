// app/api/contacts/process/route.ts
// Process a received exchange package: verify signatures, import contact.
// Handles both signed JSON and PGP-encrypted packages.

import { NextResponse } from 'next/server';
import { ContactExchange } from '@/lib/contacts/exchange';
import { ContactManager } from '@/lib/contacts/db';
import { SoverentityIdentity } from '@/lib/identity/core';

const contactExchange = new ContactExchange();
const identityManager = new SoverentityIdentity();

async function getContactManager(fingerprint: string) {
  const identity = await identityManager.loadIdentityData(fingerprint);
  if (!identity) throw new Error('Identity not found');
  const keyData = await identityManager.loadKey(fingerprint);

  return new ContactManager({
    userFingerprint: fingerprint,
    userPublicKey: identity.identity.public_key,
    userPrivateKey: keyData.privateKey,
    userPassphrase: keyData.passphrase,
  });
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { fingerprint, exchangeData } = body;

    if (!fingerprint || !exchangeData) {
      return NextResponse.json(
        { error: 'Fingerprint and exchange data are required' },
        { status: 400 }
      );
    }

    // Process and verify the exchange package (dual-sig verification)
    const contact = await contactExchange.processExchangePackage(
      exchangeData,
      fingerprint
    );

    // Add the verified contact
    const contactManager = await getContactManager(fingerprint);

    // Check if contact already exists
    const existing = await contactManager.getContactByFingerprint(contact.fingerprint);
    if (existing) {
      return NextResponse.json({
        success: true,
        contact: existing,
        alreadyExists: true,
        message: 'Contact already exists in your network',
      });
    }

    const addedContact = await contactManager.addContact(contact);

    return NextResponse.json({
      success: true,
      contact: addedContact,
      verified: true,
      message: `${contact.name} added to your network as Known. Vouch for them to grant trust.`,
    });

  } catch (error) {
    console.error('Failed to process exchange:', error);

    const message = error instanceof Error ? error.message : 'Failed to process exchange';

    // Provide helpful error messages
    if (message.includes('expired')) {
      return NextResponse.json(
        { success: false, error: 'This exchange package has expired. Ask them to share a new one.' },
        { status: 400 }
      );
    }
    if (message.includes('signature') || message.includes('Invalid')) {
      return NextResponse.json(
        { success: false, error: 'Signature verification failed. The package may have been tampered with.' },
        { status: 400 }
      );
    }
    if (message.includes('not intended')) {
      return NextResponse.json(
        { success: false, error: 'This exchange was encrypted for someone else.' },
        { status: 403 }
      );
    }

    return NextResponse.json(
      { success: false, error: message },
      { status: 500 }
    );
  }
}
