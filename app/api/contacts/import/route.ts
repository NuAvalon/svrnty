// app/api/contacts/import/route.ts
import { NextResponse } from 'next/server';
import { ContactManager } from '@/lib/contacts/db';
import { SoverentityIdentity } from '@/lib/identity/core';

const identityManager = new SoverentityIdentity();

async function getContactManager(fingerprint: string) {
  const identity = await identityManager.loadIdentityData(fingerprint);
  if (!identity) {
    throw new Error('Identity not found');
  }

  const keyData = await identityManager.loadKey(fingerprint);

  return new ContactManager({
    userFingerprint: fingerprint,
    userPublicKey: identity.identity.public_key,
    userPrivateKey: keyData.privateKey,
    userPassphrase: keyData.passphrase
  });
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
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
