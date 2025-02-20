// app/api/simple-contacts/route.ts
import { NextResponse } from 'next/server';
import { RobustContactManager } from '@/lib/contacts/robust-db';
import { SoverentityIdentity } from '@/lib/identity/core';

const identityManager = new SoverentityIdentity();

// Memory storage for demo purposes
const inMemoryContacts: Record<string, any[]> = {};

// GET /api/simple-contacts?fingerprint=<user_fingerprint>
export async function GET(request: Request) {
  console.log('API route hit: /api/simple-contacts [GET]');
  
  try {
    // Get query parameters
    const url = new URL(request.url);
    const fingerprint = url.searchParams.get('fingerprint');
    
    if (!fingerprint) {
      return NextResponse.json(
        { success: false, error: 'Fingerprint is required' },
        { status: 400 }
      );
    }
    
    // Use in-memory storage as a fallback
    const contacts = inMemoryContacts[fingerprint] || [];
    
    console.log(`Found ${contacts.length} contacts for fingerprint ${fingerprint}`);
    return NextResponse.json({ 
      success: true, 
      contacts,
      storage: 'in-memory'
    });
    
  } catch (error) {
    console.error('Failed to get contacts:', error);
    return NextResponse.json(
      { 
        success: false, 
        error: error instanceof Error ? error.message : 'Failed to get contacts',
        errorType: error instanceof Error ? error.constructor.name : typeof error
      },
      { status: 500 }
    );
  }
}

// POST /api/simple-contacts
export async function POST(request: Request) {
  console.log('API route hit: /api/simple-contacts [POST]');
  
  try {
    const body = await request.json();
    console.log('Received request body:', body);
    
    const { fingerprint, contact } = body;
    
    if (!fingerprint || !contact) {
      return NextResponse.json(
        { success: false, error: 'Fingerprint and contact data are required' },
        { status: 400 }
      );
    }
    
    // Initialize in-memory storage if needed
    if (!inMemoryContacts[fingerprint]) {
      inMemoryContacts[fingerprint] = [];
    }
    
    // Create a new contact with ID
    const newContact = {
      ...contact,
      id: Math.random().toString(36).substring(2, 11),
      added_at: new Date().toISOString()
    };
    
    inMemoryContacts[fingerprint].push(newContact);
    
    return NextResponse.json({
      success: true,
      contact: newContact,
      storage: 'in-memory'
    });
    
  } catch (error) {
    console.error('Failed to add contact:', error);
    return NextResponse.json(
      { 
        success: false, 
        error: error instanceof Error ? error.message : 'Failed to add contact',
        errorType: error instanceof Error ? error.constructor.name : typeof error
      },
      { status: 500 }
    );
  }
}

// DELETE /api/simple-contacts?fingerprint=<fingerprint>&contactId=<contactId>
export async function DELETE(request: Request) {
  console.log('API route hit: /api/simple-contacts [DELETE]');
  
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
    
    // Check if we have contacts for this fingerprint
    if (!inMemoryContacts[fingerprint]) {
      return NextResponse.json(
        { success: false, error: 'No contacts found for this fingerprint' },
        { status: 404 }
      );
    }
    
    // Find and remove the contact
    const initialLength = inMemoryContacts[fingerprint].length;
    inMemoryContacts[fingerprint] = inMemoryContacts[fingerprint].filter(
      c => c.id !== contactId
    );
    
    if (inMemoryContacts[fingerprint].length === initialLength) {
      return NextResponse.json(
        { success: false, error: 'Contact not found' },
        { status: 404 }
      );
    }
    
    return NextResponse.json({
      success: true,
      message: 'Contact deleted successfully',
      storage: 'in-memory'
    });
    
  } catch (error) {
    console.error('Failed to delete contact:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to delete contact' },
      { status: 500 }
    );
  }
}