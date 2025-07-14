// app/api/identity/route.ts
import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';
import { mkdir, access } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';

const identityManager = new SoverentityIdentity();

// Helper function to ensure storage directory exists
async function ensureStorageDirectory(): Promise<string> {
  const storageDir = join(homedir(), '.soverentity');
  try {
    await mkdir(storageDir, { recursive: true });
    console.log('✅ Storage directory ensured:', storageDir);
    return storageDir;
  } catch (error) {
    console.error('❌ Failed to create storage directory:', error);
    throw error;
  }
}

// POST - Create new identity
export async function POST(request: Request) {
  console.log('🔍 API route hit: /api/identity [POST]');
  
  try {
    const body = await request.json();
    const { name, email } = body;
    
    console.log('📝 Creating identity for:', { name, email });
    
    if (!name || !email) {
      return NextResponse.json(
        { error: 'Name and email are required' },
        { status: 400 }
      );
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return NextResponse.json(
        { error: 'Invalid email format' },
        { status: 400 }
      );
    }

    // Ensure storage directory exists
    const storageDir = await ensureStorageDirectory();
    console.log('📁 Using storage directory:', storageDir);

    try {
      // Generate the identity
      console.log('🔑 Generating new identity...');
      const result = await identityManager.generateIdentity({ name, email });
      
      console.log('✅ Identity generated successfully');
      console.log('🆔 Fingerprint:', result.fingerprint);
      console.log('👤 Name:', result.identity.identity.name);
      console.log('📧 Email:', result.identity.identity.email);
      
      // Verify the files were created
      try {
        const identityPath = join(storageDir, `${result.fingerprint}.json`);
        const keyPath = join(storageDir, `${result.fingerprint}.key`);
        
        await access(identityPath);
        await access(keyPath);
        
        console.log('✅ Identity files verified on disk');
        console.log('📄 Identity file:', identityPath);
        console.log('🔐 Key file:', keyPath);
        
      } catch (verifyError) {
        console.error('⚠️ Warning: Could not verify identity files on disk:', verifyError);
        // Continue anyway, as the identity was created in memory
      }

      return NextResponse.json({
        success: true,
        identity: result.identity,
        fingerprint: result.fingerprint,
        message: 'Identity created successfully'
      });

    } catch (generateError) {
      console.error('❌ Failed to generate identity:', generateError);
      
      // Provide specific error details
      if (generateError instanceof Error) {
        if (generateError.message.includes('EACCES')) {
          return NextResponse.json(
            { 
              error: 'Permission denied when creating identity files',
              details: 'Check file system permissions for the storage directory',
              storageDir
            },
            { status: 500 }
          );
        }
        
        if (generateError.message.includes('ENOSPC')) {
          return NextResponse.json(
            { 
              error: 'Insufficient disk space to create identity',
              details: 'Free up disk space and try again'
            },
            { status: 500 }
          );
        }
      }
      
      return NextResponse.json(
        { 
          error: 'Failed to generate identity',
          details: generateError instanceof Error ? generateError.message : 'Unknown error'
        },
        { status: 500 }
      );
    }

  } catch (error) {
    console.error('❌ Failed to create identity:', error);
    return NextResponse.json(
      { 
        error: 'Failed to create identity',
        details: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    );
  }
}

// GET - Load existing identity by fingerprint
export async function GET(request: Request) {
  console.log('🔍 API route hit: /api/identity [GET]');
  
  try {
    const url = new URL(request.url);
    const fingerprint = url.searchParams.get('fingerprint');
    
    if (!fingerprint) {
      return NextResponse.json(
        { error: 'Fingerprint is required' },
        { status: 400 }
      );
    }

    console.log('📋 Loading identity for fingerprint:', fingerprint);

    try {
      const identity = await identityManager.loadIdentityData(fingerprint);
      
      if (!identity) {
        return NextResponse.json(
          { error: 'Identity not found' },
          { status: 404 }
        );
      }

      console.log('✅ Identity loaded successfully');
      
      return NextResponse.json({
        success: true,
        identity,
        fingerprint
      });

    } catch (loadError) {
      console.error('❌ Failed to load identity:', loadError);
      
      if (loadError instanceof Error && loadError.message.includes('ENOENT')) {
        return NextResponse.json(
          { 
            error: 'Identity file not found',
            details: `No identity file exists for fingerprint: ${fingerprint}`,
            suggestion: 'Create a new identity or check the fingerprint'
          },
          { status: 404 }
        );
      }
      
      return NextResponse.json(
        { 
          error: 'Failed to load identity',
          details: loadError instanceof Error ? loadError.message : 'Unknown error'
        },
        { status: 500 }
      );
    }

  } catch (error) {
    console.error('❌ Failed to process identity request:', error);
    return NextResponse.json(
      { 
        error: 'Failed to process identity request',
        details: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    );
  }
}