// app/api/fix-identity/route.ts
import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';
import { homedir } from 'os';
import { join } from 'path';
import { mkdir } from 'fs/promises';

export async function GET() {
  console.log('[GET /api/fix-identity] Attempting to fix identity issues');
  
  const fixes = {
    monkeyPatchAttempted: false,
    monkeyPatchSuccess: false,
    directoriesCreated: false
  };
  
  try {
    // 1. Try to monkey-patch the SoverentityIdentity class if needed
    const identity = new SoverentityIdentity();
    const prototype = Object.getPrototypeOf(identity);
    const methods = Object.getOwnPropertyNames(prototype);
    
    if (!methods.includes('loadKey')) {
      fixes.monkeyPatchAttempted = true;
      console.log('Attempting to monkey-patch SoverentityIdentity...');
      
      // This is a risky approach but can work in emergencies
      // It attempts to expose a properly working loadKey method
      try {
        // Find all methods that might be the load key function 
        const loadKeyMethods = methods.filter(method => 
          method.includes('load') && method.includes('Key')
        );
        
        console.log('Potential loadKey methods found:', loadKeyMethods);
        
        if (loadKeyMethods.length > 0) {
          // Try the first matching method
          (SoverentityIdentity.prototype as any).loadKey = prototype[loadKeyMethods[0]];
          fixes.monkeyPatchSuccess = true;
          console.log('Successfully monkey-patched loadKey method');
        } else {
          // Last resort: create our own loadKey implementation
          (SoverentityIdentity.prototype as any).loadKey = async function(fingerprint: string) {
            const storageDir = join(homedir(), '.soverentity');
            const keyPath = join(storageDir, `${fingerprint}.key`);
            
            // Import directly to avoid circular dependencies
            const { readFile } = await import('fs/promises');
            const data = await readFile(keyPath, 'utf8');
            return JSON.parse(data);
          };
          
          fixes.monkeyPatchSuccess = true;
          console.log('Created new loadKey implementation');
        }
      } catch (patchError) {
        console.error('Failed to monkey-patch:', patchError);
      }
    } else {
      console.log('loadKey method already exists, no patch needed');
    }
    
    // 2. Create necessary directories
    try {
      const baseDir = join(homedir(), '.soverentity');
      const contactsDir = join(baseDir, 'contacts');
      
      await mkdir(baseDir, { recursive: true });
      await mkdir(contactsDir, { recursive: true });
      
      fixes.directoriesCreated = true;
      console.log('Storage directories created');
    } catch (dirError) {
      console.error('Failed to create directories:', dirError);
    }
    
    return NextResponse.json({
      success: true,
      fixes,
      message: 'Fix attempts completed'
    });
    
  } catch (error) {
    console.error('[GET /api/fix-identity] Error:', error);
    return NextResponse.json({
      success: false,
      fixes,
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}