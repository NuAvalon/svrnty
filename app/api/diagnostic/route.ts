// app/api/diagnostic/route.ts
import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';
import { homedir } from 'os';
import { join } from 'path';
import { readdir, stat, access, constants } from 'fs/promises';

export async function GET() {
  console.log('[GET /api/diagnostic] Running diagnostics');
  
  try {
    // Check if SoverentityIdentity class has required methods
    const identity = new SoverentityIdentity();
    const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(identity));
    
    // Check if loadKey is available and its accessibility
    const hasPublicLoadKey = methods.includes('loadKey');
    let loadKeyAccessible = false;
    
    try {
      if (hasPublicLoadKey) {
        // Test if the method can be called (we don't need a valid result)
        const testMethod = identity.loadKey;
        loadKeyAccessible = typeof testMethod === 'function';
      }
    } catch (e) {
      console.error('Error checking loadKey accessibility:', e);
    }
    
    // Check storage directories
    const baseDir = join(homedir(), '.soverentity');
    const contactsDir = join(baseDir, 'contacts');
    
    let baseDirExists = false;
    let contactsDirExists = false;
    let baseDirContents = [];
    let baseDirWritable = false;
    let contactsDirWritable = false;
    
    try {
      const baseStat = await stat(baseDir);
      baseDirExists = baseStat.isDirectory();
      if (baseDirExists) {
        baseDirContents = await readdir(baseDir);
        // Check if directory is writable
        await access(baseDir, constants.W_OK);
        baseDirWritable = true;
      }
    } catch (error) {
      console.log('Base directory does not exist or is not writable');
    }
    
    try {
      const contactsStat = await stat(contactsDir);
      contactsDirExists = contactsStat.isDirectory();
      // Check if directory is writable
      await access(contactsDir, constants.W_OK);
      contactsDirWritable = true;
    } catch (error) {
      console.log('Contacts directory does not exist or is not writable');
    }
    
    // Try to find any existing identity files for testing
    let identityFiles = [];
    if (baseDirExists) {
      try {
        identityFiles = (await readdir(baseDir))
          .filter(file => file.endsWith('.json') || file.endsWith('.key'))
          .map(file => ({
            name: file,
            fingerprint: file.split('.')[0],
            type: file.endsWith('.json') ? 'identity' : 'key'
          }));
      } catch (e) {
        console.error('Error reading identity files:', e);
      }
    }
    
    return NextResponse.json({
      success: true,
      identity: {
        methods,
        hasLoadKey: hasPublicLoadKey,
        loadKeyAccessible,
        hasLoadIdentityData: methods.includes('loadIdentityData'),
        allMethods: methods
      },
      storage: {
        baseDir,
        contactsDir,
        baseDirExists,
        contactsDirExists,
        baseDirContents,
        baseDirWritable,
        contactsDirWritable,
        identityFiles
      },
      environment: {
        node_env: process.env.NODE_ENV,
        platform: process.platform
      }
    });
    
  } catch (error) {
    console.error('[GET /api/diagnostic] Error:', error);
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      errorType: error instanceof Error ? error.constructor.name : typeof error
    });
  }
}