// lib/storage-init.ts
import { mkdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';

export async function initializeStorage() {
  const baseDir = join(homedir(), '.soverentity');
  const contactsDir = join(baseDir, 'contacts');

  try {
    // Create base directory
    await mkdir(baseDir, { recursive: true });
    console.log(`Base directory created: ${baseDir}`);
    
    // Create contacts directory
    await mkdir(contactsDir, { recursive: true });
    console.log(`Contacts directory created: ${contactsDir}`);
    
    return {
      baseDir,
      contactsDir,
      success: true
    };
  } catch (error) {
    console.error('Failed to initialize storage directories:', error);
    return {
      baseDir,
      contactsDir,
      success: false,
      error
    };
  }
}