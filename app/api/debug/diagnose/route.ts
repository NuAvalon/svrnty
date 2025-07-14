// app/api/debug/diagnose/route.ts
import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';
import { readdir, access, stat, readFile } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';

const identityManager = new SoverentityIdentity();

export async function GET() {
  console.log('🔍 Running diagnostic check...');
  
  const results = {
    storageDir: '',
    directoryExists: false,
    identityFiles: 0,
    keyFiles: 0,
    contactFiles: 0,
    identities: [] as any[],
    managerTest: {
      canLoadIdentity: false,
      canLoadKeys: false,
      error: undefined as string | undefined
    }
  };

  try {
    // Check storage directory
    const storageDir = join(homedir(), '.soverentity');
    results.storageDir = storageDir;
    
    console.log('📁 Checking storage directory:', storageDir);
    
    try {
      await access(storageDir);
      results.directoryExists = true;
      console.log('✅ Storage directory exists');
      
      // List files in storage directory
      const files = await readdir(storageDir);
      console.log('📂 Files in storage directory:', files.length);
      
      const identityFiles = files.filter(f => f.endsWith('.json'));
      const keyFiles = files.filter(f => f.endsWith('.key'));
      const contactFiles = files.filter(f => f.includes('.contacts.'));
      
      results.identityFiles = identityFiles.length;
      results.keyFiles = keyFiles.length;
      results.contactFiles = contactFiles.length;
      
      console.log('  - Identity files (.json):', identityFiles.length);
      console.log('  - Key files (.key):', keyFiles.length);
      console.log('  - Contact files:', contactFiles.length);
      
      // Analyze each identity file
      for (const file of identityFiles) {
        console.log(`\n🆔 Analyzing identity file: ${file}`);
        const fingerprint = file.replace('.json', '');
        
        const identityInfo = {
          fingerprint,
          name: 'Unknown',
          email: 'Unknown',
          verificationStatus: 'Unknown',
          hasKeyFile: false,
          hasContactFile: false,
          issues: [] as string[]
        };
        
        try {
          const filePath = join(storageDir, file);
          const fileStats = await stat(filePath);
          console.log('   File size:', fileStats.size, 'bytes');
          
          if (fileStats.size === 0) {
            identityInfo.issues.push('Identity file is empty');
          }
          
          // Try to read and parse the identity
          const content = await readFile(filePath, 'utf8');
          const identity = JSON.parse(content);
          
          identityInfo.name = identity.identity?.name || 'Unknown';
          identityInfo.email = identity.identity?.email || 'Unknown';
          identityInfo.verificationStatus = identity.verification?.status || 'Unknown';
          
          console.log('   Identity name:', identityInfo.name);
          console.log('   Identity email:', identityInfo.email);
          console.log('   Verification status:', identityInfo.verificationStatus);
          
          // Check for corresponding key file
          const keyFile = `${fingerprint}.key`;
          if (keyFiles.includes(keyFile)) {
            identityInfo.hasKeyFile = true;
            console.log('   ✅ Key file exists');
            
            try {
              const keyPath = join(storageDir, keyFile);
              const keyContent = await readFile(keyPath, 'utf8');
              const keyData = JSON.parse(keyContent);
              
              if (!keyData.privateKey) {
                identityInfo.issues.push('Key file missing private key');
              }
              if (!keyData.passphrase) {
                identityInfo.issues.push('Key file missing passphrase');
              }
              
              console.log('   ✅ Key file is valid');
            } catch (keyError) {
              console.log('   ❌ Key file is corrupted:', keyError);
              identityInfo.issues.push('Key file is corrupted');
            }
          } else {
            console.log('   ❌ Missing key file');
            identityInfo.issues.push('Missing key file');
          }
          
          // Check for corresponding contact file
          const contactFile = `${fingerprint}.contacts.enc`;
          if (contactFiles.some(f => f.includes(fingerprint))) {
            identityInfo.hasContactFile = true;
            console.log('   ✅ Contact file exists');
          } else {
            console.log('   ⚠️  No contact file found (this is normal for new identities)');
          }
          
        } catch (parseError) {
          console.log('   ❌ Failed to parse identity file:', parseError);
          identityInfo.issues.push(`Failed to parse: ${parseError}`);
        }
        
        results.identities.push(identityInfo);
      }
      
      // Test identity manager
      console.log('\n🧪 Testing Identity Manager...');
      
      if (identityFiles.length > 0) {
        const testFingerprint = identityFiles[0].replace('.json', '');
        console.log('Testing with fingerprint:', testFingerprint);
        
        try {
          const identity = await identityManager.loadIdentityData(testFingerprint);
          results.managerTest.canLoadIdentity = true;
          console.log('✅ Identity manager can load identity');
          console.log('   Name:', identity.identity.name);
          console.log('   Email:', identity.identity.email);
          
          try {
            const keyData = await identityManager.loadKey(testFingerprint);
            results.managerTest.canLoadKeys = true;
            console.log('✅ Identity manager can load keys');
          } catch (keyError) {
            console.log('❌ Identity manager cannot load keys:', keyError);
            results.managerTest.error = `Key loading failed: ${keyError}`;
          }
          
        } catch (identityError) {
          console.log('❌ Identity manager cannot load identity:', identityError);
          results.managerTest.error = `Identity loading failed: ${identityError}`;
        }
      } else {
        console.log('⚠️  No identity files to test with');
        results.managerTest.error = 'No identity files found to test';
      }
      
    } catch (dirError) {
      console.log('❌ Storage directory does not exist or is not accessible:', dirError);
      results.managerTest.error = `Storage directory error: ${dirError}`;
    }
    
    console.log('\n📋 Diagnostic complete');
    
    return NextResponse.json(results);
    
  } catch (error) {
    console.error('❌ Diagnostic failed:', error);
    return NextResponse.json(
      { 
        error: 'Diagnostic failed',
        details: error instanceof Error ? error.message : 'Unknown error',
        results 
      },
      { status: 500 }
    );
  }
}