// app/api/identity/check/route.ts — Check if an identity exists without exposing it
import { NextResponse } from 'next/server';
import { readdir, readFile } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';

export async function GET() {
  try {
    const storageDir = join(homedir(), '.soverentity');
    const files = await readdir(storageDir).catch(() => []);

    // Look for identity.json files in fingerprint directories
    const identities: Array<{ name: string; fingerprint: string; hasPassphrase: boolean }> = [];

    for (const dir of files) {
      const identityPath = join(storageDir, dir, 'identity.json');
      try {
        const data = JSON.parse(await readFile(identityPath, 'utf-8'));
        const lockPath = join(storageDir, dir, 'lock.json');
        let hasPassphrase = false;
        try {
          await readFile(lockPath, 'utf-8');
          hasPassphrase = true;
        } catch {}

        identities.push({
          name: data.identity?.name || 'Unknown',
          fingerprint: dir,
          hasPassphrase,
        });
      } catch {
        // Not an identity directory
      }
    }

    return NextResponse.json({
      exists: identities.length > 0,
      identities,
    });
  } catch {
    return NextResponse.json({ exists: false, identities: [] });
  }
}
