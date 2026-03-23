// app/api/identity/unlock/route.ts — Unlock identity with passphrase
import { NextResponse } from 'next/server';
import { readFile } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { createHash, timingSafeEqual } from 'crypto';

export async function POST(request: Request) {
  try {
    const { fingerprint, passphrase } = await request.json();

    if (!fingerprint || !passphrase) {
      return NextResponse.json({ error: 'Fingerprint and passphrase required' }, { status: 400 });
    }

    const storageDir = join(homedir(), '.soverentity', fingerprint);
    const lockPath = join(storageDir, 'lock.json');

    try {
      const lockData = JSON.parse(await readFile(lockPath, 'utf-8'));
      const hash = createHash('sha256').update(passphrase + lockData.salt).digest('hex');
      const expected = Buffer.from(lockData.hash, 'hex');
      const actual = Buffer.from(hash, 'hex');

      if (!timingSafeEqual(expected, actual)) {
        return NextResponse.json({ error: 'Incorrect passphrase' }, { status: 401 });
      }
    } catch {
      // No lock file — identity is unlocked
    }

    // Load and return the full identity
    const identityPath = join(storageDir, 'identity.json');
    const identity = JSON.parse(await readFile(identityPath, 'utf-8'));

    return NextResponse.json({ success: true, identity });
  } catch (error) {
    return NextResponse.json({ error: 'Failed to unlock identity' }, { status: 500 });
  }
}
