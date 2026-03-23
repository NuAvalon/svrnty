// app/api/identity/lock/route.ts — Set/update passphrase for identity
import { NextResponse } from 'next/server';
import { writeFile } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { createHash, randomBytes } from 'crypto';

export async function POST(request: Request) {
  try {
    const { fingerprint, passphrase } = await request.json();

    if (!fingerprint || !passphrase) {
      return NextResponse.json({ error: 'Fingerprint and passphrase required' }, { status: 400 });
    }

    if (passphrase.length < 4) {
      return NextResponse.json({ error: 'Passphrase must be at least 4 characters' }, { status: 400 });
    }

    const salt = randomBytes(32).toString('hex');
    const hash = createHash('sha256').update(passphrase + salt).digest('hex');

    const lockPath = join(homedir(), '.soverentity', fingerprint, 'lock.json');
    await writeFile(lockPath, JSON.stringify({ hash, salt, created_at: new Date().toISOString() }));

    return NextResponse.json({ success: true });
  } catch (error) {
    return NextResponse.json({ error: 'Failed to set passphrase' }, { status: 500 });
  }
}
