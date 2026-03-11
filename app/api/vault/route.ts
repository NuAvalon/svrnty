// app/api/vault/route.ts
// Vault API — export and import unified .svrnty vault files.
// GET: export current identity + trust graph as encrypted vault
// POST: import a vault (decrypt server-side, hydrate identity + contacts)

import { NextResponse } from 'next/server';
import { SoverentityIdentity } from '@/lib/identity/core';
import { RobustContactManager } from '@/lib/contacts/robust-db';
import { readFile, writeFile } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';

const identityManager = new SoverentityIdentity();

// GET /api/vault?fingerprint=...&safeWord=...
// Returns the data needed to build a vault file client-side.
// The actual encryption happens in the browser (client-side).
export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const fingerprint = searchParams.get('fingerprint');
    const safeWord = searchParams.get('safeWord') || '';

    if (!fingerprint) {
      return NextResponse.json({ error: 'fingerprint required' }, { status: 400 });
    }

    // Load identity
    const identity = await identityManager.loadIdentityData(fingerprint);
    if (!identity) {
      return NextResponse.json({ error: 'Identity not found' }, { status: 404 });
    }

    // Load keys
    const keyData = await identityManager.loadKey(fingerprint);
    let pqKeys = null;
    try {
      const pqBundle = await identityManager.loadPQKeys(fingerprint);
      if (pqBundle) {
        // Serialize for vault (already has a serialize function in the codebase)
        const { serializeKeypairBundle } = await import('@/lib/crypto/pq');
        pqKeys = serializeKeypairBundle(pqBundle);
      }
    } catch {
      // PQ keys may not exist for v1 identities
    }

    // Load trust graph
    let trustGraph = null;
    try {
      const storageDir = join(homedir(), '.soverentity');
      const trustPath = join(storageDir, `${fingerprint}.trust.enc`);
      // Try to read the encrypted trust graph
      // It's encrypted with the user's PGP key, so we need to decrypt server-side
      const contactManager = new RobustContactManager(
        fingerprint,
        identity.identity.public_key,
        keyData.privateKey,
        keyData.passphrase
      );
      const contacts = await contactManager.getAllContacts();
      trustGraph = {
        version: '2.0.0',
        owner_fingerprint: fingerprint,
        edges: contacts || [],
        tribes: [],
        settings: { default_decay_days: 730 },
        stats: {
          total_contacts: contacts?.length || 0,
          trusted_count: contacts?.filter((c: any) => c.trusted)?.length || 0,
          known_count: contacts?.filter((c: any) => !c.trusted)?.length || 0,
          decayed_count: 0,
          last_modified: new Date().toISOString(),
        },
      };
    } catch {
      // No trust graph yet — empty
      trustGraph = {
        version: '2.0.0',
        owner_fingerprint: fingerprint,
        edges: [],
        tribes: [],
        settings: { default_decay_days: 730 },
        stats: {
          total_contacts: 0,
          trusted_count: 0,
          known_count: 0,
          decayed_count: 0,
          last_modified: new Date().toISOString(),
        },
      };
    }

    // Load vault recovery data
    let recovery = null;
    try {
      recovery = await identityManager.loadVault(fingerprint);
    } catch {
      // No vault recovery data
    }

    // Return the vault contents (will be encrypted client-side)
    return NextResponse.json({
      identity,
      keys: {
        classical: keyData,
        pq: pqKeys,
      },
      trustGraph,
      settings: {
        defaultDecayDays: 730,
        safeWord,
      },
      recovery,
    });
  } catch (error) {
    console.error('Vault export error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to export vault' },
      { status: 500 }
    );
  }
}

// POST /api/vault
// Import vault contents (already decrypted client-side).
// Hydrates identity, keys, and contacts on the server.
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { identity, keys, trustGraph, recovery } = body;

    if (!identity?.identity?.fingerprint) {
      return NextResponse.json({ error: 'Invalid vault data: missing identity' }, { status: 400 });
    }

    const fingerprint = identity.identity.fingerprint;
    const storageDir = join(homedir(), '.soverentity');

    // Store identity
    await writeFile(
      join(storageDir, `${fingerprint}.json`),
      JSON.stringify(identity, null, 2)
    );

    // Store classical keys
    if (keys?.classical) {
      await writeFile(
        join(storageDir, `${fingerprint}.key`),
        JSON.stringify(keys.classical)
      );
    }

    // Store PQ keys
    if (keys?.pq) {
      await writeFile(
        join(storageDir, `${fingerprint}.pq.key`),
        JSON.stringify(keys.pq)
      );
    }

    // Store recovery vault
    if (recovery) {
      await writeFile(
        join(storageDir, `${fingerprint}.vault`),
        JSON.stringify(recovery, null, 2)
      );
    }

    // Restore contacts from trust graph edges
    let contactCount = 0;
    if (trustGraph?.edges?.length > 0 && keys?.classical) {
      try {
        const contactManager = new RobustContactManager(
          fingerprint,
          identity.identity.public_key,
          keys.classical.privateKey,
          keys.classical.passphrase
        );

        for (const edge of trustGraph.edges) {
          try {
            await contactManager.addContact(edge);
            contactCount++;
          } catch {
            // Contact might already exist — skip
          }
        }
      } catch (err) {
        console.error('Failed to restore some contacts:', err);
      }
    }

    return NextResponse.json({
      success: true,
      fingerprint,
      contactsRestored: contactCount,
    });
  } catch (error) {
    console.error('Vault import error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to import vault' },
      { status: 500 }
    );
  }
}
