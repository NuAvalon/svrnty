// app/api/relay/[code]/route.ts
// Retrieve and destroy a relay entry. Single-use: the blob is deleted on read.

import { NextResponse } from 'next/server';

// Import the store from the parent route module.
// In Next.js edge/serverless, module-level state is shared within the same
// runtime instance. For production, this would use Redis or similar.
// For now, we co-locate the store definition.

interface RelayEntry {
  encrypted: string;
  expiresAt: number;
  timer: ReturnType<typeof setTimeout>;
}

// This store must be the same instance as in ../route.ts.
// We achieve this with a global reference since Next.js may isolate route modules.
declare global {
  // eslint-disable-next-line no-var
  var __relayStore: Map<string, RelayEntry> | undefined;
}

function getStore(): Map<string, RelayEntry> {
  if (!globalThis.__relayStore) {
    globalThis.__relayStore = new Map();
  }
  return globalThis.__relayStore;
}

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ code: string }> }
) {
  try {
    const { code } = await params;
    const store = getStore();
    const entry = store.get(code);

    if (!entry) {
      return NextResponse.json(
        { error: 'Link expired or not found' },
        { status: 404 }
      );
    }

    // Check TTL (belt-and-suspenders — timer should have cleaned it up)
    if (Date.now() > entry.expiresAt) {
      clearTimeout(entry.timer);
      store.delete(code);
      return NextResponse.json(
        { error: 'Link expired or not found' },
        { status: 404 }
      );
    }

    // Single use: read and destroy
    const { encrypted } = entry;
    clearTimeout(entry.timer);
    store.delete(code);

    return NextResponse.json({ encrypted });
  } catch (error) {
    console.error('Relay GET error:', error);
    return NextResponse.json(
      { error: 'Failed to retrieve relay.' },
      { status: 500 }
    );
  }
}
