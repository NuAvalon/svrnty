// app/api/relay/[code]/route.ts
// Retrieve a relay entry (the giver's opaque, key-fragment-encrypted identity card). Served for the
// code's TTL — MULTI-USE, not consume-on-view. One Grow link → N joiners up to GROW_INVITE_CAP. The
// entry is cleaned up by the POST's TTL
// timer at expiry, not on read.

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

    // Serve the card for the code's LIFETIME — do NOT consume-on-view. The anti-replay/anti-abuse is
    // enforced DOWNSTREAM at the joiner-response accept-oracle (isCodeOutstanding + codeUnderCap +
    // !alreadyAccepted per-(code,joinerFp)), so the relay's old single-use delete-on-read was REDUNDANT
    // with that AND was the bug: a 2nd opener — or the SPA double-fetching/re-mounting — got "expired" on
    // their FIRST open, breaking multi-person viral Grow. The card is the
    // giver's OWN identity (deliberately shared, key-fragment-gated), so serving it N times within the
    // TTL adds no exposure. The POST's setTimeout still deletes the entry at expiry.
    const { encrypted } = entry;
    return NextResponse.json({ encrypted });
  } catch (error) {
    console.error('Relay GET error:', error);
    return NextResponse.json(
      { error: 'Failed to retrieve relay.' },
      { status: 500 }
    );
  }
}
