// app/api/relay/route.ts
// Shortcode relay: encrypted dead drop for identity exchange packages.
// Client encrypts with AES-256-GCM before sending. Server only stores opaque blobs.

import { NextResponse } from 'next/server';

// --- In-memory relay store (shared via globalThis with [code]/route.ts) ---
interface RelayEntry {
  encrypted: string;
  expiresAt: number;
  timer: ReturnType<typeof setTimeout>;
}

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

const store = getStore();

// --- Rate limiting ---
const rateLimits = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT_MAX = 10;
const RATE_LIMIT_WINDOW_MS = 60_000;

// Safe alphabet: no 0, O, l, I, 1
const ALPHABET = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const CODE_LENGTH = 6;
const TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days — the Grow card's share window. Aligns with the
// code's ~7d acceptance window (client-store R1_ACCEPTANCE_WINDOW_MS) so a friend opening a shared link
// hours/days later still retrieves the card (multi-use viral Grow; Peter #125734). The card is opaque
// (AES-GCM, #key in the URL fragment), so a longer window adds no server-readable exposure.
const MAX_PAYLOAD_BYTES = 64 * 1024; // 64KB

function generateCode(): string {
  // Rejection sampling to avoid modulo bias (ALPHABET.length=55, 256%55≠0)
  const limit = 256 - (256 % ALPHABET.length); // 256 - (256%55) = 256-36 = 220
  let code = '';
  while (code.length < CODE_LENGTH) {
    const bytes = new Uint8Array(CODE_LENGTH); // overallocate is fine
    crypto.getRandomValues(bytes);
    for (let i = 0; i < bytes.length && code.length < CODE_LENGTH; i++) {
      if (bytes[i] < limit) {
        code += ALPHABET[bytes[i] % ALPHABET.length];
      }
    }
  }
  // Collision check — regenerate if taken (extremely unlikely)
  if (store.has(code)) return generateCode();
  return code;
}

function getClientIP(request: Request): string {
  const forwarded = request.headers.get('x-forwarded-for');
  if (forwarded) return forwarded.split(',')[0].trim();
  const real = request.headers.get('x-real-ip');
  if (real) return real;
  return 'unknown';
}

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimits.get(ip);

  if (!entry || now > entry.resetAt) {
    rateLimits.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return true;
  }

  if (entry.count >= RATE_LIMIT_MAX) {
    return false;
  }

  entry.count++;
  return true;
}

export async function POST(request: Request) {
  try {
    // Check content length before parsing
    const contentLength = request.headers.get('content-length');
    if (contentLength && parseInt(contentLength, 10) > MAX_PAYLOAD_BYTES) {
      return NextResponse.json(
        { error: 'Payload too large. Max 64KB.' },
        { status: 413 }
      );
    }

    // Rate limit
    const ip = getClientIP(request);
    if (!checkRateLimit(ip)) {
      return NextResponse.json(
        { error: 'Rate limit exceeded. Max 10 relays per minute.' },
        { status: 429 }
      );
    }

    const body = await request.json();
    const { encrypted } = body;

    if (!encrypted || typeof encrypted !== 'string') {
      return NextResponse.json(
        { error: 'Missing or invalid "encrypted" field.' },
        { status: 400 }
      );
    }

    // Validate size after parsing (base64 string length)
    if (encrypted.length > MAX_PAYLOAD_BYTES) {
      return NextResponse.json(
        { error: 'Encrypted payload too large. Max 64KB.' },
        { status: 413 }
      );
    }

    const code = generateCode();
    const expiresAt = Date.now() + TTL_MS;

    // Auto-cleanup after TTL
    const timer = setTimeout(() => {
      store.delete(code);
    }, TTL_MS);

    store.set(code, { encrypted, expiresAt, timer });

    return NextResponse.json({
      code,
      expiresAt: new Date(expiresAt).toISOString(),
    });
  } catch (error) {
    console.error('Relay POST error:', error);
    return NextResponse.json(
      { error: 'Failed to create relay.' },
      { status: 500 }
    );
  }
}
