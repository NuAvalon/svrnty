// src/lib/sync/relay.ts
// Client-side shortcode relay: encrypt locally, dead-drop via server, decrypt locally.
// The AES-256-GCM key travels only in the URL fragment — never reaches the server.
//
// Domain is parameterized via src/lib/config/domain (NEXT_PUBLIC_SVRNTY_DOMAIN, default
// svrnty.is) so a self-hoster's share links point at THEIR domain — no code fork.

import { shareUrl } from '@/lib/config/domain';

/**
 * Base64url encode (URL-safe, no padding)
 */
function toBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Base64url decode (URL-safe, no padding)
 */
function fromBase64url(str: string): Uint8Array {
  // Restore standard base64
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export interface RelayResult {
  /** Full URL: https://{domain}/c/{code}#{base64url_key} (domain per NEXT_PUBLIC_SVRNTY_DOMAIN, default svrnty.is) */
  url: string;
  /** The 6-char shortcode */
  code: string;
  /** When the relay entry expires */
  expiresAt: string;
}

/**
 * Create a relay: encrypt an exchange package and POST the blob.
 * Returns a URL with the decryption key in the fragment (never sent to server).
 */
export async function createRelay(exchangePackage: string): Promise<RelayResult> {
  // Generate a random 256-bit AES key
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true, // extractable — we need to encode it into the URL
    ['encrypt', 'decrypt']
  );

  // Encrypt the exchange package
  const encoder = new TextEncoder();
  const plaintext = encoder.encode(exchangePackage);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintext
  );

  // Pack: iv(12) + ciphertext
  const packed = new Uint8Array(12 + ciphertext.byteLength);
  packed.set(iv, 0);
  packed.set(new Uint8Array(ciphertext), 12);

  // Base64-encode the encrypted blob for JSON transport
  const encrypted = toBase64url(packed.buffer);

  // POST to relay
  const res = await fetch('/api/relay', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ encrypted }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Relay request failed' }));
    throw new Error(err.error || `Relay POST failed: ${res.status}`);
  }

  const { code, expiresAt } = await res.json();

  // Export the raw key bytes and encode as base64url for the fragment
  const rawKey = await crypto.subtle.exportKey('raw', key);
  const keyFragment = toBase64url(rawKey);

  return {
    url: shareUrl(code, keyFragment),
    code,
    expiresAt,
  };
}

/**
 * Resolve a relay: fetch the encrypted blob and decrypt with the key from the URL fragment.
 */
export async function resolveRelay(code: string, keyFragment: string): Promise<string> {
  // Fetch the encrypted blob (single-use — server deletes it)
  const res = await fetch(`/api/relay/${encodeURIComponent(code)}`);

  if (!res.ok) {
    if (res.status === 404) {
      throw new Error('This link has expired or already been used.');
    }
    const err = await res.json().catch(() => ({ error: 'Relay request failed' }));
    throw new Error(err.error || `Relay GET failed: ${res.status}`);
  }

  const { encrypted } = await res.json();

  // Decode the key from the URL fragment
  const rawKey = fromBase64url(keyFragment);
  const key = await crypto.subtle.importKey(
    'raw',
    rawKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  // Decode and unpack the encrypted blob
  const packed = fromBase64url(encrypted);
  const iv = packed.slice(0, 12);
  const ciphertext = packed.slice(12);

  // Decrypt
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );

  const decoder = new TextDecoder();
  return decoder.decode(plaintext);
}
