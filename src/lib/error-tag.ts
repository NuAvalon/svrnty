// src/lib/error-tag.ts
// The log tag for an UNKNOWN error: its class name and code, nothing else. Never the message, never the stack, never the object (a JSON parse error can quote the pasted text).
// A leaf module on purpose (no imports): a screen that only needs this tag must not pull crypto or import code into its bundle.
// Run: npx tsx --test src/lib/contacts/contact-io-errors.test.ts src/lib/error-tag.test.ts
const SAFE = /[^A-Za-z0-9_.:-]/g;
const part = (v: unknown): string => (typeof v === 'string' ? v.replace(SAFE, '').slice(0, 40) : '');

export function errorTag(err: unknown): string {
  if (!err || typeof err !== 'object') return typeof err;
  const o = err as { name?: unknown; code?: unknown };
  return [part(o.name) || 'Error', part(o.code)].filter(Boolean).join(':');
}
