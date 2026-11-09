// The next-authority-commitment ("pin") a signed identity card carries. No imports on purpose: the storage layer and the Gate use this check
// without taking the card-signing code with it.

/** The card's pin if it is canonical 64 lowercase hex, else null. */
export function canonicalAuthorityPin(v: unknown): string | null {
  return typeof v === 'string' && /^[0-9a-f]{64}$/.test(v) ? v : null;
}
