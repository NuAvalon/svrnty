// Allowlist for the same-origin PSI proxy body. Device-local tags / blocked
// flags / group labels must never be copied onto the satellite request.

export const PSI_BODY_KEYS = [
  'initiator_fingerprint',
  'responder_fingerprint',
  'blinded_set',
  'reblinded_initiator_set',
  'signature',
] as const;

export function pickPsiBody(raw: Record<string, unknown>): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  for (const key of PSI_BODY_KEYS) {
    if (!(key in raw)) continue;
    const value = raw[key];
    if (typeof value === 'string' && value.length <= 8192) body[key] = value;
    else if (Array.isArray(value) && value.every((x) => typeof x === 'string')) {
      body[key] = value.slice(0, 4096);
    }
  }
  return body;
}
