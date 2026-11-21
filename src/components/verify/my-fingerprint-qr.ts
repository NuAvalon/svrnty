// "My QR": a QR that holds the owner's own fingerprint and nothing else, so someone who has this person's card can check it in person with the Verify
// sheet (which already reads a bare fingerprint from a scan and compares it byte for byte to the one it stored). No network, no storage.

export const MY_QR_LABEL = 'My QR';
export const MY_QR_LINE = "This is only your fingerprint. Share it in person, or anywhere they'll know it's really you.";

/**
 * What the QR holds: the fingerprint, 64 lowercase hex, and nothing else. Anything else (a short stand-in, a wrong length, groups, a link, JSON,
 * a non-string) makes NO QR rather than a QR of something that is not a fingerprint.
 */
export function myQrPayload(fingerprint: unknown): string | null {
  if (typeof fingerprint !== 'string') return null;
  const trimmed = fingerprint.trim();
  return /^[0-9a-fA-F]{64}$/.test(trimmed) ? trimmed.toLowerCase() : null;
}
