// Device-local "this book has redeemed" flag. Never a wire / publish / PSI field.
// Keyed by fingerprint so two books on one device do not share the bit.

const PREFIX = 'svrnty.beta-messaging.claimed:';

function storage(): Storage | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

export function localClaimStorageKey(fingerprint: string): string {
  return PREFIX + String(fingerprint || '').trim().toLowerCase();
}

export function readLocalBetaClaimed(fingerprint: string): boolean {
  const fp = String(fingerprint || '').trim();
  if (!fp) return false;
  const s = storage();
  if (!s) return false;
  try {
    return s.getItem(localClaimStorageKey(fp)) === '1';
  } catch {
    return false;
  }
}

export function writeLocalBetaClaimed(fingerprint: string): void {
  const fp = String(fingerprint || '').trim();
  if (!fp) return;
  const s = storage();
  if (!s) return;
  try {
    s.setItem(localClaimStorageKey(fp), '1');
  } catch {
    // quota / private-mode — session still shows post-redeem from React state
  }
}
