/**
 * Local-only drafts for Signal / Site until contact.update allowlist grows.
 * Email stays on identity.identity.email (existing field).
 * Never put this bag on the wire — local UX only.
 */

export type LocalMethodsBag = {
  signal?: string;
  site?: string;
};

const keyFor = (fingerprint: string) =>
  `svrnty.local-methods.${fingerprint.replace(/[^0-9a-fA-F]/g, '').toLowerCase()}`;

export function loadLocalMethods(fingerprint: string): LocalMethodsBag {
  if (typeof window === 'undefined') return {};
  try {
    const raw = localStorage.getItem(keyFor(fingerprint));
    if (!raw) return {};
    const parsed = JSON.parse(raw) as LocalMethodsBag;
    return {
      signal: typeof parsed.signal === 'string' ? parsed.signal : undefined,
      site: typeof parsed.site === 'string' ? parsed.site : undefined,
    };
  } catch {
    return {};
  }
}

export function saveLocalMethods(fingerprint: string, patch: LocalMethodsBag): LocalMethodsBag {
  const next = { ...loadLocalMethods(fingerprint), ...patch };
  // Drop empty strings
  if (next.signal !== undefined && !next.signal.trim()) delete next.signal;
  if (next.site !== undefined && !next.site.trim()) delete next.site;
  localStorage.setItem(keyFor(fingerprint), JSON.stringify(next));
  return next;
}
