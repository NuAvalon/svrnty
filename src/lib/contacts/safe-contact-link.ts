// src/lib/contacts/safe-contact-link.ts
// CUR-3 · L1g deep-linked contact methods — PURE frontend, zero crypto.
//
// I-10a render-safety: fields from an IMPORTED contact are untrusted.
// Only scheme-allowlisted hrefs become clickable links. Everything else
// renders as inert text (never javascript:/data:).

/** Display char budget for imported contact-method strings (I-10a bound). */
export const CONTACT_METHOD_DISPLAY_MAX = 200;

const ALLOWED_SCHEMES = new Set(['https:', 'tel:', 'mailto:', 'sms:']);

export type ContactMethodKind = 'email' | 'phone' | 'url' | 'handle';

export interface SafeContactHref {
  /** Allowlisted href, or null → render as plain text only. */
  href: string | null;
  /** Bound + stripped label for display (never trust length/shape from the wire). */
  label: string;
  kind: ContactMethodKind;
}

/** Strip C0/C1 controls + bidi overrides; NFC-normalize; bound length. */
export function sanitizeContactMethodText(raw: unknown, max = CONTACT_METHOD_DISPLAY_MAX): string {
  if (typeof raw !== 'string') return '';
  const nfc = raw.normalize('NFC');
  // eslint-disable-next-line no-control-regex -- intentional control/bidi strip (I-10a)
  const stripped = nfc.replace(/[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/g, '');
  return stripped.slice(0, max);
}

function isPlainEmail(s: string): boolean {
  // Conservative — enough to reject scheme injection; not a full RFC validator.
  return /^[^\s@/\\:]+@[^\s@/\\:]+\.[^\s@/\\:]+$/.test(s) && s.length <= CONTACT_METHOD_DISPLAY_MAX;
}

function phoneDigits(s: string): string {
  const hasPlus = s.trim().startsWith('+');
  const digits = s.replace(/\D/g, '');
  return hasPlus ? `+${digits}` : digits;
}

function isSafePhone(digits: string): boolean {
  // E.164-ish: optional +, 7–15 digits
  return /^\+?\d{7,15}$/.test(digits);
}

/**
 * Resolve a raw URL / scheme'd string to an allowlisted href, or null.
 * NEVER returns javascript: or data:.
 */
export function resolveUrlHref(raw: string): string | null {
  const label = sanitizeContactMethodText(raw);
  if (!label) return null;

  let candidate = label.trim();
  // Bare domain / path → assume https (never proto-relative // which can be scheme-ambiguous in some hosts)
  if (/^\/\//.test(candidate)) return null;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(candidate)) {
    candidate = `https://${candidate}`;
  }

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return null;
  }

  const scheme = url.protocol.toLowerCase();
  if (!ALLOWED_SCHEMES.has(scheme)) return null;
  if (scheme === 'javascript:' || scheme === 'data:') return null; // belt

  if (scheme === 'https:') {
    // Open by design — contact links resolve to ANY host; safety = scheme-allowlist +
    // noopener + visible URL (I-10a), NOT a host allowlist (which would false-pass phishing
    // hosts AND break the open-ended custom contact field).
    if (!url.hostname) return null;
    return url.toString();
  }

  if (scheme === 'mailto:') {
    const addr = decodeURIComponent(url.pathname);
    return isPlainEmail(addr) ? `mailto:${addr}` : null;
  }

  if (scheme === 'tel:' || scheme === 'sms:') {
    const digits = phoneDigits(decodeURIComponent(url.pathname));
    return isSafePhone(digits) ? `${scheme}${digits}` : null;
  }

  return null;
}

/** Email → mailto: or null. */
export function resolveEmailHref(raw: string): string | null {
  const label = sanitizeContactMethodText(raw).trim();
  if (!isPlainEmail(label)) return null;
  return `mailto:${label}`;
}

/** Phone → tel: or null. */
export function resolvePhoneHref(raw: string): string | null {
  const label = sanitizeContactMethodText(raw).trim();
  if (!label) return null;
  const digits = phoneDigits(label);
  if (!isSafePhone(digits)) return null;
  return `tel:${digits}`;
}

/**
 * Platform handle → deep-link on an allowlisted app host, or null.
 * Unknown platforms stay inert text (no invented schemes).
 */
export function resolveHandleHref(platform: string, handle: string): string | null {
  const p = sanitizeContactMethodText(platform, 40).trim().toLowerCase();
  const h = sanitizeContactMethodText(handle).trim();
  if (!p || !h) return null;

  // If the "handle" is already a full URL, run it through the URL gate.
  if (/^https?:\/\//i.test(h) || /^[a-z]+:/i.test(h)) {
    return resolveUrlHref(h);
  }

  const bare = h.replace(/^@/, '');

  switch (p) {
    case 'signal': {
      // Phone-shaped → #p/+E164; otherwise username → #eu/<name> (Signal public links).
      const digits = phoneDigits(bare);
      if (isSafePhone(digits)) {
        const e164 = digits.startsWith('+') ? digits : `+${digits}`;
        return `https://signal.me/#p/${e164}`;
      }
      if (!/^[A-Za-z0-9_.-]{3,32}$/.test(bare)) return null;
      return `https://signal.me/#eu/${bare}`;
    }
    case 'telegram':
    case 'tg': {
      if (!/^[A-Za-z0-9_]{5,32}$/.test(bare)) return null;
      return `https://t.me/${bare}`;
    }
    case 'whatsapp':
    case 'wa': {
      const digits = phoneDigits(bare).replace(/^\+/, '');
      if (!/^\d{7,15}$/.test(digits)) return null;
      return `https://wa.me/${digits}`;
    }
    case 'instagram':
    case 'ig': {
      if (!/^[A-Za-z0-9_.]{1,30}$/.test(bare)) return null;
      return `https://instagram.com/${bare}`;
    }
    case 'facebook':
    case 'fb': {
      if (!/^[A-Za-z0-9.]{5,50}$/.test(bare)) return null;
      return `https://facebook.com/${bare}`;
    }
    case 'email':
    case 'email_alt':
    case 'mailto':
      return resolveEmailHref(bare);
    case 'phone':
    case 'tel':
    case 'sms':
      return resolvePhoneHref(bare);
    default:
      return null;
  }
}

export function safeEmailLink(raw: string): SafeContactHref {
  const label = sanitizeContactMethodText(raw);
  return { kind: 'email', label, href: resolveEmailHref(label) };
}

export function safePhoneLink(raw: string): SafeContactHref {
  const label = sanitizeContactMethodText(raw);
  return { kind: 'phone', label, href: resolvePhoneHref(label) };
}

export function safeUrlLink(raw: string): SafeContactHref {
  const label = sanitizeContactMethodText(raw);
  return { kind: 'url', label, href: resolveUrlHref(label) };
}

export function safeHandleLink(platform: string, handle: string): SafeContactHref {
  const label = sanitizeContactMethodText(handle);
  return { kind: 'handle', label, href: resolveHandleHref(platform, handle) };
}
