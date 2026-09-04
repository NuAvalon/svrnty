/**
 * Own-identity → portable vCard 3.0.
 * User-authored contact methods only — non-crypto, phone/email-client friendly.
 *
 * Apollo §2: never serialize device-local tags / blocked / group-labels
 * onto export payloads. OwnVCardSource has no such fields; tests assert
 * extras cannot leak even if a caller spreads a contact record.
 */

export type OwnVCardSource = {
  name: string;
  fingerprint: string;
  email?: string;
  /** Signal number or handle — emitted as TEL when phone-like, else X-SIGNAL */
  signal?: string;
  /** Personal site / claimed URL host */
  site?: string;
};

function escapeVCard(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,');
}

function looksLikePhone(value: string): boolean {
  const digits = value.replace(/\D/g, '');
  return digits.length >= 7 && digits.length <= 15;
}

/** http(s) only — never javascript:/data: even on owner-authored site text. */
export function toHttpUrl(site: string): string | null {
  const raw = site.trim();
  if (!raw) return null;
  const candidate = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  try {
    const u = new URL(candidate);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u.href;
  } catch {
    return null;
  }
}

/**
 * Build a single vCard for the owner's own card (not the address book).
 * Omits private tags, blocked flags, trust state, and keys.
 */
export function toOwnVCard(src: OwnVCardSource): string {
  const name = (src.name || '').trim() || 'Unnamed';
  const fp = src.fingerprint.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  const lines: string[] = [
    'BEGIN:VCARD',
    'VERSION:3.0',
    `FN:${escapeVCard(name)}`,
  ];

  const parts = name.split(/\s+/).filter(Boolean);
  if (parts.length >= 2) {
    lines.push(`N:${escapeVCard(parts.slice(1).join(' '))};${escapeVCard(parts[0])};;;`);
  } else {
    lines.push(`N:;${escapeVCard(name)};;;`);
  }

  if (src.email?.trim()) {
    lines.push(`EMAIL;TYPE=INTERNET:${src.email.trim()}`);
  }

  if (src.signal?.trim()) {
    const signal = src.signal.trim();
    if (looksLikePhone(signal)) {
      lines.push(`TEL;TYPE=CELL:${signal}`);
    }
    lines.push(`X-SIGNAL:${escapeVCard(signal)}`);
  }

  if (src.site?.trim()) {
    const url = toHttpUrl(src.site);
    if (url) lines.push(`URL:${url}`);
  }

  if (fp) {
    lines.push(`UID:svrnty:${fp}`);
    lines.push(`NOTE:${escapeVCard(`svrnty fingerprint: ${fp}`)}`);
  }

  lines.push('END:VCARD');
  return lines.join('\r\n');
}

/** Trigger a browser download of the owner's .vcf (client-side only). */
export function downloadOwnVCard(src: OwnVCardSource, filename?: string): void {
  const vcf = toOwnVCard(src);
  const blob = new Blob([vcf], { type: 'text/vcard;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const safeName = (src.name || 'svrnty')
    .trim()
    .replace(/[^\w.\- ]+/g, '')
    .replace(/\s+/g, '-')
    .slice(0, 48) || 'svrnty';
  a.href = url;
  a.download = filename || `${safeName}.vcf`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
