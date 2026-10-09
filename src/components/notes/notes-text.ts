// Display-safety for untrusted contact / note fields (I-10a). Bound + strip; React still text-renders.

import { NOTES_BOUNDS } from './notes-copy';

const CONTROL_AND_BIDI =
  /[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/g;

export function boundDisplayText(raw: string | null | undefined, max: number = NOTES_BOUNDS.name): string {
  const nfc = String(raw ?? '').normalize('NFC');
  const stripped = nfc.replace(CONTROL_AND_BIDI, '').trim();
  if (!stripped) return '';
  return stripped.length > max ? stripped.slice(0, max) : stripped;
}

export function formatFingerprintShort(fp: string): string {
  const hex = String(fp || '')
    .toLowerCase()
    .replace(/[^0-9a-f]/g, '');
  if (hex.length < 16) return hex || '————';
  return `${hex.slice(0, 8)}…${hex.slice(-8)}`;
}
