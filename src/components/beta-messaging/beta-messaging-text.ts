import { BETA_BOUNDS } from './beta-messaging-copy';

const CONTROL_AND_BIDI =
  /[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/g;

export function boundAccessKey(raw: string | null | undefined): string {
  const nfc = String(raw ?? '').normalize('NFC');
  const stripped = nfc.replace(CONTROL_AND_BIDI, '').trim();
  if (!stripped) return '';
  return stripped.length > BETA_BOUNDS.accessKey
    ? stripped.slice(0, BETA_BOUNDS.accessKey)
    : stripped;
}
