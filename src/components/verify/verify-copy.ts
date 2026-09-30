// Guided-verify chrome strings. Recipe lines stay verbatim from TRUST_RECIPE_COPY.
// The mismatch line interpolates only a bounded owner-local name — never scan text.

const CONTROL_AND_BIDI =
  /[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/g;

const NAME_MAX = 64;

export function boundVerifyName(raw: string | null | undefined): string {
  const nfc = String(raw ?? '').normalize('NFC');
  const stripped = nfc.replace(CONTROL_AND_BIDI, '').trim();
  if (!stripped) return '';
  return stripped.length > NAME_MAX ? stripped.slice(0, NAME_MAX) : stripped;
}

export const VERIFY_SHEET_COPY = {
  title: 'Verify',
  scanTheirQr: 'Scan their QR',
  scanAgain: 'Scan again',
  pasteCompare: 'Paste the code from the other channel',
  codeMatches: 'the code matches.',
  confirmOther: 'Confirm',
  notYet: 'Not yet',
  close: 'Close',
  mismatch: (name: string) => {
    const n = boundVerifyName(name);
    return n
      ? `this isn't the key you have for ${n} — do not verify`
      : "this isn't the key you have — do not verify";
  },
} as const;
