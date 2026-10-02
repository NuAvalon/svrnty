// One-step Connect-UX copy. Hypatia finalizes microcopy (claim-ledger).
// Until then: operational, claim-honest, no "verified" entity badge,
// no mutual/trust default, no persist claim while add-logic is stubbed.

const CONTROL_AND_BIDI =
  /[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/g;

const NAME_MAX = 80;
const HANDLE_MAX = 80;

export function boundConnectText(raw: unknown, max: number): string {
  if (typeof raw !== 'string') return '';
  const nfc = raw.normalize('NFC');
  const stripped = nfc.replace(CONTROL_AND_BIDI, '').trim();
  if (!stripped) return '';
  return stripped.length > max ? stripped.slice(0, max) : stripped;
}

export function boundConnectName(raw: unknown): string {
  return boundConnectText(raw, NAME_MAX);
}

export function boundConnectHandle(raw: unknown): string {
  return boundConnectText(raw, HANDLE_MAX);
}

export type ConnectEntityType = 'agent' | 'human' | 'org';

/** Attested (self-typed on the card), never "verified". Absent = not yet attested — not guessed. */
export function entityTypeLabel(entityType: ConnectEntityType | undefined): string {
  if (entityType === 'agent') return 'attested: agent';
  if (entityType === 'human') return 'attested: human';
  if (entityType === 'org') return 'attested: organization';
  return 'not yet attested';
}

export const CONNECT_COPY = {
  kicker: 'Connect',
  pasteLabel: 'Paste a connect link',
  pasteHint:
    'Paste their svrnty.is/c/… link or the short code. They wait at your Gate until you add them as Known.',
  open: 'Open',
  back: 'Back',
  waitingAtGate: 'Waiting at the Gate',
  addToKnown: 'Add to Known',
  addToKnownHint:
    'This is your local disclosure — one-sided. It is not a mutual bond, and it does not grant Trust.',
  localOnly:
    'Adding them to your book is your choice on this device. The link does not make you mutual.',
  invitationNotCapture:
    'A connect link is an invitation to add them if you want — not a capture, and not a bearer grant.',
  notWired:
    'This one-step connect is built as glass. Saving to your Gate is not live yet — nothing is written to your book.',
  notWiredButton: 'Saving is not live yet',
  invalidLink:
    "That doesn't look like a svrnty connect link. Paste the whole link, or the short code.",
  unavailable: 'This invitation could not be opened.',
  noIdentityTitle: 'Create your identity first',
  noIdentityBody:
    'No identity on this device yet. Create one on the home screen, then return to this same link. The invitation is not stored off this page.',
  createIdentity: 'Go to home',
  fingerprintLabel: 'Fingerprint',
  handleLabel: 'Handle',
  mailboxLabel: 'Mailbox',
  dismiss: 'Not now',
  resolving: 'Looking up this invitation…',
} as const;
