/** Flint's Relay field copy — claim surface. Do not paraphrase. */

export const RELAY_COPY = {
  title: 'Relay',
  currentPrefix: "You're on:",
  fieldLabel: 'Relay URL',
  placeholder: 'https://your-relay.example:8100',
  helper:
    'A relay sees that and when you connect — never your notes (those stay sealed end-to-end). Switching relays moves your dead-drop, not your identity.',
  switch: 'Switch to this relay',
  confirmTitle: 'Switch relay?',
  confirmBody:
    'This moves your dead-drop to the new relay and notifies people you trust. Your identity stays on this device.',
  confirm: 'Switch',
  cancel: 'Cancel',
  switching: 'Switching relay…',
  nowOn: (url: string) => `You're now on ${url}.`,
  incomplete: (n: number) =>
    `Migration incomplete — ${n} friend${n === 1 ? '' : 's'} not yet notified. Your old relay keeps receiving for ~7 days.`,
  unwired:
    'This relay is a full svrnty satellite. Switching is built, not yet wired — migrateRelay plus the config override still need the fleet.',
  valid: 'valid',
  invalid: {
    reach: "can't reach",
    notRelay: 'not a svrnty relay',
    registrationOnly: 'registration-only — need a full relay',
    scheme: 'not a svrnty relay',
  },
} as const;
