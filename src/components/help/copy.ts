/**
 * Getting Started (Help) copy.
 *
 * ★ Claim-honesty surface — Hypatia owns the final wording.
 * Ground truth for recovery = alternatives model shipped in #65 (Flint matrix):
 *   backup FILE always required + ONE key:
 *   password + file → everything · OR · recovery code + file → identity only.
 * Navigation paths must match the live chrome (not stale "Secure Export" labels).
 *
 * Do NOT strengthen crypto / wire-notify / decay-customize claims without Hypatia + fleet.
 */

export type HelpStep = {
  title: string;
  content: string[];
};

export const HELP_STEPS: HelpStep[] = [
  {
    title: 'Create Your Identity',
    content: [
      'Enter your name and a strong unlock passphrase (12+ characters).',
      'Keys are generated on this device — classical and post-quantum. The server never holds them.',
      'At forge you also see a recovery code (8 groups of 8 hex characters). Write it down offline — shown once. It is not your everyday unlock passphrase.',
      'There is no recovery email and no “forgot password” on a server. Keep the unlock passphrase and the recovery code somewhere you still have if this device is gone.',
    ],
  },
  {
    title: 'Back Up Your Identity',
    content: [
      'Open Contacts → ⋯ → Export Vault (.svrnty) to save an encrypted backup of identity, contacts, and trust.',
      'Choose a vault passphrase (12+). This can be different from your everyday unlock passphrase.',
      'Store the .svrnty file somewhere you control (drive you own, or storage you trust).',
      'Two ways to restore later — both need that backup file: password + file → everything (identity, contacts, and trust); OR recovery code + file → identity only (reconnect contacts afterward).',
      'Export again after important contact or trust changes.',
    ],
  },
  {
    title: 'Add People You Know',
    content: [
      'Click Share Identity (Contacts today; Identity card when that pass lands). This creates a signed package with your public key.',
      'Send it to your friend on a channel you trust (Signal, email, in person).',
      'They import the package in SVRNTY. Signatures are checked — the package is bound to the key.',
      'They appear as Known in your book. You appear as Known in theirs. Known is not Trusted.',
    ],
  },
  {
    title: 'Trust',
    content: [
      'Known means you have their contact. It does not mean you trust them.',
      'Trust is binary — Known or Trusted — with no score, tier, or rank.',
      'Confirm Trust on a contact to vouch on this device. Wire notify (telling them) is fleet-owned and not sent from the confirm dialog yet.',
      'Break trust returns them to Known locally. Remove and Block are local owner actions; the relay stays blind.',
    ],
  },
  {
    title: 'Trust over time',
    content: [
      'Trust edges carry a local decay clock (default about 2 years without meaningful interaction).',
      'When an edge is past that window, the map can show it as decayed — still known, no longer treated as live trust.',
      'Re-granting trust is yours to confirm again. Per-contact decay customization in the UI is not shipped yet — do not expect a settings control for it today.',
    ],
  },
  {
    title: 'How It Works',
    content: [
      'Your keys and contacts stay on your device, encrypted. The relay is designed to stay blind to your graph.',
      'Signals you send are signed. Classical and post-quantum algorithms are in the stack — do not read this as a guarantee that every path is PQ-complete yet.',
      'No server account that can revoke you. No ads. No aggregate reputation score.',
      'The card is yours. Edges you see are ones you authored or witnessed — none inferred.',
    ],
  },
];
