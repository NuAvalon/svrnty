/**
 * CUR-11 about-page copy.
 *
 * ★ PROVISIONAL — Hypatia owns the claim-honest source. Queue says
 * "copy source (Hypatia) → Cursor renders." No Hypatia-authored about
 * brief was in the repo at build time, so these strings under-claim from
 * already-shipped README / CURSOR.md constitution language. Swap this
 * module (or point `ABOUT_COPY` at Hypatia's file) once the source lands.
 *
 * Do NOT strengthen crypto / recovery / PQ claims here without Hypatia + Flint.
 */

export type AboutSection = {
  id: string;
  heading: string;
  body: string[];
};

export type AboutCopy = {
  /** Shown only while Hypatia source is pending — remove when copy is final. */
  provisionalBanner: string | null;
  brand: string;
  tagline: string;
  lede: string;
  sections: AboutSection[];
  principlesHeading: string;
  principles: { title: string; line: string }[];
  closing: string;
  backLabel: string;
};

export const ABOUT_COPY: AboutCopy = {
  provisionalBanner:
    'Copy is provisional until Hypatia delivers the about-page source. Claims under-state on purpose.',
  brand: 'svrnty',
  tagline: "reclaim what's yours",
  lede:
    'Sovereign identity, living contacts, and a consent-gated trust graph — local-first, on your device. The server never holds your keys or passphrase.',
  sections: [
    {
      id: 'what',
      heading: 'What this is',
      body: [
        'You generate your identity on your device. You author who you trust. You share contact methods that stay live when you update them.',
        'Nothing personal leaves your device unless you choose to send it. There is no account to revoke and no platform that owns your graph.',
      ],
    },
    {
      id: 'trust',
      heading: 'How trust works here',
      body: [
        'Trust is binary: Known or Trusted. No scores, no tiers, no popularity contests.',
        'Edges you see are ones both sides consented to share — none inferred. Absence stays ambiguous on purpose.',
        'Trust does not cascade. An introduction starts someone as Known; you still verify them yourself.',
      ],
    },
    {
      id: 'keys',
      heading: 'Keys & recovery',
      body: [
        'Your keys stay on your device, wrapped so the relay stays blind to them.',
        'Backups are encrypted files you control. Recovery needs the factors that protect that backup — never invent a path the crypto does not support.',
      ],
    },
    {
      id: 'open',
      heading: 'Open & self-hostable',
      body: [
        'svrnty is open source. You can run your own instance under your own domain — your instance, your control.',
        'The network is many people coordinating — not a tenancy on someone else\'s database.',
      ],
    },
  ],
  principlesHeading: 'Held as law',
  principles: [
    {
      title: 'No aggregate',
      line: 'No reputation scores, standings, or rankings on identity.',
    },
    {
      title: 'Consent first',
      line: 'What you opted out of is uncomputable — not client-side hidden.',
    },
    {
      title: 'You author your edges',
      line: 'The glass renders what you and your circle consented to share.',
    },
    {
      title: 'Reachability, not location',
      line: 'Whether someone is reachable — never where they are.',
    },
  ],
  closing: 'The card is yours. No account. No server that can read you.',
  backLabel: 'Back to app',
};
