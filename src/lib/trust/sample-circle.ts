// Demo sample circle for Trust Map / Contacts — keyless peers (no MITM risk).
// UI-only seed; not production identity data.
//
// Designed to show: mutual trust (self↔Ada↔Grace), owner-authored group
// clusters (not radial-only), known vs trusted, and a pending introduction.

import { addContact, getAllContacts, removeContact } from '@/lib/identity/client-store';

type SampleTrust = 'verified' | 'unverified';

interface SampleContact {
  name: string;
  email: string;
  fingerprint: string;
  trust_level: SampleTrust;
  /** Owner-authored group labels → cluster chords on the map */
  tags: string[];
  phones?: string[];
  handles?: Record<string, string>;
  urls?: string[];
  /** Mutual trust with self (demo — would come from PSI sync in prod) */
  reciprocal?: boolean;
  notes?: string;
  /** Pending intro — known≠accepted; trust still false */
  pending_intro?: {
    introduced_by: string;
    introduced_by_fp: string;
    context: string;
  };
  /** Sample inbound Distress — paints the vivre on load-sample. */
  distress?: boolean;
}

/** Deterministic fake fingerprints (40 hex) — no matching keys; gray/keyless OK. */
const ADA = 'a11a10e1ace00000000000000000000000000001';
const ALAN = 'a1a2011216000000000000000000000000000002';
const GRACE = '61ace00000000000000000000000000000000003';
const CLAUDE = 'c1a00e0000000000000000000000000000000004';
const HEDY = '4ed1000000000000000000000000000000000005';
const KATHERINE = 'ca1e000000000000000000000000000000000006';
const FRANK = 'f1a2000000000000000000000000000000000007';
const NIKOLA = '7e51a00000000000000000000000000000000008';
const HYPATIA = 'b7a71a0000000000000000000000000000000009';
const MARGARET = 'ba111a000000000000000000000000000000000a';

const SAMPLE: SampleContact[] = [
  {
    name: 'Ada Lovelace',
    email: 'ada@analytical.engine',
    fingerprint: ADA,
    trust_level: 'verified',
    tags: ['core', 'builders'],
    phones: ['+44 20 7946 0001'],
    handles: { signal: '@ada.lovelace' },
    urls: ['https://analytical.engine/~ada'],
    reciprocal: true,
    notes: 'Mutual trust · analytical engines & poetry.',
    distress: true,
  },
  {
    name: 'Grace Hopper',
    email: 'grace@cobol.dev',
    fingerprint: GRACE,
    trust_level: 'verified',
    tags: ['core', 'builders'],
    phones: ['+1 202 555 0142'],
    handles: { signal: '@amazing.grace' },
    reciprocal: true,
    notes: 'Mutual trust · introduced Frank (pending).',
  },
  {
    name: 'Alan Turing',
    email: 'alan@bletchley.uk',
    fingerprint: ALAN,
    trust_level: 'verified',
    tags: ['builders', 'bletchley'],
    phones: ['+44 1625 555 019'],
    handles: { telegram: '@a_turing' },
    reciprocal: false,
    notes: 'Trusted — mutual sync not yet confirmed.',
  },
  {
    name: 'Claude Shannon',
    email: 'claude@bell.labs',
    fingerprint: CLAUDE,
    trust_level: 'unverified',
    tags: ['radio', 'bletchley'],
    handles: { email_alt: 'shannon@theory.info' },
    notes: 'Known · information theory circle.',
  },
  {
    name: 'Hedy Lamarr',
    email: 'hedy@fhss.radio',
    fingerprint: HEDY,
    trust_level: 'unverified',
    tags: ['radio'],
    phones: ['+1 310 555 0188'],
    urls: ['https://fhss.radio'],
    notes: 'Known · frequency hopping.',
  },
  {
    name: 'Katherine Johnson',
    email: 'katherine@nasa.gov',
    fingerprint: KATHERINE,
    trust_level: 'unverified',
    tags: ['radio', 'orbital'],
    notes: 'Known · orbital mechanics.',
  },
  {
    name: 'Margaret Hamilton',
    email: 'margaret@apollo.mit',
    fingerprint: MARGARET,
    trust_level: 'verified',
    tags: ['builders', 'orbital'],
    phones: ['+1 617 555 0130'],
    reciprocal: true,
    notes: 'Mutual · software that flew.',
  },
  {
    name: 'Frank Garcia',
    email: 'frank@pending.intro',
    fingerprint: FRANK,
    trust_level: 'unverified',
    tags: [],
    phones: ['+1 415 555 0177'],
    pending_intro: {
      introduced_by: 'Grace Hopper',
      introduced_by_fp: GRACE,
      context: 'Grace introduced you at the compiler salon',
    },
    notes: 'Pending connection — accept to know; trust is separate.',
  },
  {
    name: 'Nikola Tesla',
    email: '',
    fingerprint: NIKOLA,
    trust_level: 'unverified',
    tags: ['orbital'],
    notes: 'Known · keyless / gray.',
  },
  {
    name: 'Hypatia',
    email: '',
    fingerprint: HYPATIA,
    trust_level: 'unverified',
    tags: [],
    notes: 'Known · no channels shared yet.',
  },
];

/**
 * Seed (or refresh) the demo sample circle.
 * - Empty book → seed.
 * - Only sample contacts → replace with the richer set (mutual + clusters + pending).
 * - Real (non-sample) contacts present → no-op (never clobber the living book).
 */
export async function seedSampleCircle(ownerFingerprint: string): Promise<number> {
  const existing = await getAllContacts(ownerFingerprint);
  const samples = existing.filter((c) => !!(c as { metadata?: { sample?: boolean } }).metadata?.sample);
  const real = existing.filter((c) => !(c as { metadata?: { sample?: boolean } }).metadata?.sample);

  // Never mix demo data into a living book.
  if (real.length > 0) return 0;

  for (const s of samples) {
    await removeContact(s.id);
  }

  const now = new Date().toISOString();
  let n = 0;
  for (const c of SAMPLE) {
    const trusted = c.trust_level === 'verified';
    await addContact(ownerFingerprint, {
      name: c.name,
      email: c.email,
      fingerprint: c.fingerprint || undefined,
      public_key: '',
      trust_level: c.trust_level,
      trusted,
      trusted_since: trusted ? now : null,
      last_interaction: now,
      decay_days: 730,
      tags: c.tags,
      notes: c.notes || '',
      contact_info: {
        phones: c.phones,
        handles: c.handles,
        urls: c.urls,
        emails: c.email ? [c.email] : undefined,
      },
      mutual: {
        they_trust_me: c.reciprocal ?? null,
        last_sync: c.reciprocal ? now : null,
        reciprocal: !!c.reciprocal,
      },
      verification: trusted
        ? { method: 'in_person', verified_at: now }
        : { method: 'none', verified_at: null },
      connection_status: c.pending_intro ? 'pending' : 'accepted',
      metadata: {
        sample: true,
        tags: c.tags,
        notes: c.notes,
        pending_intro: c.pending_intro || undefined,
        connection_status: c.pending_intro ? 'pending' : 'accepted',
        distress_inbound: c.distress || undefined,
      },
      distress_inbound: c.distress || undefined,
    } as any);
    n++;
  }
  return n;
}

/** True when the book is empty or only holds demo sample contacts. */
export async function canRefreshSampleCircle(ownerFingerprint: string): Promise<boolean> {
  const existing = await getAllContacts(ownerFingerprint);
  if (existing.length === 0) return true;
  return existing.every((c) => !!(c as { metadata?: { sample?: boolean } }).metadata?.sample);
}
