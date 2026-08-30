// Demo sample circle for Trust Map / Contacts — keyless peers (no MITM risk).
// UI-only seed; not production identity data.
//
// Designed to show a denser “web of trust” that stays constitutional:
//   • Many YOU↔peer edges you trusted (Orbit spokes).
//   • mutual.reciprocal = PSI-witnessed they-trust-you-too (glow).
//   • Open-visibility clique: Ada/Grace/… they_trust each other so the galaxy
//     draws witnessed Sally↔Joe filaments (Peter’s spec) — NOT inferred from tags.
//   • Owner-authored overlapping group tags → cluster chords / Browse hulls
//     (co-membership ≠ trust).
//   • Mix of trusted-mutual / trusted-one-way / known / pending intro.

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
  /**
   * Mutual trust with YOU (demo stand-in for PSI sync).
   * Sets mutual.reciprocal + they_trust_me — witnessed on YOUR edge.
   */
  reciprocal?: boolean;
  /**
   * Owner opted into open visibility toward this peer (demo).
   * Combined with they_trust, this is how peer↔peer filaments appear.
   */
  open_visibility?: boolean;
  /** People in this demo book this peer also trusts (PSI stand-in). */
  they_trust?: string[];
  notes?: string;
  /** Pending intro — known≠accepted; trust still false */
  pending_intro?: {
    introduced_by: string;
    introduced_by_fp: string;
    context: string;
  };
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
const BARBARA = 'ba1ba1a00000000000000000000000000000000b';
const DOROTHY = 'd0107a000000000000000000000000000000000c';
const JOAN = '10a700000000000000000000000000000000000d';
const JEAN = '1ea700000000000000000000000000000000000e';
const ROSALIND = '105a11d00000000000000000000000000000000f';
const SOPHIE = '5011e00000000000000000000000000000000010';
const EMILIE = 'e1111e0000000000000000000000000000000011';
const MARIE = 'a11e000000000000000000000000000000000012';
const LYNN = '1777000000000000000000000000000000000013';
const RADIA = '1ad1a00000000000000000000000000000000014';

/** All demo fingerprints — used to recognize older seeds that lack metadata.sample. */
const SAMPLE_FPS = new Set([
  ADA, ALAN, GRACE, CLAUDE, HEDY, KATHERINE, FRANK, NIKOLA, HYPATIA, MARGARET,
  BARBARA, DOROTHY, JOAN, JEAN, ROSALIND, SOPHIE, EMILIE, MARIE, LYNN, RADIA,
]);

/**
 * Bump when the demo roster changes. Sample-only books with a lower (or missing)
 * revision auto-upgrade on load so a hard refresh picks up the denser circle
 * without a manual “Refresh demo circle” click. Never touches non-sample books.
 */
export const SAMPLE_CIRCLE_REVISION = 3;

/**
 * Reciprocal + open-visibility clique. Demo stand-in for PSI: each lists the
 * others in `they_trust`. Alan/Dorothy/Lynn are trusted but not reciprocal —
 * they do not join these filaments. Émilie is mutual with you and may open vis
 * without they_trust — tags still are not a bond.
 */
const OPEN_VIS_CLIQUE = [ADA, GRACE, MARGARET, BARBARA, RADIA, JOAN, JEAN, SOPHIE];
const OPEN_VIS_SET = new Set(OPEN_VIS_CLIQUE);

function demoTheyTrust(fp: string): string[] | undefined {
  if (!OPEN_VIS_SET.has(fp)) return undefined;
  return OPEN_VIS_CLIQUE.filter((other) => other !== fp);
}

function isSampleContact(c: {
  fingerprint?: string;
  metadata?: { sample?: boolean; sample_revision?: number };
}): boolean {
  if (c.metadata?.sample) return true;
  const fp = (c.fingerprint || '').toLowerCase();
  return !!fp && SAMPLE_FPS.has(fp);
}

const SAMPLE: SampleContact[] = [
  // ── Core mutual ring (PSI reciprocal with you) ───────────────────────────
  {
    name: 'Ada Lovelace',
    email: 'ada@analytical.engine',
    fingerprint: ADA,
    trust_level: 'verified',
    tags: ['core', 'builders', 'math'],
    phones: ['+44 20 7946 0001'],
    handles: { signal: '@ada.lovelace' },
    urls: ['https://analytical.engine/~ada'],
    reciprocal: true,
    notes: 'Mutual (PSI) · analytical engines & poetry.',
  },
  {
    name: 'Grace Hopper',
    email: 'grace@cobol.dev',
    fingerprint: GRACE,
    trust_level: 'verified',
    tags: ['core', 'builders', 'compilers'],
    phones: ['+1 202 555 0142'],
    handles: { signal: '@amazing.grace' },
    reciprocal: true,
    notes: 'Mutual (PSI) · introduced Frank (pending).',
  },
  {
    name: 'Margaret Hamilton',
    email: 'margaret@apollo.mit',
    fingerprint: MARGARET,
    trust_level: 'verified',
    tags: ['core', 'builders', 'orbital'],
    phones: ['+1 617 555 0130'],
    reciprocal: true,
    notes: 'Mutual (PSI) · software that flew.',
  },
  {
    name: 'Barbara Liskov',
    email: 'barbara@mit.edu',
    fingerprint: BARBARA,
    trust_level: 'verified',
    tags: ['core', 'builders', 'compilers'],
    handles: { signal: '@b.liskov' },
    reciprocal: true,
    notes: 'Mutual (PSI) · abstraction & CLU.',
  },
  {
    name: 'Radia Perlman',
    email: 'radia@routing.net',
    fingerprint: RADIA,
    trust_level: 'verified',
    tags: ['core', 'radio', 'builders'],
    phones: ['+1 650 555 0199'],
    reciprocal: true,
    notes: 'Mutual (PSI) · spanning trees & routing.',
  },

  // ── Trusted, mutual sync pending (you trust them; PSI not yet reciprocal) ─
  {
    name: 'Alan Turing',
    email: 'alan@bletchley.uk',
    fingerprint: ALAN,
    trust_level: 'verified',
    tags: ['builders', 'bletchley', 'math'],
    phones: ['+44 1625 555 019'],
    handles: { telegram: '@a_turing' },
    reciprocal: false,
    notes: 'Trusted — PSI mutual not yet confirmed.',
  },
  {
    name: 'Dorothy Vaughan',
    email: 'dorothy@langley.nasa',
    fingerprint: DOROTHY,
    trust_level: 'verified',
    tags: ['orbital', 'builders', 'math'],
    reciprocal: false,
    notes: 'Trusted · FORTRAN cohort — awaiting mutual.',
  },
  {
    name: 'Lynn Conway',
    email: 'lynn@vlsi.edu',
    fingerprint: LYNN,
    trust_level: 'verified',
    tags: ['builders', 'compilers'],
    handles: { signal: '@lynn.conway' },
    reciprocal: false,
    notes: 'Trusted · VLSI & Mead–Conway — PSI pending.',
  },

  // ── More mutuals in overlapping clusters (dense group chords) ────────────
  {
    name: 'Joan Clarke',
    email: 'joan@bletchley.uk',
    fingerprint: JOAN,
    trust_level: 'verified',
    tags: ['bletchley', 'math', 'core'],
    reciprocal: true,
    notes: 'Mutual (PSI) · Banburismus & Hut 8.',
  },
  {
    name: 'Jean Bartik',
    email: 'jean@eniac.org',
    fingerprint: JEAN,
    trust_level: 'verified',
    tags: ['builders', 'compilers', 'math'],
    phones: ['+1 215 555 0160'],
    reciprocal: true,
    notes: 'Mutual (PSI) · ENIAC programmer.',
  },
  {
    name: 'Sophie Germain',
    email: 'sophie@primes.fr',
    fingerprint: SOPHIE,
    trust_level: 'verified',
    tags: ['math', 'bletchley'],
    reciprocal: true,
    notes: 'Mutual (PSI) · primes under a pen name.',
  },
  {
    name: 'Émilie du Châtelet',
    email: 'emilie@newton.fr',
    fingerprint: EMILIE,
    trust_level: 'verified',
    tags: ['math', 'orbital'],
    reciprocal: true,
    open_visibility: true,
    notes: 'Mutual (PSI) · open vis without they_trust — not a peer chord.',
  },

  // ── Known (not trusted) — fills outer ring / cluster hulls ───────────────
  {
    name: 'Claude Shannon',
    email: 'claude@bell.labs',
    fingerprint: CLAUDE,
    trust_level: 'unverified',
    tags: ['radio', 'bletchley', 'math'],
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
    tags: ['radio', 'orbital', 'math'],
    notes: 'Known · orbital mechanics.',
  },
  {
    name: 'Rosalind Franklin',
    email: 'rosalind@kings.ac.uk',
    fingerprint: ROSALIND,
    trust_level: 'unverified',
    tags: ['math'],
    notes: 'Known · Photo 51 — not yet vouched.',
  },
  {
    name: 'Marie Curie',
    email: 'marie@radium.fr',
    fingerprint: MARIE,
    trust_level: 'unverified',
    tags: ['orbital', 'math'],
    notes: 'Known · two Nobels — introduction pending trust.',
  },
  {
    name: 'Nikola Tesla',
    email: '',
    fingerprint: NIKOLA,
    trust_level: 'unverified',
    tags: ['orbital', 'radio'],
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

  // ── Pending intro (not trust) ────────────────────────────────────────────
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
];

/** True when the living book is demo-only and behind SAMPLE_CIRCLE_REVISION. */
export function sampleCircleNeedsUpgrade(
  contacts: Array<{ fingerprint?: string; metadata?: { sample?: boolean; sample_revision?: number } }>,
): boolean {
  if (contacts.length === 0) return false;
  if (!contacts.every((c) => isSampleContact(c))) return false;
  if (contacts.length !== SAMPLE.length) return true;
  return contacts.some((c) => c.metadata?.sample_revision !== SAMPLE_CIRCLE_REVISION);
}

/**
 * Seed (or refresh) the demo sample circle.
 * - Empty book → seed.
 * - Only sample contacts → replace with the richer set (mutual + clusters + pending).
 * - Real (non-sample) contacts present → no-op (never clobber the living book).
 */
export async function seedSampleCircle(ownerFingerprint: string): Promise<number> {
  const existing = await getAllContacts(ownerFingerprint);
  const samples = existing.filter((c) => isSampleContact(c as any));
  const real = existing.filter((c) => !isSampleContact(c as any));

  // Never mix demo data into a living book.
  if (real.length > 0) return 0;

  for (const s of samples) {
    await removeContact(s.id);
  }

  const now = new Date().toISOString();
  let n = 0;
  for (const c of SAMPLE) {
    const trusted = c.trust_level === 'verified';
    const theyTrust = c.they_trust ?? demoTheyTrust(c.fingerprint);
    const openVis = c.open_visibility ?? OPEN_VIS_SET.has(c.fingerprint);
    await addContact(ownerFingerprint, {
      name: c.name,
      email: c.email,
      fingerprint: c.fingerprint || undefined,
      // Keyless demo peers — omit public_key (empty string is truthy and fails fp↔key bind).
      trust_level: c.trust_level,
      trusted,
      trusted_since: trusted ? now : null,
      last_interaction: now,
      decay_days: 730,
      tags: c.tags,
      notes: c.notes || '',
      they_trust: theyTrust,
      open_visibility: openVis,
      contact_info: {
        phones: c.phones,
        handles: c.handles,
        urls: c.urls,
        emails: c.email ? [c.email] : undefined,
      },
      mutual: {
        // Demo stand-in for PSI: they_trust_me + reciprocal when mutual with YOU.
        they_trust_me: c.reciprocal === true ? true : c.reciprocal === false ? false : null,
        last_sync: c.reciprocal ? now : null,
        reciprocal: !!c.reciprocal,
      },
      verification: trusted
        ? { method: 'in_person', verified_at: now }
        : { method: 'none', verified_at: null },
      connection_status: c.pending_intro ? 'pending' : 'accepted',
      metadata: {
        sample: true,
        sample_revision: SAMPLE_CIRCLE_REVISION,
        tags: c.tags,
        notes: c.notes,
        pending_intro: c.pending_intro || undefined,
        connection_status: c.pending_intro ? 'pending' : 'accepted',
        /** Demo hint only — not a published PSI transcript. */
        psi_mutual: !!c.reciprocal,
        they_trust: theyTrust,
        share_settings: {
          share_card: true,
          share_trusted_circle: false,
          share_groups: false,
          open_visibility: openVis,
        },
      },
    } as any);
    n++;
  }
  return n;
}

/** True when the book is empty or only holds demo sample contacts. */
export async function canRefreshSampleCircle(ownerFingerprint: string): Promise<boolean> {
  const existing = await getAllContacts(ownerFingerprint);
  if (existing.length === 0) return true;
  return existing.every((c) => isSampleContact(c as any));
}
