// Demo sample circle for Trust Map / Contacts — dense living book for label LOD QA.
// UI-only seed; not production identity data.
//
// Designed to show a denser “web of trust” that stays constitutional:
//   • Many YOU↔peer edges you trusted (Orbit spokes).
//   • mutual.reciprocal = PSI-witnessed they-trust-you-too (glow).
//   • Open-visibility cliques: they_trust each other so the galaxy
//     draws witnessed Sally↔Joe filaments (Peter’s spec) — NOT inferred from tags.
//   • Owner-authored overlapping group tags → cluster chords / Browse hulls
//     (co-membership ≠ trust).
//   • SVRNTY demo peers carry a frozen public_key (fingerprint ≡ H(key)).
//   • A few classical book rows stay keyless — no fingerprint (Invariant-1).

import { addContact, getAllContacts, removeContact } from '@/lib/identity/client-store';
import { SAMPLE_SVRNTY_FPS, SAMPLE_SVRNTY_PEERS } from '@/lib/trust/sample-svrnty-keys';

type SampleTrust = 'verified' | 'unverified';

interface SampleContact {
  name: string;
  email: string;
  /** Classical rows: omit / ''. Living SVRNTY rows get fp from SAMPLE_SVRNTY_PEERS at seed. */
  fingerprint?: string;
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

/** Historical fake fingerprints — recognize older sample seeds so revision auto-upgrades. Not stored on new classical rows. */
const LEGACY_FPS = [
  'a11a10e1ace00000000000000000000000000001',
  'a1a2011216000000000000000000000000000002',
  '61ace00000000000000000000000000000000003',
  'c1a00e0000000000000000000000000000000004',
  '4ed1000000000000000000000000000000000005',
  'ca1e000000000000000000000000000000000006',
  'f1a2000000000000000000000000000000000007',
  '7e51a00000000000000000000000000000000008',
  'b7a71a0000000000000000000000000000000009',
  'ba111a000000000000000000000000000000000a',
  'ba1ba1a00000000000000000000000000000000b',
  'd0107a000000000000000000000000000000000c',
  '10a700000000000000000000000000000000000d',
  '1ea700000000000000000000000000000000000e',
  '105a11d00000000000000000000000000000000f',
  '5011e00000000000000000000000000000000010',
  'e1111e0000000000000000000000000000000011',
  'a11e000000000000000000000000000000000012',
  '1777000000000000000000000000000000000013',
  '1ad1a00000000000000000000000000000000014',
];

/** All demo fingerprints — used to recognize older seeds that lack metadata.sample. */
const SAMPLE_FPS = new Set([...LEGACY_FPS, ...SAMPLE_SVRNTY_FPS]);

/**
 * Bump when the demo roster changes. Sample-only books with a lower (or missing)
 * revision auto-upgrade on load so a hard refresh picks up the denser circle
 * without a manual “Refresh demo circle” click. Never touches non-sample books.
 */
export const SAMPLE_CIRCLE_REVISION = 7;

/** Open-visibility clique among living (SVRNTY) demo peers — Peter's filament demo. */
const CORE_CLIQUE_IDS = new Set([
  'ada',
  'grace',
  'margaret',
  'barbara',
  'radia',
  'joan',
  'jean',
  'sophie',
]);

/** Second open-vis ring — crypto researchers (peer filaments within ring). */
const CRYPTO_CLIQUE_IDS = new Set([
  'shafi',
  'silvio',
  'whitfield',
  'martin',
  'ralph',
  'ron',
  'adi',
  'leonard',
  'feistel',
  'susan',
]);

const TAG_BY_ID: Record<string, string[]> = {
  ada: ['core', 'builders', 'math'],
  grace: ['core', 'builders', 'compilers'],
  margaret: ['core', 'builders', 'orbital'],
  barbara: ['core', 'builders', 'compilers'],
  radia: ['core', 'radio', 'builders'],
  joan: ['bletchley', 'math', 'core'],
  jean: ['builders', 'compilers', 'math'],
  sophie: ['math', 'bletchley'],
  alan: ['builders', 'bletchley', 'math'],
  dorothy: ['orbital', 'builders', 'math'],
  claude: ['radio', 'bletchley', 'math'],
  hedy: ['radio'],
  katherine: ['radio', 'orbital', 'math'],
  rosalind: ['math'],
  marie: ['orbital', 'math'],
  lynn: ['builders', 'compilers'],
  tim: ['builders', 'radio'],
  vint: ['radio', 'builders'],
  bob: ['radio', 'builders'],
  dennis: ['builders', 'compilers'],
  ken: ['builders', 'compilers'],
  brian: ['builders', 'compilers'],
  donald: ['math', 'builders'],
  edsger: ['math', 'builders'],
  tony: ['builders', 'compilers'],
  frances: ['compilers', 'builders'],
  betty: ['builders', 'compilers'],
  shafi: ['crypto', 'math'],
  silvio: ['crypto', 'math'],
  whitfield: ['crypto', 'radio'],
  martin: ['crypto', 'radio'],
  ralph: ['crypto'],
  ron: ['crypto', 'math'],
  adi: ['crypto', 'math'],
  leonard: ['crypto', 'math'],
  feistel: ['crypto'],
  susan: ['crypto', 'math'],
  linus: ['builders'],
  guido: ['builders', 'compilers'],
  leslie: ['builders', 'math'],
  nancy: ['math', 'builders'],
};

function tagsFor(id: string): string[] {
  if (TAG_BY_ID[id]) return TAG_BY_ID[id];
  if (CRYPTO_CLIQUE_IDS.has(id)) return ['crypto'];
  if (CORE_CLIQUE_IDS.has(id)) return ['core'];
  // Stable hash → a couple of overlapping neighborhoods
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
  const pools = [
    ['builders'],
    ['math'],
    ['radio'],
    ['orbital'],
    ['compilers'],
    ['bletchley'],
    ['builders', 'math'],
    ['radio', 'builders'],
    ['orbital', 'math'],
    ['compilers', 'builders'],
  ];
  return pools[h % pools.length];
}

const LIVING_BY_NAME = new Map(SAMPLE_SVRNTY_PEERS.map((p) => [p.name, p]));
const LIVING_BY_ID = new Map(SAMPLE_SVRNTY_PEERS.map((p) => [p.id, p]));

const CORE_FPS = SAMPLE_SVRNTY_PEERS.filter((p) => CORE_CLIQUE_IDS.has(p.id)).map(
  (p) => p.fingerprint,
);
const CRYPTO_FPS = SAMPLE_SVRNTY_PEERS.filter((p) => CRYPTO_CLIQUE_IDS.has(p.id)).map(
  (p) => p.fingerprint,
);

function theyTrustFor(id: string, fp: string): string[] | undefined {
  if (CORE_CLIQUE_IDS.has(id)) return CORE_FPS.filter((other) => other !== fp);
  if (CRYPTO_CLIQUE_IDS.has(id)) return CRYPTO_FPS.filter((other) => other !== fp);
  return undefined;
}

function isSampleContact(c: {
  fingerprint?: string;
  metadata?: { sample?: boolean; sample_revision?: number };
}): boolean {
  if (c.metadata?.sample) return true;
  const fp = (c.fingerprint || '').toLowerCase();
  return !!fp && SAMPLE_FPS.has(fp);
}

/**
 * Build the dense living roster from frozen keys, plus a few classical hollows.
 * Trust mix (~80 living):
 *  - ~18 mutual+trusted (core + extras)
 *  - ~22 trusted one-way
 *  - ~35 known living (glow hollow / keyed)
 *  - ~3 pending
 *  - ~8 classical keyless
 */
function buildSampleRoster(): SampleContact[] {
  const ordered = [...SAMPLE_SVRNTY_PEERS];
  // Stable order: clique first, then by id
  ordered.sort((a, b) => {
    const ac = CORE_CLIQUE_IDS.has(a.id) ? 0 : CRYPTO_CLIQUE_IDS.has(a.id) ? 1 : 2;
    const bc = CORE_CLIQUE_IDS.has(b.id) ? 0 : CRYPTO_CLIQUE_IDS.has(b.id) ? 1 : 2;
    return ac - bc || a.id.localeCompare(b.id);
  });

  const mutualIds = new Set<string>([
    ...CORE_CLIQUE_IDS,
    'alan', // wait alan is trusted one-way historically — keep one-way
    'shafi',
    'silvio',
    'whitfield',
    'martin',
    'ron',
    'adi',
    'frances',
    'lynn',
    'tim',
    'vint',
    'leslie',
    'nancy',
  ]);
  mutualIds.delete('alan');

  const trustedOneWay = new Set<string>([
    'alan',
    'dorothy',
    'leonard',
    'ralph',
    'feistel',
    'susan',
    'dennis',
    'ken',
    'brian',
    'donald',
    'edsger',
    'tony',
    'betty',
    'kay',
    'guido',
    'bjarne',
    'linus',
    'wing',
    'jackson',
    'darden',
    'widom',
    'wilkes',
  ]);

  const pendingIds = new Set(['frank', 'jamie', 'brendan']);

  const out: SampleContact[] = [];
  for (const p of ordered) {
    const tags = tagsFor(p.id);
    if (pendingIds.has(p.id)) {
      const grace = LIVING_BY_ID.get('grace');
      out.push({
        name: p.name,
        email: p.email.replace('@example.invalid', '@pending.intro'),
        fingerprint: '',
        trust_level: 'unverified',
        tags: [],
        pending_intro: {
          introduced_by: grace?.name || 'Grace Hopper',
          introduced_by_fp: grace?.fingerprint || '',
          context: 'Introduced at the compiler salon — accept to know; trust is separate.',
        },
        notes: 'Pending connection — accept to know; trust is separate.',
      });
      continue;
    }
    if (mutualIds.has(p.id) || CORE_CLIQUE_IDS.has(p.id)) {
      out.push({
        name: p.name,
        email: p.email.replace('@example.invalid', '@circle.demo'),
        fingerprint: '',
        trust_level: 'verified',
        tags,
        reciprocal: true,
        open_visibility: CORE_CLIQUE_IDS.has(p.id) || CRYPTO_CLIQUE_IDS.has(p.id),
        notes: CORE_CLIQUE_IDS.has(p.id)
          ? 'Mutual (PSI) · open-visibility core clique.'
          : 'Mutual (PSI) · trusted circle.',
      });
      continue;
    }
    if (trustedOneWay.has(p.id) || CRYPTO_CLIQUE_IDS.has(p.id)) {
      out.push({
        name: p.name,
        email: p.email.replace('@example.invalid', '@circle.demo'),
        fingerprint: '',
        trust_level: 'verified',
        tags,
        reciprocal: false,
        open_visibility: CRYPTO_CLIQUE_IDS.has(p.id),
        notes: CRYPTO_CLIQUE_IDS.has(p.id)
          ? 'Trusted · crypto ring — PSI mutual not yet confirmed.'
          : 'Trusted — PSI mutual not yet confirmed.',
      });
      continue;
    }
    out.push({
      name: p.name,
      email: p.email.replace('@example.invalid', '@circle.demo'),
      fingerprint: '',
      trust_level: 'unverified',
      tags,
      notes: 'Known living · keyed — not yet trusted.',
    });
  }

  // Classical hollows — keyless contrast (Invariant-1: no fingerprint).
  const classical: SampleContact[] = [
    {
      name: 'Analog Alice',
      email: 'alice@paper.mail',
      fingerprint: '',
      trust_level: 'unverified',
      tags: ['radio'],
      notes: 'Classical book · keyless / gray.',
    },
    {
      name: 'Postcard Pat',
      email: '',
      fingerprint: '',
      trust_level: 'unverified',
      tags: [],
      notes: 'Classical book · no channels shared yet.',
    },
    {
      name: 'Rolodex Remy',
      email: 'remy@office.local',
      fingerprint: '',
      trust_level: 'verified',
      tags: ['builders'],
      phones: ['+1 555 0100'],
      notes: 'Classical book · local trust only — no key.',
    },
    {
      name: 'Vellum Vera',
      email: 'vera@archive.org',
      fingerprint: '',
      trust_level: 'unverified',
      tags: ['math'],
      notes: 'Classical book · archival contact.',
    },
    {
      name: 'Ink Indira',
      email: '',
      fingerprint: '',
      trust_level: 'unverified',
      tags: ['orbital'],
      notes: 'Classical book · keyless.',
    },
    {
      name: 'Carbon Carl',
      email: 'carl@copy.room',
      fingerprint: '',
      trust_level: 'unverified',
      tags: ['compilers'],
      notes: 'Classical book · keyless.',
    },
    {
      name: 'Ledger Lea',
      email: 'lea@books.local',
      fingerprint: '',
      trust_level: 'unverified',
      tags: ['bletchley'],
      notes: 'Classical book · keyless.',
    },
    {
      name: 'Stencil Sam',
      email: '',
      fingerprint: '',
      trust_level: 'unverified',
      tags: [],
      notes: 'Classical book · empty channels.',
    },
  ];

  return [...out, ...classical];
}

const SAMPLE: SampleContact[] = buildSampleRoster();

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
    const living = LIVING_BY_NAME.get(c.name);
    const fingerprint = living?.fingerprint;
    const public_key = living?.public_key;
    const peerId = living?.id;
    const trusted = !!living && c.trust_level === 'verified';
    const theyTrust =
      fingerprint && peerId ? theyTrustFor(peerId, fingerprint) ?? (c.they_trust || undefined) : undefined;
    const openVis = fingerprint
      ? (c.open_visibility ??
        (peerId ? CORE_CLIQUE_IDS.has(peerId) || CRYPTO_CLIQUE_IDS.has(peerId) : false))
      : false;
    await addContact(ownerFingerprint, {
      name: c.name,
      email: c.email,
      // Living peers: bound fp+key from SAMPLE_SVRNTY_PEERS. Classical: empty (Invariant-1).
      fingerprint: fingerprint || '',
      public_key: public_key || '',
      trust_level: trusted ? 'verified' : 'unverified',
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
      mutual: living
        ? {
            they_trust_me: c.reciprocal === true ? true : c.reciprocal === false ? false : null,
            last_sync: c.reciprocal ? now : null,
            reciprocal: !!c.reciprocal,
          }
        : { they_trust_me: null, last_sync: null, reciprocal: false },
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
        psi_mutual: !!(living && c.reciprocal),
        they_trust: theyTrust,
        share_settings: living
          ? {
              share_card: true,
              share_trusted_circle: false,
              share_groups: false,
              open_visibility: openVis,
            }
          : undefined,
        sample_lane: living ? 'svrnty' : 'classical',
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

/** Exported for tests — living + classical roster size. */
export function sampleRosterSize(): number {
  return SAMPLE.length;
}
