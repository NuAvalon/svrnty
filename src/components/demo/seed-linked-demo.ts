/**
 * Demo glass: mint extra local vaults and cross-link them so the book
 * shows classical (keyless sample) next to living SVRNTY cards.
 * Calls fleet generateIdentity / addContact / seedSampleCircle — does not mint keys itself.
 * Does not edit the fenced sample-circle seed.
 *
 * SAMPLE_SVRNTY_PEERS cannot be stored: their OpenPGP fps fail
 * fingerprintMatchesKey (canonical-only). Living rows must be real vaults.
 */

import { getBrowserIdentity } from '@/lib/identity/browser-identity';
import {
  addContact,
  getActiveFingerprint,
  getContactByFingerprint,
  listIdentities,
  loadIdentity,
  setActiveFingerprint,
  storeIdentity,
} from '@/lib/identity/client-store';
import { seedSampleCircle } from '@/lib/trust/sample-circle';

/** Full extra vaults — they show under Switch identity. */
export const LINKED_DEMO_VAULTS = [
  { name: 'River Vale', email: 'river@example.invalid' },
  { name: 'Sage Quinn', email: 'sage@example.invalid' },
] as const;

type VaultCard = {
  name: string;
  email: string;
  fingerprint: string;
  public_key: string;
  pq_kem_public_key?: string;
  pq_sig_public_key?: string;
};

function nowIso() {
  return new Date().toISOString();
}

async function addLiving(
  ownerFp: string,
  peer: VaultCard,
  extra: {
    trusted: boolean;
    reciprocal: boolean;
    notes: string;
    tags?: string[];
  },
) {
  if (!peer.fingerprint || !peer.public_key) return;
  const existing = await getContactByFingerprint(ownerFp, peer.fingerprint);
  if (existing) return;
  const now = nowIso();
  await addContact(ownerFp, {
    name: peer.name,
    email: peer.email,
    fingerprint: peer.fingerprint,
    public_key: peer.public_key,
    pq_kem_public_key: peer.pq_kem_public_key,
    pq_sig_public_key: peer.pq_sig_public_key,
    trust_level: extra.trusted ? 'verified' : 'unverified',
    trusted: extra.trusted,
    trusted_since: extra.trusted ? now : null,
    last_interaction: now,
    decay_days: 730,
    tags: extra.tags || ['linked-demo'],
    notes: extra.notes,
    contact_info: { emails: peer.email ? [peer.email] : undefined },
    mutual: {
      they_trust_me: extra.reciprocal,
      last_sync: extra.reciprocal ? now : null,
      reciprocal: extra.reciprocal,
    },
    verification: extra.trusted
      ? { method: 'in_person', verified_at: now }
      : { method: 'none', verified_at: null },
    connection_status: 'accepted',
    metadata: {
      demo_linked: true,
      tags: extra.tags || ['linked-demo'],
      notes: extra.notes,
    },
  } as Parameters<typeof addContact>[1]);
}

function vaultFromIdentity(data: {
  identity?: { name?: string; email?: string; fingerprint?: string; public_key?: string };
  post_quantum?: { kem_public_key?: string; sig_public_key?: string };
}): VaultCard | null {
  const fingerprint = data.identity?.fingerprint || '';
  const public_key = data.identity?.public_key || '';
  if (!fingerprint || !public_key) return null;
  return {
    name: data.identity?.name || 'Unnamed',
    email: data.identity?.email || '',
    fingerprint,
    public_key,
    pq_kem_public_key: data.post_quantum?.kem_public_key,
    pq_sig_public_key: data.post_quantum?.sig_public_key,
  };
}

async function ensureDemoVaults(): Promise<VaultCard[]> {
  const listed = await listIdentities();
  const have = new Map<string, VaultCard>();
  for (const row of listed) {
    const card = vaultFromIdentity(row.data || {});
    if (!card) continue;
    have.set(card.name, card);
  }

  const missing = LINKED_DEMO_VAULTS.filter((v) => !have.has(v.name));
  if (missing.length === 0) {
    return LINKED_DEMO_VAULTS.map((v) => have.get(v.name)!);
  }

  const previous = await getActiveFingerprint();
  const bi = getBrowserIdentity();
  try {
    for (const spec of missing) {
      const minted = await bi.generateIdentity({ name: spec.name, email: spec.email });
      const data = await loadIdentity(minted.fingerprint);
      if (data) {
        data.metadata = { ...(data.metadata || {}), demo_linked: true };
        await storeIdentity(minted.fingerprint, data);
      }
      const card = vaultFromIdentity(data || minted.identity);
      if (card) have.set(card.name, card);
    }
  } finally {
    if (previous) await setActiveFingerprint(previous);
  }

  return LINKED_DEMO_VAULTS.map((v) => have.get(v.name)).filter((v): v is VaultCard => !!v);
}

/**
 * Mint two switchable vaults, seed classical sample on each, then cross-link
 * owner ↔ vaults as living SVRNTY cards (bound key + fingerprint).
 */
export async function seedLinkedDemo(owner: VaultCard): Promise<{ vaults: number; living: number }> {
  const vaults = await ensureDemoVaults();

  for (const vault of vaults) {
    await seedSampleCircle(vault.fingerprint);
  }

  const river = vaults.find((v) => v.name === 'River Vale');
  const sage = vaults.find((v) => v.name === 'Sage Quinn');

  if (river) {
    await addLiving(owner.fingerprint, river, {
      trusted: true,
      reciprocal: true,
      notes: 'Living SVRNTY card — bound key, mutual trust. Switch identity to open their book.',
    });
  }
  if (sage) {
    await addLiving(owner.fingerprint, sage, {
      trusted: true,
      reciprocal: false,
      notes: 'Living SVRNTY card — bound key; you trust them. They have not affirmed back.',
    });
  }

  const circle: VaultCard[] = [owner, ...vaults].filter((v) => v.fingerprint && v.public_key);
  for (const a of circle) {
    for (const b of circle) {
      if (a.fingerprint === b.fingerprint) continue;
      if (a.fingerprint === owner.fingerprint) continue;
      await addLiving(a.fingerprint, b, {
        trusted: true,
        reciprocal: true,
        notes: 'Linked demo vault — switch identity to open their book.',
      });
    }
  }

  return { vaults: vaults.length, living: vaults.length };
}
