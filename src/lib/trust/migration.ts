// src/lib/trust/migration.ts
// Migrate legacy Contact objects to binary TrustEdge format.

import type { TrustEdge, LegacyContact } from './types';
import { migrateTrustLevel } from './types';
import { randomUUID } from 'crypto';

const DEFAULT_DECAY_DAYS = 730;

/**
 * Convert a legacy Contact to a binary TrustEdge.
 * 'unverified' -> known (not trusted)
 * 'verified' or 'trusted' -> trusted
 */
export function migrateContact(contact: LegacyContact): TrustEdge {
  const trusted = migrateTrustLevel(contact.trust_level);
  const now = new Date().toISOString();

  const verificationMethod = contact.verified_at
    ? (contact.metadata?.connection_method === 'qr' ? 'qr' : 'email')
    : 'none';

  return {
    id: contact.id || randomUUID(),
    peer_fingerprint: contact.fingerprint,
    peer_name: contact.name,
    peer_email: contact.email,
    peer_public_key: contact.public_key,
    trusted,
    trusted_since: trusted ? (contact.verified_at || contact.added_at) : null,
    last_interaction: contact.verified_at || contact.added_at,
    decay_days: DEFAULT_DECAY_DAYS,
    trust_history: [{
      timestamp: now,
      action: trusted ? 'trust' as const : 'reverify' as const,
      reason: `Migrated from legacy contact (was: ${contact.trust_level})`,
      initiated_by: 'self' as const,
    }],
    verification: {
      method: verificationMethod,
      verified_at: contact.verified_at || null,
    },
    mutual: {
      they_trust_me: null,
      last_sync: null,
      reciprocal: false,
    },
    tags: contact.metadata?.tags || [],
    notes: contact.metadata?.notes || '',
    connection_channels: contact.metadata?.connection_method ? [contact.metadata.connection_method] : [],
    added_at: contact.added_at,
  };
}

/**
 * Migrate an array of legacy contacts to TrustEdges.
 * Deduplicates by fingerprint (keeps the trusted one if conflict).
 */
export function migrateContacts(contacts: LegacyContact[]): TrustEdge[] {
  const byFingerprint = new Map<string, LegacyContact>();

  for (const contact of contacts) {
    const existing = byFingerprint.get(contact.fingerprint);
    if (!existing) {
      byFingerprint.set(contact.fingerprint, contact);
    } else {
      // Keep the one with higher trust
      const existingTrusted = migrateTrustLevel(existing.trust_level);
      const newTrusted = migrateTrustLevel(contact.trust_level);
      if (newTrusted && !existingTrusted) {
        byFingerprint.set(contact.fingerprint, contact);
      }
    }
  }

  return Array.from(byFingerprint.values()).map(migrateContact);
}
