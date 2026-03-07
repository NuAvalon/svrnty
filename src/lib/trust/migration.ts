// src/lib/trust/migration.ts
// Migrate legacy Contact objects to TrustEdge format.

import type { TrustEdge, LegacyContact, TrustLevel } from './types';
import { LEGACY_TRUST_MAP } from './types';
import { randomUUID } from 'crypto';

/**
 * Convert a legacy Contact to a TrustEdge.
 * Maps: unverified -> L1, verified -> L2, trusted -> L3.
 */
export function migrateContact(contact: LegacyContact): TrustEdge {
  const trustLevel = LEGACY_TRUST_MAP[contact.trust_level] ?? 1;
  const now = new Date().toISOString();

  const verificationMethod = trustLevel >= 2
    ? (contact.metadata?.connection_method === 'qr' ? 'qr' : 'email')
    : 'none';

  return {
    id: contact.id || randomUUID(),
    peer_fingerprint: contact.fingerprint,
    peer_name: contact.name,
    peer_email: contact.email,
    peer_public_key: contact.public_key,
    trust_level: trustLevel as TrustLevel,
    trust_since: contact.verified_at || contact.added_at,
    trust_history: [{
      timestamp: now,
      from_level: 0,
      to_level: trustLevel as TrustLevel,
      reason: `Migrated from legacy contact (was: ${contact.trust_level})`,
      initiated_by: 'self',
    }],
    verification: {
      method: verificationMethod,
      verified_at: contact.verified_at || null,
    },
    mutual: {
      their_level_for_me: null,
      last_sync: null,
      reciprocal: false,
    },
    tags: contact.metadata?.tags || [],
    notes: contact.metadata?.notes || '',
    connection_channels: [],
    added_at: contact.added_at,
  };
}

/**
 * Migrate an array of legacy contacts to TrustEdges.
 * Deduplicates by fingerprint (keeps the one with highest trust).
 */
export function migrateContacts(contacts: LegacyContact[]): TrustEdge[] {
  const byFingerprint = new Map<string, LegacyContact>();

  for (const contact of contacts) {
    const existing = byFingerprint.get(contact.fingerprint);
    if (!existing) {
      byFingerprint.set(contact.fingerprint, contact);
    } else {
      const existingLevel = LEGACY_TRUST_MAP[existing.trust_level] ?? 0;
      const newLevel = LEGACY_TRUST_MAP[contact.trust_level] ?? 0;
      if (newLevel > existingLevel) {
        byFingerprint.set(contact.fingerprint, contact);
      }
    }
  }

  return Array.from(byFingerprint.values()).map(migrateContact);
}
