/**
 * Classical vs SVRNTY contact lane — UI semantics only.
 *
 * SVRNTY = active network peer (fingerprint + public_key).
 * Classical = address-book-only (keyless / not yet linked).
 *
 * Peer↔peer mutual trust + disclosure-reach remain fleet-owned (PSI / visible()).
 * This module only shapes local metadata the glass can render.
 */

import { isSvrnNetworkContact } from '@/lib/contacts/is-svrn-contact';

export type ContactLane = 'classical' | 'svrnty';

export type ContactConnectionStatus = 'pending' | 'active';

export type ContactShareSettings = {
  /** What I disclose to them — local intent until fleet reach wire lands. */
  share_card: boolean;
  share_trusted_circle: boolean;
  share_groups: boolean;
  /**
   * Open visibility for trusted contacts. When I trust Sally and Joe, they
   * trust me, and all three opt in, I see that they trust each other (fleet
   * PSI / they_trust) — consented disclosure, never inferred from tags.
   */
  open_visibility: boolean;
};

export type ClassicalExtras = {
  name?: string;
  email?: string;
  phones?: string[];
  emails?: string[];
  urls?: string[];
  handles?: Record<string, string>;
  notes?: string;
};

export function contactLane(c: {
  fingerprint?: string | null;
  public_key?: string | null;
}): ContactLane {
  return isSvrnNetworkContact(c) ? 'svrnty' : 'classical';
}

/** SVRNTY without an active bond — they haven't added you / no pulse yet. */
export function isPendingSvrntyContact(c: {
  fingerprint?: string | null;
  public_key?: string | null;
  connection_status?: string | null;
  metadata?: { connection_status?: string | null; pending?: boolean } | null;
}): boolean {
  if (!isSvrnNetworkContact(c)) return false;
  const status =
    (c.connection_status || c.metadata?.connection_status || '').toLowerCase();
  if (status === 'pending') return true;
  if (c.metadata?.pending === true) return true;
  return false;
}

export function defaultShareSettings(
  partial?: Partial<ContactShareSettings> | null,
): ContactShareSettings {
  return {
    share_card: partial?.share_card ?? true,
    share_trusted_circle: partial?.share_trusted_circle ?? false,
    share_groups: partial?.share_groups ?? false,
    open_visibility: partial?.open_visibility ?? false,
  };
}

export function readShareSettings(c: {
  metadata?: { share_settings?: Partial<ContactShareSettings> } | null;
}): ContactShareSettings {
  return defaultShareSettings(c.metadata?.share_settings);
}

/**
 * Snapshot classical channels before linking to SVRNTY so they can render
 * as "additional information" on the living card (not wire fields).
 */
export function snapshotClassicalExtras(c: {
  name?: string;
  email?: string;
  contact_info?: {
    phones?: string[];
    emails?: string[];
    urls?: string[];
    handles?: Record<string, string>;
  } | null;
  metadata?: { notes?: string } | null;
}): ClassicalExtras {
  return {
    name: c.name || undefined,
    email: c.email || undefined,
    phones: [...(c.contact_info?.phones || [])],
    emails: [...(c.contact_info?.emails || [])],
    urls: [...(c.contact_info?.urls || [])],
    handles: { ...(c.contact_info?.handles || {}) },
    notes: c.metadata?.notes || undefined,
  };
}

/** Merge link payload: classical → SVRNTY (pending until fleet confirms reciprocal). */
export function buildLinkToSvrntyUpdate(args: {
  fingerprint: string;
  public_key: string;
  existing: {
    name?: string;
    email?: string;
    contact_info?: ClassicalExtras | null;
    metadata?: Record<string, unknown> | null;
  };
}): {
  fingerprint: string;
  public_key: string;
  connection_status: 'pending';
  metadata: Record<string, unknown>;
} {
  const extras = snapshotClassicalExtras({
    name: args.existing.name,
    email: args.existing.email,
    contact_info: args.existing.contact_info,
    metadata: args.existing.metadata as { notes?: string } | null,
  });
  const prev = (args.existing.metadata || {}) as Record<string, unknown>;
  return {
    fingerprint: args.fingerprint.trim(),
    public_key: args.public_key.trim(),
    connection_status: 'pending',
    metadata: {
      ...prev,
      connection_status: 'pending',
      pending: true,
      classical_extras: extras,
      linked_from_classical_at: new Date().toISOString(),
    },
  };
}

export function readClassicalExtras(c: {
  metadata?: { classical_extras?: ClassicalExtras } | null;
}): ClassicalExtras | null {
  const extras = c.metadata?.classical_extras;
  if (!extras) return null;
  const has =
    extras.email ||
    extras.notes ||
    (extras.phones && extras.phones.length) ||
    (extras.emails && extras.emails.length) ||
    (extras.urls && extras.urls.length) ||
    (extras.handles && Object.keys(extras.handles).length);
  return has ? extras : null;
}
