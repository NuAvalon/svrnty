// The share-settings write and the consent it reconciles, each decided from ONE record.
//
// `shareSettingsPatch` takes the record the store holds when the write runs. It has no other source of "trusted" and no other source of
// metadata, so the trusted-only clamp is decided on that record and nothing else.
// `consentFromRecord` takes the record read back AFTER the write, so the allowed-senders mirror matches what was stored, not what the
// screen showed or what the owner chose.
//
// Kept apart from contact-lane so it can use the trust modules without a cycle.
//
// Run: npx tsx --test src/lib/contacts/share-settings-patch.test.ts

import type { ContactRecord } from '@/lib/identity/client-store';
import { applyShareSettingsChange, readShareSettings, type ContactShareSettings } from '@/lib/contacts/contact-lane';
import { edgeTrusted } from '@/lib/trust/contact-edge';
import { isContactBlocked } from '@/components/trust-actions/trust-actions';

/** The patch that stores the owner's share-settings change on top of what the held record carries. */
export function shareSettingsPatch(
  fresh: ContactRecord,
  seen: ContactShareSettings,
  next: ContactShareSettings,
): Partial<ContactRecord> {
  return {
    metadata: {
      ...fresh.metadata,
      share_settings: applyShareSettingsChange(fresh.metadata?.share_settings, seen, next, edgeTrusted(fresh)),
    },
  };
}

export interface ConsentFromRecord {
  trusted: boolean;
  openVisibility: boolean;
  blocked: boolean;
  perContactPrivate: boolean;
}

/**
 * The consent the allowed-senders mirror is reconciled to, read from a stored record.
 * `trusted` is `edgeTrusted`, the same definition the clamp uses (an explicit `trusted: false` wins over `trust_level`).
 */
export function consentFromRecord(rec: {
  trusted?: boolean;
  trust_level?: string;
  blocked?: boolean;
  metadata?: { blocked?: boolean; share_settings?: Partial<ContactShareSettings> } | null;
}): ConsentFromRecord {
  const share = readShareSettings(rec);
  return {
    trusted: edgeTrusted(rec),
    openVisibility: share.open_visibility === true,
    blocked: isContactBlocked(rec as { blocked?: boolean; metadata?: { blocked?: boolean } }),
    perContactPrivate: share.per_contact_private === true,
  };
}

/** Consent for a contact that is gone: nothing is open, so the mirror row is removed. */
export const NO_CONSENT: ConsentFromRecord = { trusted: false, openVisibility: false, blocked: false, perContactPrivate: false };
