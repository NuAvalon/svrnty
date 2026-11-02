// The patch the contact edit form, owner verification, block and link-to-SVRNTY writes make, decided from the record the store holds when the
// write runs. Same rule as tag-patches.ts: each function takes the held record and nothing that carries an earlier copy of it
// (the open dialog, the list row), so a nested value is never written back to what a screen showed.
//
// Run: npx tsx --test src/lib/contacts/metadata-patches.test.ts

import type { ContactRecord } from '@/lib/identity/client-store';
import { linkToSvrntyPatch } from '@/lib/contacts/contact-lane';
import { ownerVerifyPersistPatch } from '@/lib/trust/trust-recipe';

type Patch = Partial<ContactRecord>;

/** The classical edit form: the fields the owner typed, with every metadata key the held record carries kept and only `notes` replaced. */
export function editFormPatch(
  fresh: ContactRecord,
  form: { name: string; email: string; contact_info: ContactRecord['contact_info']; notes: string },
): Patch {
  return {
    name: form.name,
    email: form.email,
    contact_info: form.contact_info,
    metadata: { ...fresh.metadata, notes: form.notes },
  };
}

/** Record an owner-local verification on top of the metadata the held record carries. */
export function ownerVerifyHeldPatch(fresh: ContactRecord, method: 'in_person' | 'other_channel'): Patch {
  return ownerVerifyPersistPatch(fresh.metadata, method) as unknown as Patch;
}

/**
 * Block or unblock. Blocking clears trust and open_visibility on the held record so the peer leaves every reveal set; the other
 * share settings and metadata keys the held record carries are kept. Unblocking changes only the flag.
 */
export function blockPatch(fresh: ContactRecord, blocked: boolean): Patch {
  return {
    blocked,
    ...(blocked ? { trusted: false, trust_level: 'unverified', trusted_since: null } : {}),
    metadata: {
      ...fresh.metadata,
      blocked,
      ...(blocked ? { share_settings: { ...(fresh.metadata?.share_settings || {}), open_visibility: false } } : {}),
    },
  } as unknown as Patch;
}

/** Link a classical contact to a bound SVRNTY identity: classical channels are snapshotted from the held record, trust restarts at unverified. */
export function linkHeldPatch(fresh: ContactRecord, bound: { fingerprint: string; public_key: string }): Patch {
  return { ...linkToSvrntyPatch(fresh as Parameters<typeof linkToSvrntyPatch>[0], bound), trust_level: 'unverified' } as unknown as Patch;
}
