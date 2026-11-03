// The patch the contact edit form, owner verification, block and link-to-SVRNTY writes make, decided from the record the store holds when the
// write runs. Same rule as tag-patches.ts: each function takes the held record and nothing that carries an earlier copy of it
// (the open dialog, the list row), so a nested value is never written back to what a screen showed.
//
// Run: npx tsx --test src/lib/contacts/metadata-patches.test.ts

import type { ContactRecord } from '@/lib/identity/client-store';
import { linkToSvrntyPatch } from '@/lib/contacts/contact-lane';
import { ownerVerifyPersistPatch } from '@/lib/trust/trust-recipe';
import { distressWentPersistPatch } from '@/lib/trust/distress';

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

/** Clear the inbound-distress mark on this device, on top of the metadata the held record carries. */
export function distressWentHeldPatch(fresh: ContactRecord): Patch {
  return distressWentPersistPatch(fresh.metadata) as unknown as Patch;
}

/** Accept an introduction: the connection becomes accepted and the pending introduction is cleared, on top of the held metadata. */
export function acceptIntroHeldPatch(fresh: ContactRecord): Patch {
  return {
    connection_status: 'accepted',
    metadata: { ...fresh.metadata, connection_status: 'accepted', pending_intro: undefined },
    pending_intro: undefined,
  } as unknown as Patch;
}

/**
 * Add a group label to the tags the held record carries (once). The tags live at the top level and in the metadata; both are set from the
 * held record, so they stay equal and a tag added elsewhere since a screen was drawn survives.
 */
export function addLabelHeldPatch(fresh: ContactRecord, label: string): Patch {
  const prev = ((fresh as { tags?: string[] }).tags ?? (fresh.metadata?.tags as string[] | undefined) ?? []);
  const tags = Array.from(new Set([...prev, label]));
  return { tags, metadata: { ...fresh.metadata, tags } } as unknown as Patch;
}

/**
 * The trust-map contact edit. Only what the owner changed is taken from `patch`; every other field keeps what the HELD record has now (the
 * screen's older copy is never used as a default), and the metadata keys the held record carries are kept.
 */
export function trustMapEditPatch(
  fresh: ContactRecord,
  patch: { name?: string; email?: string; notes?: string; phones?: string[] },
): Patch {
  const heldNotes = (fresh as { notes?: string }).notes ?? (fresh.metadata?.notes as string | undefined) ?? '';
  const notes = patch.notes ?? heldNotes;
  const info = (fresh.contact_info ?? {}) as { phones?: string[]; emails?: string[] };
  return {
    name: patch.name ?? fresh.name,
    email: patch.email ?? fresh.email,
    notes,
    contact_info: {
      ...(fresh.contact_info ?? {}),
      phones: patch.phones ?? info.phones,
      emails: patch.email ? [patch.email] : info.emails,
    },
    metadata: { ...fresh.metadata, notes },
  } as unknown as Patch;
}
