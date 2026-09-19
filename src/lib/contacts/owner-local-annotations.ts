/**
 * Receiver-local annotations on a received contact.
 *
 * Alias + notes live in `owner_local` on the ContactRecord open bag (no
 * schema change, no migration). They are THIS DEVICE'S words about someone —
 * preserved across sender card-updates because apply only writes allowlisted
 * wire fields onto a shallow copy of the stored record.
 *
 * Tags / groups stay in metadata.tags (existing). All of these are
 * device-local: never serialize onto publish / PSI-sync / vCard export.
 */

export const OWNER_LOCAL_FIELD = 'owner_local';

export type OwnerLocalAnnotations = {
  alias?: string;
  notes?: string;
};

const ALIAS_MAX = 80;
const NOTES_MAX = 2000;

function stripControls(s: string): string {
  return s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
}

function bound(s: string, max: number): string {
  return stripControls(s).slice(0, max);
}

export function emptyOwnerLocal(): OwnerLocalAnnotations {
  return {};
}

export function readOwnerLocal(record: {
  owner_local?: unknown;
  [key: string]: unknown;
}): OwnerLocalAnnotations {
  const raw = record.owner_local;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const o = raw as Record<string, unknown>;
  const alias = typeof o.alias === 'string' ? bound(o.alias, ALIAS_MAX) : undefined;
  const notes = typeof o.notes === 'string' ? bound(o.notes, NOTES_MAX) : undefined;
  const out: OwnerLocalAnnotations = {};
  if (alias?.trim()) out.alias = alias.trim();
  if (notes) out.notes = notes;
  return out;
}

export function patchOwnerLocal(
  current: OwnerLocalAnnotations,
  patch: Partial<OwnerLocalAnnotations>,
): OwnerLocalAnnotations {
  const aliasSrc = patch.alias !== undefined ? patch.alias : current.alias || '';
  const notesSrc = patch.notes !== undefined ? patch.notes : current.notes || '';
  const alias = bound(aliasSrc, ALIAS_MAX).trim();
  const notes = bound(notesSrc, NOTES_MAX);
  const out: OwnerLocalAnnotations = {};
  if (alias) out.alias = alias;
  if (notes.trim()) out.notes = notes;
  return out;
}

/** Display name: owner alias wins over the sender's card name (local only). */
export function displayNameWithAlias(
  cardName: string | undefined,
  local: OwnerLocalAnnotations,
): string {
  return (local.alias || cardName || '').trim() || 'Unnamed';
}

/**
 * Strip receiver-local fields from a publish / PSI-sync / export-shaped payload.
 * Defence-in-depth next to fleet `stripOwnerLocalForPublish` (which does not
 * yet know `owner_local` — asked in the PR).
 */
export function stripOwnerLocalAnnotations<T extends Record<string, unknown>>(payload: T): T {
  const out: Record<string, unknown> = { ...payload };
  delete out.owner_local;
  delete out.alias;
  const meta = out.metadata;
  if (meta && typeof meta === 'object' && !Array.isArray(meta)) {
    const next = { ...(meta as Record<string, unknown>) };
    delete next.owner_local;
    delete next.alias;
    delete next.tags;
    delete next.blocked;
    out.metadata = next;
  }
  return out as T;
}

export function ownerLocalLeaksInText(text: string, local: OwnerLocalAnnotations): boolean {
  if (local.alias && local.alias.length >= 4 && text.includes(local.alias)) return true;
  if (local.notes && local.notes.length >= 8 && text.includes(local.notes)) return true;
  return false;
}
