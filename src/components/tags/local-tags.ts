/**
 * CUR-8 — local private-tag helpers (owner-authored labels only).
 *
 * Tags are CLIENT-ONLY organization. Never include them in peer/relay publish
 * payloads — Apollo strip-on-wire. This module is pure UI bookkeeping over
 * contact records; no crypto, no gate, no sync.
 */

export const TAG_MAX_LEN = 32;
export const TAG_MAX_PER_CONTACT = 24;

export type TagReadable = {
  id?: string;
  tags?: string[];
  metadata?: { tags?: string[] | null } | null;
};

export type TagCatalogEntry = {
  /** Canonical display label (first-seen casing preserved). */
  label: string;
  /** Contact ids that carry this tag. */
  memberIds: string[];
};

/** Bound + strip control / bidi-spoof chars (I-10a canvas/text hygiene). */
export function sanitizeTagText(raw: string): string {
  return Array.from(raw.normalize('NFC'))
    .filter((ch) => {
      const code = ch.codePointAt(0) ?? 0;
      if (code < 0x20 || code === 0x7f) return false;
      // bidi overrides / isolates
      if (code >= 0x202a && code <= 0x202e) return false;
      if (code >= 0x2066 && code <= 0x2069) return false;
      return true;
    })
    .join('')
    .trim();
}

/**
 * Normalize a user-typed tag label for storage.
 * Returns null when empty / too long after sanitize.
 */
export function normalizeTagLabel(raw: string): string | null {
  const cleaned = sanitizeTagText(raw).replace(/\s+/g, ' ');
  if (!cleaned) return null;
  if (cleaned.length > TAG_MAX_LEN) return null;
  return cleaned;
}

export function tagsMatch(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/** Read tags from either top-level or metadata bag (ContactRecord open shape). */
export function readContactTags(contact: TagReadable): string[] {
  const fromTop = Array.isArray(contact.tags) ? contact.tags : [];
  const fromMeta = Array.isArray(contact.metadata?.tags) ? contact.metadata!.tags! : [];
  const source = fromTop.length > 0 ? fromTop : fromMeta;
  const out: string[] = [];
  for (const t of source) {
    if (typeof t !== 'string') continue;
    const n = normalizeTagLabel(t);
    if (!n) continue;
    if (out.some((x) => tagsMatch(x, n))) continue;
    out.push(n);
    if (out.length >= TAG_MAX_PER_CONTACT) break;
  }
  return out;
}

export function assignTag(existing: string[], label: string): string[] {
  const n = normalizeTagLabel(label);
  if (!n) return [...existing];
  if (existing.some((t) => tagsMatch(t, n))) return [...existing];
  if (existing.length >= TAG_MAX_PER_CONTACT) return [...existing];
  return [...existing, n];
}

export function removeTag(existing: string[], label: string): string[] {
  return existing.filter((t) => !tagsMatch(t, label));
}

export function renameTag(existing: string[], from: string, to: string): string[] {
  const next = normalizeTagLabel(to);
  if (!next) return removeTag(existing, from);
  let seen = false;
  const out: string[] = [];
  for (const t of existing) {
    if (tagsMatch(t, from)) {
      if (!seen && !out.some((x) => tagsMatch(x, next))) {
        out.push(next);
        seen = true;
      }
      continue;
    }
    if (tagsMatch(t, next)) continue; // collapse duplicate after rename
    out.push(t);
  }
  return out;
}

/** Build the owner's private tag catalog from their local contacts. */
export function collectTagCatalog(
  contacts: Array<TagReadable & { id: string }>
): TagCatalogEntry[] {
  const map = new Map<string, TagCatalogEntry>();
  for (const c of contacts) {
    if (!c.id) continue;
    for (const label of readContactTags(c)) {
      const key = label.toLowerCase();
      const entry = map.get(key);
      if (entry) {
        if (!entry.memberIds.includes(c.id)) entry.memberIds.push(c.id);
      } else {
        map.set(key, { label, memberIds: [c.id] });
      }
    }
  }
  return [...map.values()].sort((a, b) => a.label.localeCompare(b.label));
}

/**
 * Patch shape for IndexedDB updateContact — keep tags on BOTH top-level and
 * metadata so TrustMap projection (contact-edge) and older readers stay in sync.
 * Local-only — never feed this object into a peer/relay publish path.
 */
export function tagPersistPatch(
  prevMetadata: Record<string, unknown> | null | undefined,
  tags: string[]
): { tags: string[]; metadata: Record<string, unknown> } {
  return {
    tags,
    metadata: { ...(prevMetadata || {}), tags },
  };
}
