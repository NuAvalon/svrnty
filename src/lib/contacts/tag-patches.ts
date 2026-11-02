// The patch each group (tag) edit writes, decided from the record the store holds when the write runs.
//
// Every function takes ONLY that record. There is no second parameter that carries a copy captured earlier (the open dialog, a list loaded
// before a loop), so a stale copy cannot reach the tag list. An empty patch means "nothing to change here".
//
// Run: npx tsx --test src/lib/contacts/tag-patches.test.ts

import type { ContactRecord } from '@/lib/identity/client-store';

type Patch = Partial<ContactRecord>;

const tagsOf = (fresh: ContactRecord): string[] => (fresh.metadata?.tags as string[] | undefined) || [];

/** Add `tag` if the held record lacks it, remove it if it has it. */
export function toggleTagPatch(fresh: ContactRecord, tag: string): Patch {
  const prev = tagsOf(fresh);
  const tags = prev.includes(tag) ? prev.filter((t) => t !== tag) : [...prev, tag];
  return { metadata: { ...fresh.metadata, tags } };
}

/** Rename `from` to `to` on the held record; nothing to change when the held record does not carry `from`. */
export function renameTagPatch(fresh: ContactRecord, from: string, to: string): Patch {
  const cur = tagsOf(fresh);
  if (!cur.includes(from)) return {};
  return { metadata: { ...fresh.metadata, tags: Array.from(new Set(cur.map((t) => (t === from ? to : t)))) } };
}

/** Remove `tag` from the held record; nothing to change when the held record does not carry it. */
export function removeTagPatch(fresh: ContactRecord, tag: string): Patch {
  const cur = tagsOf(fresh);
  return cur.includes(tag) ? { metadata: { ...fresh.metadata, tags: cur.filter((t) => t !== tag) } } : {};
}

/** Add `name` to the tags the held record carries (once). */
export function addTagPatch(fresh: ContactRecord, name: string): Patch {
  return { metadata: { ...fresh.metadata, tags: Array.from(new Set([...tagsOf(fresh), name])) } };
}
