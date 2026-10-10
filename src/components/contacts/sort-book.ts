/**
 * Living Address Book order — name, or trusted-first then name.
 * Trust stays boolean. No score, rank, or last-seen.
 */

export type BookSort = 'name-asc' | 'name-desc' | 'trusted-first';

export const BOOK_SORTS: ReadonlyArray<{ id: BookSort; label: string }> = [
  { id: 'name-asc', label: 'Name A–Z' },
  { id: 'name-desc', label: 'Name Z–A' },
  { id: 'trusted-first', label: 'Trusted first' },
];

export function isBookTrusted(row: { trusted?: boolean; trust_level?: string }): boolean {
  if (row.trusted === false) return false;
  if (row.trusted === true) return true;
  const t = (row.trust_level || '').toLowerCase();
  return t === 'trusted' || t === 'verified';
}

function nameKey(name?: string): string {
  return (name || '').trim();
}

function byName(a: { name?: string }, b: { name?: string }): number {
  return nameKey(a.name).localeCompare(nameKey(b.name), undefined, { sensitivity: 'base' });
}

export function sortBookContacts<T extends { name?: string; trusted?: boolean; trust_level?: string }>(
  rows: readonly T[],
  sort: BookSort = 'name-asc',
): T[] {
  const copy = [...rows];
  if (sort === 'name-desc') return copy.sort((a, b) => byName(b, a));
  if (sort === 'trusted-first') {
    return copy.sort((a, b) => {
      const ta = isBookTrusted(a) ? 0 : 1;
      const tb = isBookTrusted(b) ? 0 : 1;
      if (ta !== tb) return ta - tb;
      return byName(a, b);
    });
  }
  return copy.sort(byName);
}
