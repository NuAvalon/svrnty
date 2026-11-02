/**
 * Galaxy name search — glass only.
 * Hits glow on the map. Does not filter stars (absence stays uninformative).
 * Does not count matches (I-3).
 */

export function normalizeGalaxyQuery(raw: string): string {
  return raw
    .normalize('NFC')
    .replace(/[\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/[\x00-\x1f]/g, '')
    .trim()
    .toLowerCase();
}

export function galaxyNameHit(name: string | undefined, query: string): boolean {
  const q = normalizeGalaxyQuery(query);
  if (!q) return false;
  const n = normalizeGalaxyQuery(String(name || ''));
  return n.length > 0 && n.includes(q);
}

export function galaxySearchHitIds(
  nodes: Array<{ id: string; name?: string }>,
  query: string,
): string[] {
  if (!normalizeGalaxyQuery(query)) return [];
  return nodes.filter((n) => galaxyNameHit(n.name, query)).map((n) => n.id);
}
