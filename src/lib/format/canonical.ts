// src/lib/format/canonical.ts
// Canonical serialization for signed svrnty objects (Queue B lane 0.1/0.2 — Archie).
// This is the byte-string Flint's 0.1 canonical-sign-envelope signs over. Byte-identical
// across implementations for equal input — the seam contract between format (me) and crypto (Flint).
// Spec: shared/outbox/archie/svrnty_queueB_0.13_dedup_and_0.1_0.2_format_v1.md §A1

export interface CanonicalizeOptions {
  /** Top-level keys to exclude from the canonical form (e.g. ['signature']). */
  exclude?: string[];
}

/**
 * Deterministic canonical serialization. Rules:
 *  - strings NFC-normalized (é composed == decomposed → no signature breaks)
 *  - object keys sorted by UTF-16 code unit, recursively
 *  - no insignificant whitespace
 *  - integers only (floats rejected — non-canonical repr in signed structures)
 *  - null rejected (absent ≠ null; omit optional fields instead)
 *  - top-level key exclusion (sign-then-attach: exclude 'signature' from its own input)
 */
export function canonicalize(value: unknown, opts: CanonicalizeOptions = {}): string {
  return canon(value, new Set(opts.exclude ?? []), true);
}

function canon(v: unknown, ex: Set<string>, top: boolean): string {
  if (v === null) throw new Error('canonicalize: null is never a signed value — omit the field');
  const t = typeof v;
  if (t === 'string') return JSON.stringify((v as string).normalize('NFC'));
  if (t === 'boolean') return v ? 'true' : 'false';
  if (t === 'number') {
    const n = v as number;
    if (!Number.isFinite(n)) throw new Error('canonicalize: non-finite number');
    if (!Number.isInteger(n)) throw new Error('canonicalize: floats not allowed in signed structures');
    return String(n);
  }
  if (Array.isArray(v)) return '[' + v.map((x) => canon(x, ex, false)).join(',') + ']';
  if (t === 'object') {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined && !(top && ex.has(k)))
      .sort(); // default JS sort = UTF-16 code unit order
    return '{' + keys.map((k) => JSON.stringify(k.normalize('NFC')) + ':' + canon(obj[k], ex, false)).join(',') + '}';
  }
  throw new Error('canonicalize: unsupported type ' + t);
}
