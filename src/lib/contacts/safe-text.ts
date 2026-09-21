// src/lib/contacts/safe-text.ts
// §9 layer-3 — INGESTION text sanitization (Flint pin #141768, Contextual-Output-Encoding doctrine).
//
// THE DOCTRINE. Escape at each SINK in that sink's context (React auto-escapes HTML; vCard export
// escapes vCard; URL resolution scheme-allowlists). We do NOT blanket-HTML-escape or reject markup at
// ingestion — a peer's legit "Tom & Jerry" / "a<b" / "<3" must survive round-trips (rejecting/escaping
// it at ingestion would corrupt display and break propagation semantics = do-harm).
//
// WHAT INGESTION *DOES* strip — the class render-escaping structurally CANNOT catch, and which has NO
// legitimate display use: invisible / control / bidi-control characters. These are the Trojan-Source
// (CVE-2021-42574) + homoglyph-spoofing + invisible-worm-marker class. A peer could otherwise push a
// display_name that renders right-to-left-spoofed or carries invisible propagation markers straight
// into your address book — React escaping leaves them untouched. Stripping them at ingestion (before
// the store) is enforce-by-construction: a downstream render that forgets a safety wrapper still cannot
// surface a spoofed/booby-trapped string, because the store never held one.
//
// STRIPPED (always): C0/C1 controls, bidi embeddings/overrides (U+202A–202E), bidi isolates
// (U+2066–2069), bidi marks LRM/RLM/ALM (U+200E/200F/061C), zero-width & invisible
// (U+200B–200D ZW*, U+2060 word-joiner, U+FEFF BOM, U+00AD soft-hyphen). Then NFC-normalize + bound.
// PRESERVED for multi-line fields (note): TAB (U+0009) and LINE FEED (U+000A) — legit formatting;
// CR/CRLF is normalized to LF first so a lone CR can't inject a vCard header line downstream.

/** Ingestion length bounds (new — display_name/note were previously unbounded at the apply boundary). */
export const DISPLAY_NAME_MAX = 256;
export const NOTE_MAX = 4096;
/** Single-line method value bound (emails/phones) — handles/urls keep their own tighter wire bounds. */
export const METHOD_VALUE_MAX = 256;
/** URL bound (matches the contact.update wire URL_VALUE_MAX_LEN). */
export const URL_MAX = 512;

// Always-strip set: control + bidi + zero-width/invisible. Two variants only differ on whether TAB+LF
// are also stripped (single-line fields strip them; multi-line `note` keeps them).
// U+2028/2029 (line/paragraph separators) included: JS line-terminators / JSON-hijack chars that also
// inject visual breaks in single-line fields; no legit display use in a name/method (Flint nit #141804).
const INVISIBLE_BIDI = '\\u00AD\\u061C\\u200B-\\u200F\\u2028\\u2029\\u202A-\\u202E\\u2060\\u2066-\\u2069\\uFEFF';
// Single-line: strip ALL C0 (0000-001F, incl \t\n\r) + DEL/C1 (007F-009F) + invisible/bidi.
const STRIP_SINGLE_LINE = new RegExp(`[\\u0000-\\u001F\\u007F-\\u009F${INVISIBLE_BIDI}]`, 'g');
// Multi-line: strip C0 EXCEPT \t (0009) and \n (000A); still strip DEL/C1 + invisible/bidi.
const STRIP_MULTI_LINE = new RegExp(`[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F-\\u009F${INVISIBLE_BIDI}]`, 'g');

export interface SanitizeTextOptions {
  /** Max characters AFTER stripping (hard bound). */
  max: number;
  /** Preserve TAB + LINE FEED (multi-line fields like `note`). Default false (single-line). */
  allowNewlines?: boolean;
}

/**
 * Sanitize a peer-authored text value at INGESTION (before the store). NFC-normalize, strip the
 * invisible/control/bidi class (see file header), and bound length. Non-strings → '' (a non-string is
 * never a legitimate text value here; the caller's type-guard has already run, this is belt-and-braces).
 * This NEVER touches visible markup — <, >, &, quotes survive verbatim; each sink escapes them in context.
 */
export function sanitizeText(raw: unknown, opts: SanitizeTextOptions): string {
  if (typeof raw !== 'string') return '';
  // NFC first so composed/decomposed forms are canonical before we measure or strip.
  let s = raw.normalize('NFC');
  if (opts.allowNewlines) {
    // Normalize CRLF / lone CR → LF so a bare CR cannot inject a vCard header line at an export sink,
    // while legitimate line breaks are preserved.
    s = s.replace(/\r\n?/g, '\n');
    s = s.replace(STRIP_MULTI_LINE, '');
  } else {
    s = s.replace(STRIP_SINGLE_LINE, '');
  }
  return s.slice(0, opts.max);
}

/** Single-line convenience (display_name, contact methods): strips TAB/LF too. */
export function sanitizeSingleLine(raw: unknown, max: number): string {
  return sanitizeText(raw, { max, allowNewlines: false });
}

/**
 * Sanitize a peer-authored contact_info object's text fields at INGESTION — the vCard-import / QR-scan
 * store paths (the two paths that DON'T flow through applyVerifiedContactUpdate's FIELD_MAP). Returns a
 * shallow-sanitized copy so import ≡ broadcast: string arrays (phones/emails/urls) + handle-map values +
 * the vCard free-ish fields (org/title/nickname/bday/adr) + extras values, all single-line-stripped.
 * Non-object → undefined. Reuses the SAME strip as the apply FIELD_MAP (one definition, no drift).
 */
export function sanitizeContactInfo(ci: unknown): Record<string, unknown> | undefined {
  if (ci === null || typeof ci !== 'object') return undefined;
  const src = ci as Record<string, unknown>;
  const out: Record<string, unknown> = { ...src };
  const cleanArr = (v: unknown, max: number) =>
    Array.isArray(v) ? v.filter((x) => typeof x === 'string').map((x) => sanitizeSingleLine(x, max)) : v;
  if ('phones' in src) out.phones = cleanArr(src.phones, METHOD_VALUE_MAX);
  if ('emails' in src) out.emails = cleanArr(src.emails, METHOD_VALUE_MAX);
  if ('urls' in src) out.urls = cleanArr(src.urls, URL_MAX);
  for (const f of ['org', 'title', 'nickname', 'bday', 'adr']) {
    if (typeof src[f] === 'string') out[f] = sanitizeSingleLine(src[f], METHOD_VALUE_MAX);
  }
  if (src.handles && typeof src.handles === 'object' && !Array.isArray(src.handles)) {
    const h: Record<string, string> = {};
    for (const [k, v] of Object.entries(src.handles as Record<string, unknown>)) {
      if (typeof v === 'string') h[k] = sanitizeSingleLine(v, METHOD_VALUE_MAX);
    }
    out.handles = h;
  }
  if (Array.isArray(src.extras)) {
    out.extras = src.extras.map((x) =>
      x && typeof x === 'object' && typeof (x as { value?: unknown }).value === 'string'
        ? { ...(x as object), value: sanitizeSingleLine((x as { value: string }).value, METHOD_VALUE_MAX) }
        : x,
    );
  }
  return out;
}

/**
 * §9 CHOKEPOINT (Flint pin #141811). Sanitize a contact record's peer-authored DISPLAY/CONTACT text at
 * the client-store WRITE boundary — the ONE convergence every ingestion path flows through (vCard-import,
 * joiner/grow admit, broadcast, management, and any FUTURE writer). enforce-by-construction: a path that
 * forgets to sanitize still cannot store a booby-trapped string, because the store never holds one.
 *
 * FIELD ALLOWLIST — sanitize ONLY these peer-authored text fields:
 *   name (single-line) · notes (multi-line) · email/phone (single-line) · phones[]/emails[] · contact_info.
 * NEVER touch structural / crypto / lookup fields (fingerprint, public_key, id, owner_fingerprint,
 * added_at, trust_level, version, epoch, pq_* keys, PSI session state, …): NFC/strip there would corrupt
 * identity and break BYTE-EXACT matching — fingerprint is THE lookup key (getContactByFingerprint), and
 * dedup matches on NORMALIZED channels, not raw. Idempotent → composes safely on the FIELD_MAP /
 * edgeToRecordFields sanitizers (kept as layered defense-in-depth). Returns a shallow-sanitized copy.
 */
export function sanitizeContactRecordText<T>(rec: T): T {
  if (rec === null || typeof rec !== 'object') return rec;
  const out = { ...(rec as Record<string, unknown>) };
  if (typeof out.name === 'string') out.name = sanitizeSingleLine(out.name, DISPLAY_NAME_MAX);
  if (typeof out.notes === 'string') out.notes = sanitizeText(out.notes, { max: NOTE_MAX, allowNewlines: true });
  if (typeof out.email === 'string') out.email = sanitizeSingleLine(out.email, METHOD_VALUE_MAX);
  if (typeof out.phone === 'string') out.phone = sanitizeSingleLine(out.phone, METHOD_VALUE_MAX);
  if (Array.isArray(out.emails)) out.emails = out.emails.map((x) => (typeof x === 'string' ? sanitizeSingleLine(x, METHOD_VALUE_MAX) : x));
  if (Array.isArray(out.phones)) out.phones = out.phones.map((x) => (typeof x === 'string' ? sanitizeSingleLine(x, METHOD_VALUE_MAX) : x));
  if (out.contact_info && typeof out.contact_info === 'object') out.contact_info = sanitizeContactInfo(out.contact_info);
  return out as unknown as T;
}
