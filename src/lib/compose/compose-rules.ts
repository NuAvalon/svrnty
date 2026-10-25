// src/lib/compose/compose-rules.ts
// App side of "portal compose, svrnty-signed" (spec v0.7 §6/§8; Flint #673/#808/#831; Hypatia #812/#832). PURE: no UI, no crypto keys, no I/O.
//
// A TypeScript port of Athena's reference compose_rules.py, held to the SHARED fixture (compose-vectors-v1.json, sha1 6aca9667ec9912dc, pinned by
// compose-rules.test.ts) so the portal (Python), the cell (Python), Mneme's side and this app agree byte for byte.
//
// THE APP NEVER NORMALISES. The portal is the single normaliser; this app signs exactly the string it receives or REFUSES. There is no "sign anyway"
// path anywhere: a refusal is final. Receivers (portal on hand-back, cell, Weft) also REJECT, never strip. So this module has `refusedAt` and no
// `normalise`.
//
// Never uses a platform Unicode property for the SECURITY rules: Extended_Pictographic is the pinned literal below (Node 22 / ICU 78, 156 ranges),
// a strict subset of emoji-data 15.1, so any error is toward refusal. (The mentions hint uses \p{L}; it is a UI hint, not a gate.)
import { buildSignedBytes } from '../crypto/sign-envelope';
import { DOMAIN_LOOM_POST, DOMAIN_LOOM_TASK } from '../format/envelope';

/** One number: cost(text) must be <= CAP (spec §8, measured against post_signed's real envelope; confirmed Flint #831). */
export const COMPOSE_CAP = 2900;

export type ComposeKind = 'post' | 'task';
export const COMPOSE_DOMAIN: Record<ComposeKind, string> = { post: DOMAIN_LOOM_POST, task: DOMAIN_LOOM_TASK };
/** v1 suites a compose request may bind. Ed25519 is REQUIRED at every receiver; the PQ leg is optional until compose carries authority beyond text. */
export const COMPOSE_SUITES = ['ed25519', 'ed25519+ml-dsa-87'] as const;
export type ComposeSuite = (typeof COMPOSE_SUITES)[number];

// Node 22's \p{Extended_Pictographic} as inclusive ranges: generated once, PINNED, never recomputed. compose-rules.test.ts asserts this equals the
// fixture's `ext_pict_ranges` entry for entry.
export const EXT_PICT: ReadonlyArray<readonly [number, number]> = [
  [0xA9, 0xA9], [0xAE, 0xAE], [0x203C, 0x203C], [0x2049, 0x2049], [0x2122, 0x2122],
  [0x2139, 0x2139], [0x2194, 0x2199], [0x21A9, 0x21AA], [0x231A, 0x231B], [0x2328, 0x2328],
  [0x23CF, 0x23CF], [0x23E9, 0x23F3], [0x23F8, 0x23FA], [0x24C2, 0x24C2], [0x25AA, 0x25AB],
  [0x25B6, 0x25B6], [0x25C0, 0x25C0], [0x25FB, 0x25FE], [0x2600, 0x2604], [0x260E, 0x260E],
  [0x2611, 0x2611], [0x2614, 0x2615], [0x2618, 0x2618], [0x261D, 0x261D], [0x2620, 0x2620],
  [0x2622, 0x2623], [0x2626, 0x2626], [0x262A, 0x262A], [0x262E, 0x262F], [0x2638, 0x263A],
  [0x2640, 0x2640], [0x2642, 0x2642], [0x2648, 0x2653], [0x265F, 0x2660], [0x2663, 0x2663],
  [0x2665, 0x2666], [0x2668, 0x2668], [0x267B, 0x267B], [0x267E, 0x267F], [0x2692, 0x2697],
  [0x2699, 0x2699], [0x269B, 0x269C], [0x26A0, 0x26A1], [0x26A7, 0x26A7], [0x26AA, 0x26AB],
  [0x26B0, 0x26B1], [0x26BD, 0x26BE], [0x26C4, 0x26C5], [0x26C8, 0x26C8], [0x26CE, 0x26CF],
  [0x26D1, 0x26D1], [0x26D3, 0x26D4], [0x26E9, 0x26EA], [0x26F0, 0x26F5], [0x26F7, 0x26FA],
  [0x26FD, 0x26FD], [0x2702, 0x2702], [0x2705, 0x2705], [0x2708, 0x270D], [0x270F, 0x270F],
  [0x2712, 0x2712], [0x2714, 0x2714], [0x2716, 0x2716], [0x271D, 0x271D], [0x2721, 0x2721],
  [0x2728, 0x2728], [0x2733, 0x2734], [0x2744, 0x2744], [0x2747, 0x2747], [0x274C, 0x274C],
  [0x274E, 0x274E], [0x2753, 0x2755], [0x2757, 0x2757], [0x2763, 0x2764], [0x2795, 0x2797],
  [0x27A1, 0x27A1], [0x27B0, 0x27B0], [0x27BF, 0x27BF], [0x2934, 0x2935], [0x2B05, 0x2B07],
  [0x2B1B, 0x2B1C], [0x2B50, 0x2B50], [0x2B55, 0x2B55], [0x3030, 0x3030], [0x303D, 0x303D],
  [0x3297, 0x3297], [0x3299, 0x3299], [0x1F004, 0x1F004], [0x1F02C, 0x1F02F], [0x1F094, 0x1F09F],
  [0x1F0AF, 0x1F0B0], [0x1F0C0, 0x1F0C0], [0x1F0CF, 0x1F0D0], [0x1F0F6, 0x1F0FF], [0x1F170, 0x1F171],
  [0x1F17E, 0x1F17F], [0x1F18E, 0x1F18E], [0x1F191, 0x1F19A], [0x1F1AE, 0x1F1E5], [0x1F201, 0x1F20F],
  [0x1F21A, 0x1F21A], [0x1F22F, 0x1F22F], [0x1F232, 0x1F23A], [0x1F23C, 0x1F23F], [0x1F249, 0x1F25F],
  [0x1F266, 0x1F321], [0x1F324, 0x1F393], [0x1F396, 0x1F397], [0x1F399, 0x1F39B], [0x1F39E, 0x1F3F0],
  [0x1F3F3, 0x1F3F5], [0x1F3F7, 0x1F3FA], [0x1F400, 0x1F4FD], [0x1F4FF, 0x1F53D], [0x1F549, 0x1F54E],
  [0x1F550, 0x1F567], [0x1F56F, 0x1F570], [0x1F573, 0x1F57A], [0x1F587, 0x1F587], [0x1F58A, 0x1F58D],
  [0x1F590, 0x1F590], [0x1F595, 0x1F596], [0x1F5A4, 0x1F5A5], [0x1F5A8, 0x1F5A8], [0x1F5B1, 0x1F5B2],
  [0x1F5BC, 0x1F5BC], [0x1F5C2, 0x1F5C4], [0x1F5D1, 0x1F5D3], [0x1F5DC, 0x1F5DE], [0x1F5E1, 0x1F5E1],
  [0x1F5E3, 0x1F5E3], [0x1F5E8, 0x1F5E8], [0x1F5EF, 0x1F5EF], [0x1F5F3, 0x1F5F3], [0x1F5FA, 0x1F64F],
  [0x1F680, 0x1F6C5], [0x1F6CB, 0x1F6D2], [0x1F6D5, 0x1F6E5], [0x1F6E9, 0x1F6E9], [0x1F6EB, 0x1F6F0],
  [0x1F6F3, 0x1F6FF], [0x1F7DA, 0x1F7FF], [0x1F80C, 0x1F80F], [0x1F848, 0x1F84F], [0x1F85A, 0x1F85F],
  [0x1F888, 0x1F88F], [0x1F8AE, 0x1F8AF], [0x1F8BC, 0x1F8BF], [0x1F8C2, 0x1F8CF], [0x1F8D9, 0x1F8FF],
  [0x1F90C, 0x1F93A], [0x1F93C, 0x1F945], [0x1F947, 0x1F9FF], [0x1FA58, 0x1FA5F], [0x1FA6E, 0x1FAFF],
  [0x1FC00, 0x1FFFD],
];

const SKIN_LO = 0x1f3fb;
const SKIN_HI = 0x1f3ff;

export function isPict(cp: number): boolean {
  let lo = 0;
  let hi = EXT_PICT.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    const [a, b] = EXT_PICT[mid];
    if (cp < a) hi = mid;
    else if (cp > b) lo = mid + 1;
    else return true;
  }
  return false;
}

/** Code points of a string. A lone surrogate comes through as its own value (0xD800..0xDFFF), which is refused below. */
export function codePoints(text: string): number[] {
  const out: number[] = [];
  for (const ch of text) out.push(ch.codePointAt(0)!);
  return out;
}

/** Refused wherever it appears (§6 + Flint #808). U+000A is the only allowed control character. */
export function alwaysRefused(cp: number): boolean {
  return (
    (cp < 0x20 && cp !== 0x0a) ||
    cp === 0x7f ||
    (cp >= 0x80 && cp <= 0x9f) ||
    cp === 0x2028 ||
    cp === 0x2029 ||
    (cp >= 0x202a && cp <= 0x202e) || // bidi overrides
    (cp >= 0x2066 && cp <= 0x2069) || // bidi isolates
    cp === 0x200b ||
    cp === 0x200c ||
    cp === 0xfeff ||
    cp === 0x2060 || // zero-width (a ZWJ is handled separately)
    (cp >= 0xe0000 && cp <= 0xe007f) || // TAG characters (ASCII smuggling)
    (cp >= 0xfe00 && cp <= 0xfe0d) ||
    (cp >= 0xe0100 && cp <= 0xe01ef) || // variation selectors other than FE0E / FE0F
    (cp >= 0xd800 && cp <= 0xdfff) // lone surrogates (never valid text)
  );
}

/** Narrow GB11 (Flint #808): ExtPict (FE0F | U+1F3FB..1F3FF)? ZWJ ExtPict. Nothing else in between. */
export function zwjOk(cps: number[], i: number): boolean {
  if (i + 1 >= cps.length || !isPict(cps[i + 1])) return false;
  let j = i - 1;
  if (j >= 0 && (cps[j] === 0xfe0f || (cps[j] >= SKIN_LO && cps[j] <= SKIN_HI))) j -= 1;
  return j >= 0 && isPict(cps[j]);
}

/** Code-point indices of refused characters. Non-empty => REFUSE (never strip). */
export function refusedAt(text: string): number[] {
  const cps = codePoints(text);
  const out: number[] = [];
  for (let i = 0; i < cps.length; i++) {
    if (alwaysRefused(cps[i]) || (cps[i] === 0x200d && !zwjOk(cps, i))) out.push(i);
  }
  return out;
}

/** Hypatia #812: the only refused characters are the TAG characters of a flag (black flag + tags + cancel tag): lets the card say so honestly. */
export function onlySubdivisionFlag(text: string): boolean {
  const cps = codePoints(text);
  const bad = refusedAt(text);
  return bad.length > 0 && bad.every((i) => cps[i] >= 0xe0020 && cps[i] <= 0xe007f) && cps.includes(0x1f3f4);
}

/** Hypatia #832: "@" followed by a letter shows "Mentions don't notify from here yet. Your message is posted as written." A hint, not a gate. */
export function mentionsHint(text: string): boolean {
  const cps = codePoints(text);
  for (let i = 0; i < cps.length - 1; i++) {
    if (cps[i] === 0x40 && /^\p{L}$/u.test(String.fromCodePoint(cps[i + 1]))) return true;
  }
  return false;
}

/** Escaped cost in the loom envelope (Athena #696): the additive per-character budget. Must equal the Python `cost` on every vector. */
export function composeCost(text: string): number {
  let n = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    n += ch === '"' || ch === '\\' ? 4 : ch === '\n' ? 3 : cp < 0x80 ? 1 : cp <= 0xffff ? 6 : 12;
  }
  return n;
}

/** thread id = [A-Za-z0-9:._/-]{1,64} (spec §6). Anything else (incl. bidi / zero-width) is refused. */
export function isValidThreadId(thread: string): boolean {
  return /^[A-Za-z0-9:._/-]{1,64}$/.test(thread);
}

/**
 * RFC 8785 JCS for THIS domain: an object of STRING values with ASCII keys (asserted). NOT format/canonical.ts canonicalize(): that one NFC-normalises,
 * which would break "shown = signed" (spec v0.6). For string values JSON.stringify is JCS (ES6 number/string serialisation; keys sorted by UTF-16
 * code unit, which for ASCII keys is plain byte order). Output is asserted single-line: JCS escapes control characters, so raw CR/LF cannot appear.
 */
export function jcs(obj: Record<string, string>): string {
  const keys = Object.keys(obj);
  for (const k of keys) {
    if (!/^[\x20-\x7e]+$/.test(k)) throw new Error('compose JCS: keys must be printable ASCII');
    if (typeof obj[k] !== 'string') throw new Error('compose JCS: string values only in v1');
  }
  keys.sort();
  const out = '{' + keys.map((k) => JSON.stringify(k) + ':' + JSON.stringify(obj[k])).join(',') + '}';
  if (/[\r\n]/.test(out)) throw new Error('compose JCS: output must be single-line');
  return out;
}

/** True if `s` contains a UTF-16 surrogate that is not half of a valid pair. TS and Python escape those differently, so two honest sides would show different words. */
export function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(i + 1);
      if (n >= 0xdc00 && n <= 0xdfff) { i++; continue; }
      return true;
    }
    if (c >= 0xdc00 && c <= 0xdfff) return true;
  }
  return false;
}

/** The exact bytes (as a string) the app signs: LP(domain) || LP(suite) || JCS(object). The old NUL-tag preimage is withdrawn (spec §8). */
export function composeSignedBytes(kind: ComposeKind, suite: ComposeSuite, obj: Record<string, string>): string {
  if (!COMPOSE_SUITES.includes(suite)) throw new Error(`compose: unknown suite ${String(suite)}`);
  return buildSignedBytes(COMPOSE_DOMAIN[kind], suite, jcs(obj));
}
