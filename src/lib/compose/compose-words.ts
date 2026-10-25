// src/lib/compose/compose-words.ts
// The four check-words on the sign card: words = SAS(request), NO new wire field. Pinned by Flint's ruling "compose-words v1" (lane:portal #1465),
// design call Archie #1462, claims rules Hypatia §6c. A HUMAN check that the card describes the same request the portal built (~44 bits): NOT a security
// boundary (the pinned-sender gate is), so nothing calls it "verified", "secure" or "safe", and nothing but the words may depend on it.
//
//   W1 preimage = u16be(len(D)) || D || JCS(request), D = UTF-8 "svrnty:compose-words:v1", JCS over the validated closed-field object, UTF-8
//   W2 digest   = SHA-256(preimage); word i (0..3) = big-endian bits [11i, 11i+11) of the digest = an index into BIP-39 English (2048 words)
//   W3 derived from the SAME object the card renders (the caller passes request.object), never a re-parse
//   W4 FAIL CLOSED: JCS throws, a string holds a lone surrogate, or the word list does not match its pinned sha256 -> NO words (an empty list)
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes, bytesToHex } from '@noble/hashes/utils.js';
import { jcs, hasLoneSurrogate } from './compose-rules';
export { hasLoneSurrogate };
import { BIP39_ENGLISH, BIP39_ENGLISH_SHA256 } from './compose-wordlist';

export const WORDS_DOMAIN = 'svrnty:compose-words:v1';
export const WORD_COUNT = 4;

let listChecked: boolean | null = null;
/** Recompute sha256(words joined by LF + trailing LF) once and compare to the pinned value. A mismatch means NO words, ever, until the code is fixed. */
export function wordListIsPinned(list: readonly string[] = BIP39_ENGLISH, pinned: string = BIP39_ENGLISH_SHA256): boolean {
  if (list === BIP39_ENGLISH && pinned === BIP39_ENGLISH_SHA256 && listChecked !== null) return listChecked;
  let ok = false;
  try {
    ok = list.length === 2048 && bytesToHex(sha256(utf8ToBytes(list.join('\n') + '\n'))) === pinned;
  } catch {
    ok = false;
  }
  if (list === BIP39_ENGLISH && pinned === BIP39_ENGLISH_SHA256) listChecked = ok;
  return ok;
}

/** W1. Throws on anything JCS refuses or on a lone surrogate; callers that must not throw use deriveComposeWords. */
export function composeWordsPreimage(object: Readonly<Record<string, string>>): Uint8Array {
  for (const v of Object.values(object)) if (typeof v === 'string' && hasLoneSurrogate(v)) throw new Error('compose-words: lone surrogate');
  const d = utf8ToBytes(WORDS_DOMAIN);
  const body = utf8ToBytes(jcs(object as Record<string, string>));
  const out = new Uint8Array(2 + d.length + body.length);
  out[0] = (d.length >> 8) & 0xff;
  out[1] = d.length & 0xff;
  out.set(d, 2);
  out.set(body, 2 + d.length);
  return out;
}

/** W2: four 11-bit big-endian indices from the digest's first 44 bits. */
export function composeWordIndices(object: Readonly<Record<string, string>>): number[] {
  const digest = sha256(composeWordsPreimage(object));
  const idx: number[] = [];
  for (let i = 0; i < WORD_COUNT; i++) {
    let v = 0;
    for (let b = 11 * i; b < 11 * i + 11; b++) v = (v << 1) | ((digest[b >> 3] >> (7 - (b & 7))) & 1);
    idx.push(v);
  }
  return idx;
}

/** W4: the four words, or an EMPTY list on any failure. Never throws. */
export function deriveComposeWords(object: Readonly<Record<string, string>>): string[] {
  try {
    if (!wordListIsPinned()) return [];
    return composeWordIndices(object).map((i) => BIP39_ENGLISH[i]);
  } catch {
    return [];
  }
}
