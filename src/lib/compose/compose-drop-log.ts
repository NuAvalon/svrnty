// src/lib/compose/compose-drop-log.ts
// The app's one line for a sign request that was DROPPED with no card because its thread id holds hidden characters. Hypatia's string (portal_compose_copy_v0
// sha1 2e479849), the app logging it is Archie's call #1473, and Flint's condition #1474 (2) is the whole design: the line is FIXED TEXT plus ONE token.
// It never carries the thread id or any other request text, because hidden characters in a log are the same injection one hop later.
// Log only: no card, no pin screen, nothing for the user to click.
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import type { RefusalCode } from './compose-request';

const SAFE_TOKEN = /^[A-Za-z0-9_-]{1,64}$/;
/** A token that is not plainly safe is replaced, never repaired or echoed. */
export const NO_TOKEN = '-';

export const safeRef = (t: unknown): string => (typeof t === 'string' && SAFE_TOKEN.test(t) ? t : NO_TOKEN);

/** First 8 hex of the sha256 of the note plaintext, for when there is no usable note id. Pure; reveals nothing but a hash prefix. */
export const refFromText = (text: string): string => bytesToHex(sha256(utf8ToBytes(text))).slice(0, 8);

export const DROPPED_THREAD_LINE = (token: string): string =>
  `A sign request arrived that couldn't be shown: its thread name contains hidden characters. Nothing was signed. (ref ${safeRef(token)})`;

/** The line for a dropped request, or null when this drop has no line (only the thread case is specified). Takes the CODE and a token, never request text. */
export function dropLogLine(code: RefusalCode, token: string): string | null {
  return code === 'bad-thread' ? DROPPED_THREAD_LINE(token) : null;
}
