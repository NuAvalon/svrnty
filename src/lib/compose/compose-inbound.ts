// src/lib/compose/compose-inbound.ts
// The RECEIVE SEAM's pure half: decide whether an opened note is a compose request we may even look at, and extract the raw request for the validator.
// PURE: no I/O, no keys. The caller (the note-open path) supplies what the ENVELOPE established, never what the note claims.
//
// WIRE SHAPE (a PROPOSAL, Archie lane:portal #1032, until Athena states the real one; swap COMPOSE_NOTE_TYPE if she changes it): the plaintext inside the
// sealed note is exactly ONE JSON object {"type":"svrnty-compose-request-v1","request":<the object validateComposeRequest accepts>} and nothing else; any other
// top-level key is refused.
//
// SENDER (Flint #996 Q3, K1-K5 #1035): requests are accepted ONLY from the portal's separate "portal-compose" identity, PINNED in the app's settings (set once
// by Peter after comparing its first 16 hex with the portal page), NEVER taken from the note, AND the envelope's sender-auth must have verified against that
// pinned card (`senderVerified`). The login-code (passcode) sender is a different, throwaway, unverified identity: it must NEVER be pinned here. An unpinned
// app accepts nothing: there is no trust-on-first-use. (This code does not know which fingerprint is pinned; the setting's label and the screens carry that.)
/** Wire type string. CONFIRMED by Athena (lane:portal #1163): top level is exactly {"type","request"}. */
export const COMPOSE_NOTE_TYPE = 'svrnty-compose-request-v1';
/**
 * Parse-time ceiling on the plaintext, in UTF-16 code units. = the portal's STATED number (Athena, lane:portal #1163): 4096. Flint: set it equal to hers,
 * never above it. Measured, not assumed (compose-note-cap.test.ts): the largest LEGAL task note (every fixed field at its max, title+body at the
 * 2900 cost cap) is 3351 units compact, 3429 indent-2, so 4096 leaves ~22% headroom. The portal sends COMPACT JSON. This is a DoS/size bound and runs
 * BEFORE any parse: a note that spends its units on \u-escapes (6 units for one ASCII char) is refused 'too-long', which is the safe failure.
 * If any field max in compose-request.ts changes, the test fails: re-measure before raising this.
 */
export const COMPOSE_NOTE_MAX_CHARS = 4096;

export type InboundRefusalCode =
  | 'no-pinned-sender'
  | 'bad-pin'
  | 'sender-not-verified'
  | 'wrong-sender'
  | 'too-long'
  | 'not-json'
  | 'duplicate-key'
  | 'wrong-shape'
  | 'wrong-type';

export type InboundResult = { ok: true; raw: unknown } | { ok: false; code: InboundRefusalCode };

/** A usable pin is the FULL fingerprint (lowercase hex, 40 or 64): a prefix pin would let a different identity with the same first 16 hex through. */
export function isUsablePin(fp: unknown): fp is string {
  return typeof fp === 'string' && /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(fp);
}

/** First 16 hex of a fingerprint, the string Peter compares against the portal page when he pins. */
export function pinDisplay(fp: string): string {
  return fp.slice(0, 16);
}

/**
 * True when ANY JSON object in `text` has two members with the same name (after decoding escapes, so "a" and "a" collide). JSON.parse silently keeps
 * the LAST duplicate, so without this the app could display and sign a value the portal never meant, or that a differently-parsing verifier reads
 * the other way (Flint #1035: "refuses a duplicate key"). Assumes `text` is already valid JSON (the caller parsed it first); on anything it cannot read
 * it answers true (fail closed).
 */
export function hasDuplicateJsonKeys(text: string): boolean {
  let i = 0;
  // A duplicate is a FLAG, and the parse always runs to completion: no early return leaves the cursor mid-object (an earlier version returned early and
  // only reached the right answer because the desynchronised next token threw into the fail-closed catch, which a mutation check exposed).
  let duplicate = false;
  const ws = () => {
    while (i < text.length && (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r')) i++;
  };
  const str = (): string => {
    const start = i;
    i++; // opening quote
    while (i < text.length && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
    if (i >= text.length) throw new Error('unterminated');
    i++; // closing quote
    return JSON.parse(text.slice(start, i)) as string;
  };
  const value = (): void => {
    ws();
    const c = text[i];
    if (c === '{') {
      i++;
      const seen = new Set<string>();
      ws();
      if (text[i] === '}') {
        i++;
        return;
      }
      for (;;) {
        ws();
        const k = str();
        if (seen.has(k)) duplicate = true;
        seen.add(k);
        ws();
        if (text[i] !== ':') throw new Error('colon');
        i++;
        value();
        ws();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === '}') {
          i++;
          return;
        }
        throw new Error('object');
      }
    }
    if (c === '[') {
      i++;
      ws();
      if (text[i] === ']') {
        i++;
        return;
      }
      for (;;) {
        value();
        ws();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === ']') {
          i++;
          return;
        }
        throw new Error('array');
      }
    }
    if (c === '"') {
      str();
      return;
    }
    // number / true / false / null: skip to the next structural character.
    const m = /^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|^true|^false|^null/.exec(text.slice(i));
    if (!m) throw new Error('token');
    i += m[0].length;
  };
  try {
    value();
    ws();
    return duplicate || i !== text.length;
  } catch {
    return true;
  }
}

export function parseComposeNote(
  input: {
    /** The decrypted note body. */
    plaintext: string;
    /** The fingerprint the ENVELOPE established for the sender (decryptFromContact's `senderFingerprint`), never a field of the plaintext. */
    senderFingerprint: string;
    /** Whether the envelope's sender-auth verified against the sender's card (decryptFromContact's `senderVerified`). */
    senderVerified: boolean;
  },
  pinnedSenderFp: string | null | undefined,
): InboundResult {
  // 1. The sender gate comes FIRST and looks at nothing inside the note.
  if (pinnedSenderFp === null || pinnedSenderFp === undefined || pinnedSenderFp === '') return { ok: false, code: 'no-pinned-sender' };
  if (!isUsablePin(pinnedSenderFp)) return { ok: false, code: 'bad-pin' };
  if (input.senderVerified !== true) return { ok: false, code: 'sender-not-verified' };
  if (typeof input.senderFingerprint !== 'string' || input.senderFingerprint.toLowerCase() !== pinnedSenderFp) return { ok: false, code: 'wrong-sender' };

  // 2. Then the note itself.
  if (typeof input.plaintext !== 'string' || input.plaintext.length > COMPOSE_NOTE_MAX_CHARS) return { ok: false, code: 'too-long' };
  let parsed: unknown;
  try {
    parsed = JSON.parse(input.plaintext);
  } catch {
    return { ok: false, code: 'not-json' };
  }
  if (hasDuplicateJsonKeys(input.plaintext)) return { ok: false, code: 'duplicate-key' };
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return { ok: false, code: 'wrong-shape' };
  const keys = Object.keys(parsed as object).sort();
  if (keys.length !== 2 || keys[0] !== 'request' || keys[1] !== 'type') return { ok: false, code: 'wrong-shape' };
  const o = parsed as { type?: unknown; request?: unknown };
  if (o.type !== COMPOSE_NOTE_TYPE) return { ok: false, code: 'wrong-type' };
  if (o.request === null || typeof o.request !== 'object' || Array.isArray(o.request)) return { ok: false, code: 'wrong-shape' };
  return { ok: true, raw: o.request };
}
