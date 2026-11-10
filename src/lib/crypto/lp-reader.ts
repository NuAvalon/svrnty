// src/lib/crypto/lp-reader.ts
/**
 * The strict READ side of the length-prefixed binary framing in lp-tlv.ts (LP(x) = uint32_be(len) || x).
 *
 * One reader for every binary wire object (key.rotate, pointer v2, the trust carrier), so there is ONE parser style:
 *   - every length is checked against what is left BEFORE any byte is taken (no over-read);
 *   - fixed-width fields have exactly their width, variable fields have an explicit maximum;
 *   - `finish()` refuses trailing bytes, so a parse either consumes the whole object or fails;
 *   - integers must be safe JS integers (a u64 above 2^53 - 1 is refused, never rounded);
 *   - a refusal carries a STABLE REASON CODE and nothing else: never a byte, a length or a field of the input, so it can
 *     go to a log or a dead-letter row without echoing attacker data.
 * Pure: no I/O, no clock, no randomness, no secrets.
 */

export type LpParseReason =
  | 'truncated'          // fewer bytes left than a fixed field needs
  | 'length-overrun'     // a length prefix points past the end of the object
  | 'length-over-max'    // a length prefix exceeds the field's declared maximum
  | 'trailing-bytes'     // bytes left after the last field
  | 'unsafe-integer'     // a u64 above Number.MAX_SAFE_INTEGER
  | 'bad-utf8'           // a text field is not valid UTF-8
  | 'bad-header'         // wrong magic, version or kind
  | 'bad-field';         // a field has the right width but the wrong shape (set by the caller)

export class LpParseError extends Error {
  constructor(public readonly reason: LpParseReason) {
    super(`binary object refused (${reason})`); // the message is the reason and nothing else
    this.name = 'LpParseError';
  }
}

const UTF8_FATAL = new TextDecoder('utf-8', { fatal: true });

export class LpReader {
  private off = 0;

  constructor(private readonly bytes: Uint8Array) {
    if (!(bytes instanceof Uint8Array)) throw new LpParseError('bad-field');
  }

  get remaining(): number {
    return this.bytes.length - this.off;
  }

  /** Exactly n bytes (a copy, so the caller cannot alias the input). */
  readFixed(n: number): Uint8Array {
    if (!Number.isSafeInteger(n) || n < 0) throw new LpParseError('bad-field');
    if (this.remaining < n) throw new LpParseError('truncated');
    const out = this.bytes.slice(this.off, this.off + n);
    this.off += n;
    return out;
  }

  readU8(): number {
    return this.readFixed(1)[0];
  }

  readU32(): number {
    const b = this.readFixed(4);
    return new DataView(b.buffer, b.byteOffset, 4).getUint32(0, false);
  }

  /** u64 big-endian, refused above Number.MAX_SAFE_INTEGER. */
  readU64(): number {
    const b = this.readFixed(8);
    const v = new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0, false);
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new LpParseError('unsafe-integer');
    return Number(v);
  }

  /** LP(x): a u32 length, checked against the maximum and against what is left, then the bytes. */
  readLp(maxLen: number): Uint8Array {
    const len = this.readU32();
    if (len > maxLen) throw new LpParseError('length-over-max');
    if (len > this.remaining) throw new LpParseError('length-overrun');
    return this.readFixed(len);
  }

  /** LP(utf8 text), decoded strictly (invalid UTF-8 is refused, not replaced). */
  readLpUtf8(maxLen: number): string {
    const b = this.readLp(maxLen);
    try {
      return UTF8_FATAL.decode(b);
    } catch {
      throw new LpParseError('bad-utf8');
    }
  }

  /** The object must be fully consumed. */
  finish(): void {
    if (this.remaining !== 0) throw new LpParseError('trailing-bytes');
  }
}
