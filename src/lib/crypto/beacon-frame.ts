// src/lib/crypto/beacon-frame.ts: the in-person confirm and key rotation. ONE framing function for the in-person confirm transcript T and the gate-15 rotate statement M, so the two
// cannot drift and a second implementation has one rule to match. DARK: nothing imports this yet.
//
//   beaconFrame(fields) = LP(f1) || LP(f2) || ...,   LP(b) = 4-byte BIG-endian length || b      (the tag is a field like any other)
//
// The field encoders REFUSE a malformed value with ProverRefused('statement') and never normalise it (a second spelling of the same value would
// frame to different bytes and the two sides would silently disagree):
//  - hexField: the ASCII bytes of exactly 64 LOWERCASE hex characters (a fingerprint or a durable id; the same rule as beacon-pair-id.ts).
//  - keyField: the DECODED 32 bytes of a beacon key in its card form, through the strict decoder (re-encoding must give the input back).
//  - u32Field: an integer generation, 0 <= g <= MAX_KEY_GENERATION, as 4 bytes big-endian.
import { ProverRefused } from './beacon-prover';
import { decodeBeaconKey } from './beacon-key';
import { MAX_KEY_GENERATION } from './beacon-generation';

const enc = new TextEncoder();
const HEX64 = /^[0-9a-f]{64}$/;

export function beaconFrame(fields: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const f of fields) {
    if (!(f instanceof Uint8Array)) throw new ProverRefused('statement');
    total += 4 + f.length;
  }
  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);
  let off = 0;
  for (const f of fields) {
    dv.setUint32(off, f.length, false);
    out.set(f, off + 4);
    off += 4 + f.length;
  }
  return out;
}

/** A tag or any fixed ASCII label, as the bytes of its characters. */
export const asciiField = (s: string): Uint8Array => enc.encode(s);

export function hexField(s: unknown): Uint8Array {
  if (typeof s !== 'string' || !HEX64.test(s)) throw new ProverRefused('statement');
  return enc.encode(s);
}

export function keyField(b64: unknown): Uint8Array {
  const u = decodeBeaconKey(b64);
  if (u === null) throw new ProverRefused('statement');
  return u;
}

export function u32Field(g: unknown): Uint8Array {
  if (typeof g !== 'number' || !Number.isInteger(g) || g < 0 || g > MAX_KEY_GENERATION) throw new ProverRefused('statement');
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, g, false);
  return out;
}
