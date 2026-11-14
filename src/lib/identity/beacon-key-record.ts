// src/lib/identity/beacon-key-record.ts
// #588 D1/D2 (Flint's rulings, 11-09; DARK; nothing imports it from a live path): the identity's beacon secret x, its generation, and the re-deposit
// jitter secret, as ONE record. IDENTITY STATE (Archie's multi-device rule, D3 of psi_multidevice_decision_v1): one value per identity, carried in the
// backup, never minted independently per device. This file is the PURE half: shape, strict validation (the restore gate), minting, and the derived values.
// Storage (encrypted, atomic create-if-absent) is in client-store.ts. imports: beacon-key (curve code loads lazily), beacon-generation (no wire).
import { generateBeaconSecret, beaconPublicKey, BEACON_ORDER } from '../crypto/beacon-key';
import { generationFromClock, MAX_KEY_GENERATION } from '../crypto/beacon-generation';

export interface BeaconKeyRecord {
  /** x as 32 bytes little-endian, base64; 1 <= x < l. */
  secret: string;
  /** Monotonic, clock-seeded (D3). */
  key_generation: number;
  /** 32 random bytes, base64: the HMAC key for the re-deposit jitter. Identity state, so every device of one identity schedules alike. */
  jitter_secret: string;
}

const ZERO = BigInt(0), EIGHT = BigInt(8);

const toB64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
function fromB64Strict32(s: unknown): Uint8Array | null {
  if (typeof s !== 'string' || s.length !== 44 || !/^[A-Za-z0-9+/]{43}=$/.test(s)) return null;
  let bin: string;
  try { bin = atob(s); } catch { return null; }
  if (bin.length !== 32) return null;
  const u = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return toB64(u) === s ? u : null;
}
function leToBigInt(u: Uint8Array): bigint {
  let x = ZERO;
  for (let i = u.length - 1; i >= 0; i--) x = (x << EIGHT) | BigInt(u[i]);
  return x;
}
function bigIntToLe(x: bigint): Uint8Array {
  const o = new Uint8Array(32);
  let v = x;
  for (let i = 0; i < 32; i++) { o[i] = Number(v & BigInt(0xff)); v >>= EIGHT; }
  return o;
}

/** The restore gate: exactly the three fields, x in [1, l), a 32-byte jitter secret, an integer generation in [1, 2^31-1]. Canonical encodings only. */
export function isBeaconKeyRecord(x: unknown): x is BeaconKeyRecord {
  if (!x || typeof x !== 'object' || Array.isArray(x)) return false;
  const o = x as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.length !== 3 || !['secret', 'key_generation', 'jitter_secret'].every((k) => keys.includes(k))) return false;
  const sec = fromB64Strict32(o.secret);
  if (!sec) return false;
  const v = leToBigInt(sec);
  if (v < BigInt(1) || v >= BEACON_ORDER) return false;
  if (!fromB64Strict32(o.jitter_secret)) return false;
  const g = o.key_generation;
  return typeof g === 'number' && Number.isInteger(g) && g >= 1 && g <= MAX_KEY_GENERATION;
}

function defaultRandom(n: number): Uint8Array {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- globalThis has no typed crypto on every target
  const c: Crypto | undefined = (globalThis as any).crypto;
  if (!c || typeof c.getRandomValues !== 'function') throw new Error('no CSPRNG available');
  return c.getRandomValues(new Uint8Array(n));
}

/** Mint a record: a fresh x, a generation from the clock that is never below previous + 1 (generationFromClock refuses a clock before the floor or a
 * previous beyond the future bound), and a separate 32-byte jitter secret from its own draw. `random` is a test seam. */
export async function newBeaconKeyRecord(nowMs: number, previous?: BeaconKeyRecord, random: (n: number) => Uint8Array = defaultRandom): Promise<BeaconKeyRecord> {
  const key_generation = generationFromClock(nowMs, previous?.key_generation);
  const x = await generateBeaconSecret(random);
  const jitter = random(32);
  if (!(jitter instanceof Uint8Array) || jitter.length !== 32) throw new Error('bad random source');
  return { secret: toB64(bigIntToLe(x)), key_generation, jitter_secret: toB64(new Uint8Array(jitter)) };
}

export function secretOf(rec: BeaconKeyRecord): bigint {
  const u = fromB64Strict32(rec.secret);
  if (!u) throw new Error('beacon record: bad secret');
  return leToBigInt(u);
}
export async function publicKeyOf(rec: BeaconKeyRecord): Promise<string> {
  return beaconPublicKey(secretOf(rec));
}
export function jitterSeedOf(rec: BeaconKeyRecord): Uint8Array {
  const u = fromB64Strict32(rec.jitter_secret);
  if (!u) throw new Error('beacon record: bad jitter secret');
  return u;
}
