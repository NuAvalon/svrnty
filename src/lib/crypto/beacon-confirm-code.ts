// src/lib/crypto/beacon-confirm-code.ts: the in-person confirm. The 6-digit code of the in-person confirm. DARK: nothing imports this yet.
//
//   T    = beaconFrame(tag 'svrnty:822:confirm:v1', fp1, key1, gen1, fp2, key2, gen2, nMin, nMax)   identities ordered by the fingerprint's ASCII bytes,
//          nonces ordered by the byte order of their ASCII (min then max), so both devices frame the SAME bytes
//   K    = deriveConfirmKey(x, held key, T)           (beacon-prover.ts: HKDF-SHA256 over S = x*Y; S never leaves that module)
//   code = first 5 bytes of K, big-endian, mod 10^6, zero-padded to 6 digits
//
// What the code proves, and what it does not, is in the confirm-source design note (section 0): the device in front of me holds the secret
// for the key I hold, now. Not who the person is. Classical only (Baby Jubjub DH).
// Nothing here is persisted or logged: no nonce, no K, no S, no code.
import { ProverRefused, deriveConfirmKey, CONFIRM_DOMAIN } from './beacon-prover';
import { beaconFrame, asciiField, hexField, keyField, u32Field } from './beacon-frame';
import { BEACON_ORDER, beaconPublicKey, checkBeaconPublicKey } from './beacon-key';

export type ConfirmParty = {
  /** 64 lowercase hex characters. */
  fingerprint: string;
  /** The beacon public key in its 32-byte card form, base64. For `own` it must be the key of the secret x. */
  beaconKey: string;
  generation: number;
};

/** A confirm nonce part: 10 characters of RFC 4648 base32, UPPERCASE, no padding (50 bits). A typed fallback is uppercased by the CALLER before this check. */
const NONCE = /^[A-Z2-7]{10}$/;

const cmp = (a: Uint8Array, b: Uint8Array): number => {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
};

/** The transcript T. Refuses (ProverRefused): 'statement' for a malformed fingerprint, key or generation; 'nonce' for a nonce that is not 10
 * uppercase base32 characters, or when the two nonces are equal (a device scanned itself); 'statement' also for two equal fingerprints. Pure: no curve library. */
export function confirmTranscript(own: ConfirmParty, held: ConfirmParty, nonceOwn: string, nonceOther: string): Uint8Array {
  const fpOwn = hexField(own.fingerprint), fpHeld = hexField(held.fingerprint);
  const keyOwn = keyField(own.beaconKey), keyHeld = keyField(held.beaconKey);
  const genOwn = u32Field(own.generation), genHeld = u32Field(held.generation);
  if (typeof nonceOwn !== 'string' || typeof nonceOther !== 'string' || !NONCE.test(nonceOwn) || !NONCE.test(nonceOther)) throw new ProverRefused('nonce');
  const nOwn = asciiField(nonceOwn), nOther = asciiField(nonceOther);
  if (cmp(nOwn, nOther) === 0) throw new ProverRefused('nonce');
  const order = cmp(fpOwn, fpHeld);
  if (order === 0) throw new ProverRefused('statement');
  const [first, second] = order < 0 ? [[fpOwn, keyOwn, genOwn], [fpHeld, keyHeld, genHeld]] : [[fpHeld, keyHeld, genHeld], [fpOwn, keyOwn, genOwn]];
  const [nMin, nMax] = cmp(nOwn, nOther) < 0 ? [nOwn, nOther] : [nOther, nOwn];
  return beaconFrame([asciiField(CONFIRM_DOMAIN), ...first, ...second, nMin, nMax]);
}

/** code from K: first 5 bytes big-endian (below 2^40, exact in a double), mod 10^6, 6 digits. K must be the 32 bytes deriveConfirmKey returns, else 'key-length'. */
export function codeFromKey(K: Uint8Array): string {
  if (!(K instanceof Uint8Array) || K.length !== 32) throw new ProverRefused('key-length');
  let n = 0;
  for (let i = 0; i < 5; i++) n = n * 256 + K[i];
  return String(n % 1000000).padStart(6, '0');
}

const KEY_REASON: Record<string, string> = {
  encoding: 'encoding', 'off-curve': 'y-off-curve', identity: 'y-identity', 'small-order': 'y-small-order',
  'not-in-subgroup': 'y-not-in-subgroup', 'own-key': 'y-self', unavailable: 'unavailable',
};

/** The code this device shows for the contact it holds `held` for. Refusals are ProverRefused with a fixed reason: those of confirmTranscript, 'encoding'
 * for a held key that is not a canonical point, the deposit path's codes for it (x-range, y-off-curve, y-identity, y-small-order, y-not-in-subgroup, y-self), 'own-key' when `own.beaconKey` is
 * not the public key of x (a device never builds a transcript for a key it does not hold), and 'unavailable' when the curve library cannot load. */
export async function confirmCode(x: bigint, own: ConfirmParty, held: ConfirmParty, nonceOwn: string, nonceOther: string): Promise<string> {
  const T = confirmTranscript(own, held, nonceOwn, nonceOther);
  const checked = await checkBeaconPublicKey(held.beaconKey, own.beaconKey);
  if (!checked.ok) throw new ProverRefused(KEY_REASON[checked.reason] ?? 'statement');
  // Own key first, so no confirm key ever exists for a key this device does not hold. A secret outside [1, l) is refused here with the deposit path's
  // reason, because beaconPublicKey would throw a RangeError for it.
  if (typeof x !== 'bigint' || x < BigInt(1) || x >= BEACON_ORDER) throw new ProverRefused('x-range');
  if ((await beaconPublicKey(x)) !== own.beaconKey) throw new ProverRefused('own-key');
  return codeFromKey(await deriveConfirmKey(x, checked.point, T));
}
