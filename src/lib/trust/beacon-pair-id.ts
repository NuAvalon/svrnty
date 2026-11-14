// src/lib/trust/beacon-pair-id.ts: #822 (a) P1. The LOCAL id of one beacon pair. Pure: it takes the index key, so it is tested without the store. DARK.
//
//   pairId = hex( HMAC-SHA256( indexKey, 'svrnty:beacon-pair:v1' || LP(durableId) ) ),  LP(b) = 4-byte big-endian length || b
//
// WHY THIS SHAPE (each line was forced by the code, see the #822 thread):
//  - DURABLE id, not the contact's current fingerprint and not the shared secret: a pair must survive the contact's key rotation, or its latches orphan and a Block stops applying.
//    Today every identity is epoch 0, so the durable id equals the fingerprint first seen; after rotation exists it must be PINNED on the contact at first sight.
//  - BLINDED with the SAME index key that blinds contact rows (HMAC(indexKey, fp), client-store enc-b): the beacon store keys are plaintext key NAMES, so a plain id there would put
//    the social graph back in the clear. The label gives domain separation: this id cannot be matched against a contact row's index even by someone holding both stores.
//  - HEX, because the ports accept only [A-Za-z0-9._-] ids (base64 has + / =).
//  - It is a LOCAL id only: the relay sees a slot and a nullifier, never this.
//
// RULE (Flint's trap 1, #8529): the index key derives from the PASSPHRASE (deriveContactCryptoKeys, PBKDF2). If a passphrase change ever lands it changes EVERY pairId, so every beacon_pair
// and beacon_latch row would ORPHAN and a Block would silently stop applying. Any such change MUST re-key every beacon_* row in the SAME transaction. beacon-pair-id.test.ts pins the
// derivation inputs (a known-answer test against an independent HMAC), so changing any input fails loudly instead of orphaning rows.

const LABEL = 'svrnty:beacon-pair:v1';
const DURABLE_ID = /^[0-9a-f]{64}$/; // a fingerprint: 64 lowercase hex
const enc = new TextEncoder();

function lp(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + b.length);
  new DataView(out.buffer).setUint32(0, b.length, false); // big-endian
  out.set(b, 4);
  return out;
}

export async function beaconPairId(indexKey: CryptoKey, durableId: string): Promise<string> {
  if (typeof durableId !== 'string' || !DURABLE_ID.test(durableId)) throw new Error('beacon pair id: the durable id must be 64 lowercase hex');
  const label = enc.encode(LABEL), id = lp(enc.encode(durableId));
  const msg = new Uint8Array(label.length + id.length);
  msg.set(label, 0);
  msg.set(id, label.length);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', indexKey, msg));
  let hex = '';
  for (const b of mac) hex += b.toString(16).padStart(2, '0');
  return hex;
}
