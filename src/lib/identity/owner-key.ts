// src/lib/identity/owner-key.ts — the owner's STORAGE KEY: the one value every owner-keyed store, the contacts partition and the AAD of every
// encrypted record use. DARK and PURE: no I/O, no clock, no randomness; nothing imports it yet.
/**
 * WHY. The owner's own fingerprint keys three things (verified at dev 7309551): the object stores `identities`, `keys`, `pq_keys`, `vaults`,
 * `shards` and `device_mailbox` (keyPath 'fingerprint'); the contacts `owner` partition; and the AAD of every encrypted record
 * (contact-crypto.ts buildContactAAD: TLV(domain, scheme, id, ownerFingerprint); contacts, suppression, held-affirmatives and the delivery
 * default all pass it). A plain key rotation gives the owner FRESH operational keys, so the owner's operational fingerprint changes. If the
 * owner-side code keeps passing the OPERATIONAL fingerprint, every stored record then fails to decrypt (AES-GCM refuses a different AAD).
 *
 * THE RULE. The storage key is the owner's DURABLE id (the genesis fingerprint, the DID anchor). For an identity that has never rotated the
 * durable id IS today's fingerprint, so `ownerStoreKey` returns its argument UNCHANGED, byte for byte: nothing is migrated and no stored row
 * moves. After a rotation the caller still holds the new OPERATIONAL fingerprint as the active one; `aliases` maps each operational
 * fingerprint the owner has ever had to the durable id, and the rotation's persist is what writes that entry (RotSign R5, not built).
 *
 * A wrong key is not a soft error: a different string misplaces rows or makes them undecryptable. So every malformed alias fails CLOSED with a
 * reason code and a durable id is terminal (an alias of an alias is refused, never followed).
 */

/** operational fingerprint -> durable id. A Map, so no key can reach a prototype. */
export type OwnerAliases = ReadonlyMap<string, string>;

export type OwnerKeyReason = 'bad-fingerprint' | 'bad-alias' | 'alias-chain' | 'alias-conflict';

export class OwnerKeyError extends Error {
  constructor(public readonly reason: OwnerKeyReason) {
    super('owner key refused (' + reason + ')'); // a reason code only, never the fingerprint
    this.name = 'OwnerKeyError';
  }
}

// What a fingerprint looks like today: 40-hex (legacy OpenPGP) or 64-hex (canonical), either case. Used only to refuse a malformed ALIAS; an
// argument that is not in an alias entry is returned untouched whatever it looks like.
const SHAPE = /^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$/;

/**
 * The storage key for the owner whose active (operational) fingerprint is `fingerprint`.
 * No alias entry for it: returned UNCHANGED (never normalised, never trimmed). An entry: the durable id.
 */
export function ownerStoreKey(fingerprint: string, aliases?: OwnerAliases): string {
  if (typeof fingerprint !== 'string' || fingerprint.length === 0) throw new OwnerKeyError('bad-fingerprint');
  if (aliases === undefined || !aliases.has(fingerprint)) return fingerprint;
  const durable = aliases.get(fingerprint);
  if (typeof durable !== 'string' || !SHAPE.test(durable) || durable === fingerprint) throw new OwnerKeyError('bad-alias');
  if (aliases.has(durable)) throw new OwnerKeyError('alias-chain'); // a durable id is terminal
  return durable;
}

/**
 * A new alias map that also maps `operationalFp` to `durableId`. The input is never modified. The same pair again is a no-op; re-pointing an
 * existing alias to a different durable id, aliasing a durable id, or using a fingerprint that is already some entry's durable id is refused.
 */
export function withOwnerAlias(aliases: OwnerAliases | undefined, operationalFp: string, durableId: string): OwnerAliases {
  if (typeof operationalFp !== 'string' || !SHAPE.test(operationalFp) || typeof durableId !== 'string' || !SHAPE.test(durableId) || operationalFp === durableId) {
    throw new OwnerKeyError('bad-alias');
  }
  const base = aliases ?? new Map<string, string>();
  const existing = base.get(operationalFp);
  if (existing !== undefined) {
    if (existing === durableId) return new Map(base);
    throw new OwnerKeyError('alias-conflict');
  }
  if (base.has(durableId)) throw new OwnerKeyError('alias-chain');
  for (const v of base.values()) if (v === operationalFp) throw new OwnerKeyError('alias-chain');
  const next = new Map(base);
  next.set(operationalFp, durableId);
  return next;
}
