/**
 * Classical (VCF / keyless gray) vs SVRN network contact.
 * Import path stores grays without a key (and often without a fingerprint).
 * A peer who joined / exchanged a card has fingerprint + public_key.
 */

export function isSvrnNetworkContact(c: {
  fingerprint?: string | null;
  public_key?: string | null;
}): boolean {
  const fp = (c.fingerprint || '').trim();
  const pk = (c.public_key || '').trim();
  return fp.length >= 16 && pk.length > 0;
}

export function isClassicalAddressBookContact(c: {
  fingerprint?: string | null;
  public_key?: string | null;
}): boolean {
  return !isSvrnNetworkContact(c);
}
