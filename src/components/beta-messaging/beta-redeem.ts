// Thin CALL to fleet owner-auth + POST /api/relay/claim.
// Does not reimplement token verify, mailbox-id, or claim-registry.
// Fleet helpers are loaded only on the live path (tests inject mocks).

import { boundAccessKey } from './beta-messaging-text';

type SignClaim = (args: {
  mailboxId: string;
  fingerprint: string;
  publicKeyArmored: string;
  privateKeyArmored: string;
  passphrase: string;
  now: number;
  kemPublicKey?: string;
  sigPublicKey?: string;
}) => Promise<Record<string, string>>;

type MailboxIdOf = (fingerprint: string) => string;

export type RedeemArgs = {
  token: string;
  fingerprint: string;
  publicKeyArmored: string;
  privateKeyArmored: string;
  passphrase: string;
  kemPublicKey?: string;
  sigPublicKey?: string;
  now?: number;
  fetchImpl?: typeof fetch;
  signClaim?: SignClaim;
  mailboxIdOf?: MailboxIdOf;
};

export type RedeemResult = { ok: true } | { ok: false };

/**
 * Redeem a beta-access token for this address book.
 * Failures are uniform — never which verify step failed (anti-oracle).
 */
export async function redeemBetaAccessKey(args: RedeemArgs): Promise<RedeemResult> {
  const token = boundAccessKey(args.token);
  const fingerprint = String(args.fingerprint || '').trim();
  if (!token || !fingerprint || !args.publicKeyArmored || !args.privateKeyArmored) {
    return { ok: false };
  }
  const fetchImpl = args.fetchImpl ?? fetch;
  const mailboxIdOf =
    args.mailboxIdOf ?? (await import('@/lib/relay/mailbox-auth')).deriveMailboxId;
  const signClaim =
    args.signClaim ?? (await import('@/lib/relay/mailbox-auth')).signMailboxClaimRequest;
  try {
    const mailboxId = mailboxIdOf(fingerprint);
    const headers = await signClaim({
      mailboxId,
      fingerprint,
      publicKeyArmored: args.publicKeyArmored,
      privateKeyArmored: args.privateKeyArmored,
      passphrase: args.passphrase,
      now: args.now ?? Date.now(),
      kemPublicKey: args.kemPublicKey,
      sigPublicKey: args.sigPublicKey,
    });
    const res = await fetchImpl('/api/relay/claim', {
      method: 'POST',
      headers: { ...headers, 'content-type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    if (!res.ok) return { ok: false };
    const body = (await res.json().catch(() => null)) as { status?: unknown } | null;
    if (body?.status !== 'claimed') return { ok: false };
    return { ok: true };
  } catch {
    return { ok: false };
  }
}

/** Public PQ pubs on the identity wrapper (genesis) — strings only, no crypto. */
export function pqPubStringsFromIdentity(identity: unknown): {
  kemPublicKey?: string;
  sigPublicKey?: string;
} {
  const root = identity && typeof identity === 'object' ? (identity as Record<string, unknown>) : {};
  const pq =
    root.post_quantum && typeof root.post_quantum === 'object'
      ? (root.post_quantum as Record<string, unknown>)
      : {};
  const id =
    root.identity && typeof root.identity === 'object'
      ? (root.identity as Record<string, unknown>)
      : {};
  const nestedPq =
    id.post_quantum && typeof id.post_quantum === 'object'
      ? (id.post_quantum as Record<string, unknown>)
      : {};
  const kem =
    (typeof pq.kem_public_key === 'string' && pq.kem_public_key) ||
    (typeof nestedPq.kem_public_key === 'string' && nestedPq.kem_public_key) ||
    undefined;
  const sig =
    (typeof pq.sig_public_key === 'string' && pq.sig_public_key) ||
    (typeof nestedPq.sig_public_key === 'string' && nestedPq.sig_public_key) ||
    undefined;
  return {
    kemPublicKey: kem || undefined,
    sigPublicKey: sig || undefined,
  };
}

export function publicKeyFromIdentity(identity: unknown): string {
  const root = identity && typeof identity === 'object' ? (identity as Record<string, unknown>) : {};
  const id =
    root.identity && typeof root.identity === 'object'
      ? (root.identity as Record<string, unknown>)
      : {};
  return typeof id.public_key === 'string' ? id.public_key : '';
}
