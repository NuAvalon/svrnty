/**
 * Trust recipe — local glass only.
 *
 * Know (card in the book) → Verify (private, this device) → Trust (mutual, or it isn't).
 * Verified is NEVER a public badge. Only you know whom you verified. It is a
 * prerequisite for Trust on this device — collaboration in the real world /
 * another channel, then you mark it here.
 *
 * ⛔ Does not implement PSI / visible() / wire vouch. Overlay disclosure is fleet.
 * Owner-local fields must never serialize on publish / PSI-sync (Apollo §2).
 */

export const TRUST_RECIPE_COPY = {
  /** Three-line constitution (reach). */
  knowLayer:
    'People I know can see others I know, but only if they know them as well and we all want it to be known.',
  trustLayer:
    'People I trust can see others I trust, but only if they trust them and are trusted by them and we all want it to be known.',
  mutualOnly: 'In this domain, trust only exists if it is mutual.',
  helpTitle: 'The Formula',
  /** Name is not the key. */
  verifyWhy:
    "Anyone can use my name. They can't forge this key.",
  verifyPrivate:
    'Only you see whom you\'ve verified. Nobody else gets a badge. You only need this step if you want to Trust them — and they must do the same on their side.',
  verifyInPerson: 'In person',
  verifyOtherChannel: 'Another channel',
  verifiedHere:
    'You verified this key on this device. Nobody else sees that. Trust still needs them to verify you too.',
  growHint:
    'Show this so they can join your Galaxy. They become a star you Know. Bonds among people you already Know may light later — not new strangers.',
  mycelial:
    'The lattice knits; it doesn\'t recruit. New stars are people who joined you. Lines are ties you were meant to see.',
  gateStart: 'Start',
  gateContinue: 'Continue',
  /** Site-bottom manifesto (the thing we must never lose). */
  manifestoWord: 'SVRNTY',
  manifestoKeep: 'We must never lose it, and we must never give it away.',
  manifestoAxes: 'post-quantum · local-first · social-recovery',
  manifestoCloser: 'you are not a product',
  decay:
    "If you don't stay in touch, trust can fade. That's a nudge to re-meet, not a score.",
} as const;

export const GROW_INVITE_CAP = 7;

export type OwnerLocalVerify = {
  /** You confirmed this key is the person you mean. Private to this device. */
  owner_verified_at: string;
  method: 'in_person' | 'other_channel';
};

const META_KEY = 'owner_verify';

export function ownerHasVerified(source: {
  verification?: { verified_at?: string | null; method?: string };
  metadata?: Record<string, unknown>;
  owner_verify?: OwnerLocalVerify;
}): boolean {
  if (source.owner_verify?.owner_verified_at) return true;
  const meta = source.metadata?.[META_KEY] as OwnerLocalVerify | undefined;
  if (meta?.owner_verified_at) return true;
  const v = source.verification;
  // Migration only: earlier glass wrote the ritual into verification.
  // Email / QR / mutual_vouch are not "I made sure it's them."
  if (v?.verified_at && (v.method === 'in_person' || v.method === 'other_channel')) return true;
  return false;
}

export function canGrantTrust(source: Parameters<typeof ownerHasVerified>[0] & { trusted?: boolean }): {
  ok: boolean;
  reason?: 'need-verify';
} {
  if (source.trusted) return { ok: true };
  if (!ownerHasVerified(source)) return { ok: false, reason: 'need-verify' };
  return { ok: true };
}

/** Group fingerprint for compare-aloud / QR footer (not a badge). */
export function formatFingerprintForVerify(fp: string): string {
  const hex = (fp || '').replace(/[^a-fA-F0-9]/g, '').toUpperCase();
  if (hex.length < 8) return fp || '';
  const parts: string[] = [];
  for (let i = 0; i < hex.length; i += 4) parts.push(hex.slice(i, i + 4));
  return parts.join(' ');
}

export function buildOwnerVerifyMeta(
  existing: Record<string, unknown> | undefined,
  method: OwnerLocalVerify['method'],
): Record<string, unknown> {
  return {
    ...(existing || {}),
    [META_KEY]: {
      owner_verified_at: new Date().toISOString(),
      method,
    } satisfies OwnerLocalVerify,
  };
}

/** Local persist shape — never include public `verification` (that is not a badge). */
export function ownerVerifyPersistPatch(
  existing: Record<string, unknown> | undefined,
  method: OwnerLocalVerify['method'],
): { metadata: Record<string, unknown>; owner_verify: OwnerLocalVerify } {
  const metadata = buildOwnerVerifyMeta(existing, method);
  return {
    metadata,
    owner_verify: metadata[META_KEY] as OwnerLocalVerify,
  };
}

/** Negative: owner_verify must not appear on publish-shaped payloads. */
export function stripOwnerLocalForPublish<T extends Record<string, unknown>>(payload: T): T {
  const out = { ...payload };
  delete (out as { owner_verify?: unknown }).owner_verify;
  const meta = out.metadata;
  if (meta && typeof meta === 'object') {
    const next = { ...(meta as Record<string, unknown>) };
    delete next[META_KEY];
    delete next.blocked;
    delete next.notes;
    delete next.tags;
    out.metadata = next;
  }
  return out;
}
