/**
 * Distress — glass only.
 *
 * A silent cry. Sender's phone keeps no proof. Relay is dumb about the inner packet.
 * Recipient witnesses an inbound mark and paints the vivre: ember in the star,
 * the card corner burning until they act in the world.
 *
 * ⛔ Does not encrypt, deposit, or classify on the relay. Fleet owns the envelope.
 */

export const DISTRESS_COPY = {
  caution: 'Check on them in the world. Approach with caution.',
  went: 'I went',
  wentHint: 'This mark is on your device. It does not tell them you went.',
  pickHint: 'Default is all Guardians. You can pick one.',
  silent: 'This phone keeps no proof.',
} as const;

export type DistressTarget = {
  fingerprint: string;
  name: string;
  trusted?: boolean;
};

export function contactHasDistress(source: {
  distress_inbound?: boolean;
  metadata?: Record<string, unknown>;
}): boolean {
  if (source.distress_inbound) return true;
  const meta = source.metadata?.distress_inbound;
  return meta === true;
}

/** Recipient: the inbound mark is gone on this device only. */
export function distressWentPersistPatch(
  existing: Record<string, unknown> | undefined,
): { distress_inbound: false; metadata: Record<string, unknown> } {
  return {
    distress_inbound: false,
    metadata: { ...(existing || {}), distress_inbound: false },
  };
}

/**
 * Fire-and-forget. Must not return copy that says the cry was sent.
 * Fleet replaces the body with outer-mailbox encrypt + fan-out.
 */
export async function sendDistress(_req: {
  recipientFingerprints: string[];
}): Promise<void> {
  return;
}
