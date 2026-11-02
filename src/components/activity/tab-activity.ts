// Binary tab embers — activity happened, not a count (I-3). No presence (I-6).

export function galaxyActivitySignature(gateCount: number, attentionFingerprints: string[]): string {
  const fps = [...attentionFingerprints].filter(Boolean).sort().join('|');
  return `${gateCount}:${fps}`;
}

/** First snapshot is not a notification. Later signature change is. */
export function shouldMarkGalaxyActivity(prevSig: string | null, nextSig: string): boolean {
  if (prevSig == null) return false;
  return nextSig !== prevSig;
}

export function attentionFingerprintsFromTrust(args: {
  inbound?: boolean;
  pending?: boolean;
  fingerprint: string;
}): string | null {
  if (!args.inbound && !args.pending) return null;
  return args.fingerprint || null;
}
