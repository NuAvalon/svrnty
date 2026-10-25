// src/components/compose/compose-bus.ts
// "This request was handled in a tab" -> every OTHER tab of this origin closes its copy of the card (Flint #1489 C1). Same mechanism as note-events.ts: a
// BroadcastChannel (same-origin only, so only our own code can post here). The message carries ONE thing, a 32-hex nonce; the receiver ignores anything else.
// It is a convenience for the other tab's UI, not a security control: the persisted memory (compose-memory.ts) is what stops a replay raising a card.

export interface ResolvedBus {
  emit(nonce: string): void;
  subscribe(cb: (nonce: string) => void): () => void;
}

const CHANNEL_NAME = 'svrnty:compose-resolved';
const NONCE = /^[0-9a-f]{32}$/;

/** A bus backed by a BroadcastChannel, one per owner so two identities in one browser never close each other's cards. */
export function createBroadcastResolvedBus(ownerFingerprint: string): ResolvedBus {
  const name = `${CHANNEL_NAME}:${ownerFingerprint}`;
  return {
    emit(nonce) {
      if (typeof BroadcastChannel === 'undefined' || !NONCE.test(nonce)) return;
      const ch = new BroadcastChannel(name);
      ch.postMessage({ nonce });
      ch.close(); // a channel never delivers to the tab that posted it, so there is nothing to keep open here
    },
    subscribe(cb) {
      if (typeof BroadcastChannel === 'undefined') return () => undefined;
      const ch = new BroadcastChannel(name);
      ch.onmessage = (e: MessageEvent) => {
        const n = (e.data as { nonce?: unknown } | null)?.nonce;
        if (typeof n === 'string' && NONCE.test(n)) cb(n);
      };
      return () => ch.close();
    },
  };
}
