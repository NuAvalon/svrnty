// Browser-side harness: renders ONE owner-scoped section the way the app mounts it, then changes the OWNER in place with no null in between (the case a keyed mount exists for),
// so the spec can see whether the previous owner's state is still on screen. Bundled by esbuild and injected into a page; it makes no request and uses fake ports only.
//   variant 'bare'  = the mount as it was written before the owner key: the section straight under the identity check, the port made for the owner on every render.
//   variant 'mount' = the mount component the app now uses.
import { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { RelayHoldsSection } from '@/components/relay/RelayHoldsSection';
import { makeRelayHoldsPort, type BookRecord, type PortIo } from '@/components/relay/relay-holds-port';
import { RelayHoldsMount } from '@/components/relay/RelayHoldsMount';
import { HeldMessagesSection } from '@/components/held/HeldMessagesSection';
import { HeldMessagesMount } from '@/components/held/HeldMessagesMount';
import type { HeldSectionPort } from '@/components/held/held-port';
import type { HeldPort } from '@/components/held/hold-view-model';

const OWNER_A = 'a'.repeat(40);
const OWNER_B = 'b'.repeat(40);
const CONTACT_OF_A = 'c1'.repeat(20);
const HELD_SENDER_OF_A = 'd2'.repeat(20);
const ALLOW = { trusted: true, openVisibility: true, blocked: false, perContactPrivate: false };

/** Owner A has one contact the book allows that the relay does not list (so the panel shows a row); owner B has nothing at all. */
function relayIo(owner: string): PortIo {
  const isA = owner === OWNER_A;
  const records: BookRecord[] = isA ? [{ fingerprint: CONTACT_OF_A, name: 'Zelda Only-A', consent: ALLOW }] : [];
  return {
    lastRead: () => ({ listed: { status: 'ok', fps: [] } as never, at: Date.now() }),
    records: async () => records,
    bookWhole: async () => true,
    tick: async () => {},
    add: async () => true,
    nowMs: () => Date.now(),
  };
}

/** Owner A has one held note from one sender; owner B has none. */
const heldSectionPort = (owner: string): HeldSectionPort => ({
  senders: async () => (owner === OWNER_A ? [{ from_fingerprint: HELD_SENDER_OF_A, count: 1 }] : []),
  frozen: async () => new Set<string>(),
});
const heldPort: HeldPort = {
  listHeld: async () => [{ note_id: 'n-1', body: 'HELD-NOTE-BODY-OF-OWNER-A', sent_at: new Date().toISOString(), held_at: new Date().toISOString() } as never],
  release: async () => ({ ok: true }) as never,
  remove: async () => ({ ok: true }) as never,
  nowMs: () => Date.now(),
};

const relayPortFor = (owner: string) => makeRelayHoldsPort(owner, relayIo(owner));   // module level: a stable function, as the mount asks

type Which = 'relay' | 'held';
type Variant = 'bare' | 'mount';

function Switcher({ which, variant }: { which: Which; variant: Variant }) {
  const [owner, setOwner] = useState(OWNER_A);
  (window as unknown as { __setOwner: (o: string) => void }).__setOwner = setOwner;
  if (which === 'relay') {
    return variant === 'bare'
      ? <RelayHoldsSection port={makeRelayHoldsPort(owner, relayIo(owner))} gate={() => true} />
      : <RelayHoldsMount ownerFingerprint={owner} makePort={relayPortFor} gate={() => true} />;
  }
  return variant === 'bare'
    ? <HeldMessagesSection sectionPort={heldSectionPort(owner)} heldPort={heldPort} />
    : <HeldMessagesMount ownerFingerprint={owner} makeSectionPort={heldSectionPort} heldPort={heldPort} />;
}

(window as unknown as { __ownerSwitch: unknown }).__ownerSwitch = {
  OWNER_A, OWNER_B,
  render(which: Which, variant: Variant) {
    const host = document.createElement('div');
    host.id = 'owner-switch-host';
    document.body.appendChild(host);
    createRoot(host).render(<Switcher which={which} variant={variant} />);
  },
  flip() { (window as unknown as { __setOwner: (o: string) => void }).__setOwner(OWNER_B); },
};
