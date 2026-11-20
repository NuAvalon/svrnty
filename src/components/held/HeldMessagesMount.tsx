'use client';

/**
 * The mount the app uses for "Held messages": the section, keyed by the owner, with its section port made once per owner.
 * The section holds its own state (open, the senders it listed, the sender chosen), and the held-note view under it holds the notes it loaded. Keyed by owner, a change of owner in place gives the new
 * owner a fresh section instead of the previous owner's state. No path in today's routing changes the owner without unmounting the section first (every change passes through the locked screen or the
 * gate); the key makes that boundary structural instead of a property of the routing. A component test (e2e/owner-switch.spec.ts) changes the owner in place and checks it.
 */

import { useMemo } from 'react';
import { HeldMessagesSection } from './HeldMessagesSection';
import { makeHeldSectionPort, realHeldPort, type HeldSectionPort } from './held-port';
import type { HeldPort } from './hold-view-model';

export type HeldMessagesMountProps = {
  ownerFingerprint: string;
  /** the owner's section port; the real one unless a test supplies its own. Pass a stable function: the port is made again only when the owner or this function changes. */
  makeSectionPort?: (ownerFp: string) => HeldSectionPort;
  heldPort?: HeldPort;
};

export function HeldMessagesMount({ ownerFingerprint, makeSectionPort = makeHeldSectionPort, heldPort = realHeldPort }: HeldMessagesMountProps) {
  const sectionPort = useMemo(() => makeSectionPort(ownerFingerprint), [makeSectionPort, ownerFingerprint]);
  return <HeldMessagesSection key={ownerFingerprint} sectionPort={sectionPort} heldPort={heldPort} />;
}
