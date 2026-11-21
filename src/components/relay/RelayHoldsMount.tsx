'use client';

/**
 * The mount the app uses for "What the relay lists": the section, keyed by the owner, with its port made once per owner.
 * The section holds its own state (open, the loaded read, notices, the refresh gap). Keyed by owner, a change of owner in place gives the new owner a fresh section instead of the previous owner's
 * state, so one owner's list cannot be carried to the next by a re-render. No path in today's routing changes the owner without unmounting the section first (every change passes through the locked
 * screen or the gate); the key makes that boundary structural instead of a property of the routing. A component test (e2e/owner-switch.spec.ts) changes the owner in place and checks it.
 */

import { useMemo } from 'react';
import { RelayHoldsSection } from './RelayHoldsSection';
import { makeRelayHoldsPort, type RelayHoldsPort } from './relay-holds-port';

export type RelayHoldsMountProps = {
  ownerFingerprint: string;
  /** the owner's port; the real one unless a test supplies its own. Pass a stable function: the port is made again only when the owner or this function changes. */
  makePort?: (ownerFp: string) => RelayHoldsPort;
  /** the PSI gate; the section's own gate unless a test supplies one */
  gate?: () => boolean;
};

export function RelayHoldsMount({ ownerFingerprint, makePort = makeRelayHoldsPort, gate }: RelayHoldsMountProps) {
  const port = useMemo(() => makePort(ownerFingerprint), [makePort, ownerFingerprint]);
  return <RelayHoldsSection key={ownerFingerprint} port={port} gate={gate} />;
}
