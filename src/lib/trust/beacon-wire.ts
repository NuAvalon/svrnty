// src/lib/trust/beacon-wire.ts — #822 (a) P1: the beacon trust wire, as one composition of pieces that already exist.
//
// It builds a BeaconClient from the sealed pair store and latch (beacon-ports), the secrets adapter (beacon-secrets) and the client (beacon-client).
// Nothing imports this file yet: no screen calls it, and isBeaconWireLive() is false outside an opted-in dev build.
//
// Three rules, each pinned by a test:
//  1. OFF MEANS OFF, on every path. The switch is read on every client call and again inside the fetch the client is given, not once at construction.
//     While it is off the client is INERT: it answers from constants, writes nothing, reads nothing, calls no dependency.
//  2. The two inputs that are not built yet fail CLOSED. counterpartY (the contact's verified beacon key) defaults to "unknown", so nothing can be derived
//     and no request is made. confirmed (key-freshness evidence after a restore) defaults to false for every pair, so no request is made.
//  3. The base URL is not a parameter. The client's fixed same-origin base is the only one.
//
// NOT here: restore order, the contact's beacon key intake, rotation, the stuck-state screen (all later slices).
import {
  createBeaconClient,
  type BeaconClient,
  type BeaconClientDeps,
  type BeaconProverPort,
  type PairConfirmedPort,
} from '../crypto/beacon-client';
import { isBeaconWireLive } from '../claim-gates';
import type { Point } from '../crypto/beacon-prover';
import { createBeaconLatch, createBeaconStore, type BeaconKV, type Sealer } from './beacon-ports';
import { createBeaconSecrets, type SeedStore } from './beacon-secrets';

export interface BeaconWireDeps {
  /** the sealed key/value store the pair records and latches live in, and the sealer over the session key */
  kv: BeaconKV;
  sealer: Sealer;
  owner: string;
  /** the STRICT seed store (absent = {}, unreadable or locked throws). The blind setter is not an option here. */
  seeds: SeedStore;
  /** the identity's beacon secret scalar; undefined = no beacon key yet */
  secretX(): Promise<bigint | undefined>;
  /** the VERIFIED beacon key of a pair's counterpart. Not built yet: left out = unknown for every pair = no request. */
  counterpartY?(pairId: string): Promise<Point | undefined>;
  /** key-freshness evidence after a restore. Not built yet: left out = no pair is confirmed = no request. */
  confirmed?: PairConfirmedPort;
  fetch: BeaconClientDeps['fetch'];
  prover: BeaconProverPort;
  now?: () => number;
  requestTimeoutMs?: number;
  backoffMs?: (attempt: number) => number;
  random?: (n: number) => Uint8Array;
}

export interface BeaconWire {
  client: BeaconClient;
}

/** What a request path throws when the switch went off between the client's own check and the fetch. */
export class BeaconWireOff extends Error {
  readonly code = 'beacon-wire-off' as const;
  constructor() { super('The beacon trust wire is off.'); this.name = 'BeaconWireOff'; }
}

/** The answers while the wire is off. Constants: no dependency is touched, nothing is persisted, nothing is sent. */
const INERT: BeaconClient = {
  trustAtTap: async () => ({ kind: 'unsent' }),
  removeAtTap: async () => ({ observedMatch: false }),
  matchState: async () => 'none',
  matchSince: async () => null,
  renew: async () => undefined,
  pollNow: async () => undefined,
  nextRenewalAt: async () => undefined,
  drainPendingWithdraws: async () => undefined,
};

const NEVER_CONFIRMED: PairConfirmedPort = { isConfirmed: async () => false };
const UNKNOWN_COUNTERPART = async (): Promise<Point | undefined> => undefined;

/** The wire, gated by the real switch. This is the only entry a screen may use. */
export function createBeaconWire(deps: BeaconWireDeps): BeaconWire {
  return createBeaconWireWithGate(deps, isBeaconWireLive);
}

/** The same wire with the switch injected. For tests only: a static guard fails if any other source file names it. */
export function createBeaconWireWithGate(deps: BeaconWireDeps, live: () => boolean): BeaconWire {
  const store = createBeaconStore(deps.kv, deps.sealer, deps.owner);
  const latch = createBeaconLatch(deps.kv, deps.sealer, deps.owner);
  const secrets = createBeaconSecrets({
    seeds: deps.seeds,
    secretX: deps.secretX,
    counterpartY: deps.counterpartY ?? UNKNOWN_COUNTERPART,
    latchKind: (pairId) => latch.kindOf(pairId),
    now: deps.now,
    random: deps.random,
  });
  const inner = createBeaconClient({
    // read again at the moment of the request: a client built while ON must stop the instant the switch goes OFF
    fetch: (url, init) => {
      if (!live()) throw new BeaconWireOff();
      return deps.fetch(url, init);
    },
    latch,
    confirmed: deps.confirmed ?? NEVER_CONFIRMED,
    store,
    secrets,
    prover: deps.prover,
    now: deps.now,
    requestTimeoutMs: deps.requestTimeoutMs,
    backoffMs: deps.backoffMs,
    // baseUrl is deliberately not passed: the client's fixed same-origin base is the only one
  });
  const client: BeaconClient = {
    trustAtTap: (p) => (live() ? inner.trustAtTap(p) : INERT.trustAtTap(p)),
    removeAtTap: (p) => (live() ? inner.removeAtTap(p) : INERT.removeAtTap(p)),
    matchState: (p) => (live() ? inner.matchState(p) : INERT.matchState(p)),
    matchSince: (p) => (live() ? inner.matchSince(p) : INERT.matchSince(p)),
    renew: (p) => (live() ? inner.renew(p) : INERT.renew(p)),
    pollNow: (p) => (live() ? inner.pollNow(p) : INERT.pollNow(p)),
    nextRenewalAt: (p) => (live() ? inner.nextRenewalAt(p) : INERT.nextRenewalAt(p)),
    drainPendingWithdraws: () => (live() ? inner.drainPendingWithdraws() : INERT.drainPendingWithdraws()),
  };
  return { client };
}
