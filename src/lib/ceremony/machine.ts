// src/lib/ceremony/machine.ts
//
// Pure, framework-agnostic state machine for the SVRNTY 2-device connection ceremony
// (task #482, the 9/10 ceremony sequencer spine).
//
// The five canon steps, in order:
//   1. handshake — initiator shows a QR + short-link; joiner scans it or enters the code
//   2. card      — the identity card is conveyed initiator -> joiner
//   3. edge      — the connection is persisted (a ContactRecord is written to IndexedDB)
//   4. lattice   — the new facet lights up in the constellation (TrustMap)
//   5. tear      — the initiator tears off a recovery shard and gives it to the joiner
//   ->complete   — terminal
//
// Design notes:
//   - Steps are STRICTLY LINEAR. A step advances only on its own milestone event;
//     out-of-order or duplicate events are ignored (idempotent), never corrupting state.
//   - `role` affects RENDERING (initiator shows/gives, joiner scans/receives), NOT the
//     transition graph — both devices walk the same logical progression, so one machine
//     serves both sides of the 2-device flow.
//   - No React, no DOM, no clock reads inside the reducer: `startedAt` is injected so the
//     reducer is a pure function of (state, event) and is unit-testable in isolation.
//
// This module is the "hardest part" the feasibility gap-map named — sequencing the
// scattered surfaces into one ceremony — isolated as pure logic so it can be proven
// correct without a browser. UI wiring lives in the Ceremony component that consumes it.

export type CeremonyRole = 'initiator' | 'joiner';

export type CeremonyStepId =
  | 'handshake'
  | 'card'
  | 'edge'
  | 'lattice'
  | 'tear'
  | 'complete';

/** Canonical ordering. The last entry (`complete`) is terminal. */
export const CEREMONY_STEP_ORDER: readonly CeremonyStepId[] = [
  'handshake',
  'card',
  'edge',
  'lattice',
  'tear',
  'complete',
] as const;

/** The non-terminal steps a participant actively works through. */
export type ActiveStepId = Exclude<CeremonyStepId, 'complete'>;

export interface CeremonyState {
  role: CeremonyRole;
  step: CeremonyStepId;

  // Artifacts accumulated as the ceremony proceeds. Each is null until the step that
  // produces it fires; carried forward so later steps (and the UI) can reference them.
  peerRef: string | null; // relay short-code / channel established at the handshake
  peerFingerprint: string | null; // learned when the card is conveyed
  peerName: string | null;
  edgeId: string | null; // ContactRecord id once the edge is persisted
  shardGiven: boolean; // true once the tear (give a shard) completes

  error: string | null;
  startedAt: string; // ISO timestamp, injected at init (keeps the reducer pure)
}

export type CeremonyEvent =
  | { type: 'HANDSHAKE_ESTABLISHED'; peerRef: string }
  | { type: 'CARD_CONVEYED'; peerFingerprint: string; peerName?: string | null }
  | { type: 'EDGE_PERSISTED'; edgeId: string }
  | { type: 'LATTICE_RENDERED' }
  | { type: 'SHARD_GIVEN' }
  | { type: 'FAIL'; error: string }
  | { type: 'CLEAR_ERROR' }
  | { type: 'RESET' };

/**
 * The single milestone event that advances each active step. Any other event received
 * while on that step is a no-op (kept idempotent so a double-fire or a late relay
 * callback can't skip or corrupt the flow).
 */
const ADVANCING_EVENT: Record<ActiveStepId, CeremonyEvent['type']> = {
  handshake: 'HANDSHAKE_ESTABLISHED',
  card: 'CARD_CONVEYED',
  edge: 'EDGE_PERSISTED',
  lattice: 'LATTICE_RENDERED',
  tear: 'SHARD_GIVEN',
};

/** Zero-based position of a step in the canonical order (-1 if unknown). */
export function stepIndex(step: CeremonyStepId): number {
  return CEREMONY_STEP_ORDER.indexOf(step);
}

/** The step that follows `step`, or `complete` if it is last/terminal/unknown. */
export function nextStep(step: CeremonyStepId): CeremonyStepId {
  const i = CEREMONY_STEP_ORDER.indexOf(step);
  if (i < 0 || i >= CEREMONY_STEP_ORDER.length - 1) return 'complete';
  return CEREMONY_STEP_ORDER[i + 1];
}

export function isComplete(state: CeremonyState): boolean {
  return state.step === 'complete';
}

/**
 * Progress through the ceremony as a 0..1 fraction. `complete` is 1; `handshake` is 0.
 * Uses the number of active steps (order length minus the terminal `complete`).
 */
export function ceremonyProgress(state: CeremonyState): number {
  const activeSteps = CEREMONY_STEP_ORDER.length - 1; // exclude 'complete'
  const i = stepIndex(state.step);
  if (i < 0) return 0;
  return Math.min(1, i / activeSteps);
}

/** Human-facing label for a step (UI headings / progress dots). */
export function stepLabel(step: CeremonyStepId): string {
  switch (step) {
    case 'handshake':
      return 'Handshake';
    case 'card':
      return 'Card given';
    case 'edge':
      return 'Edge live';
    case 'lattice':
      return 'Lattice facet';
    case 'tear':
      return 'The tear';
    case 'complete':
      return 'Complete';
  }
}

/** Fresh ceremony state for a role. `startedAt` is injected (ISO string). */
export function initCeremony(role: CeremonyRole, startedAt: string): CeremonyState {
  return {
    role,
    step: 'handshake',
    peerRef: null,
    peerFingerprint: null,
    peerName: null,
    edgeId: null,
    shardGiven: false,
    error: null,
    startedAt,
  };
}

/** True if `event` is the milestone that would advance the current step. */
export function canAdvance(state: CeremonyState, event: CeremonyEvent): boolean {
  if (state.step === 'complete') return false;
  return event.type === ADVANCING_EVENT[state.step];
}

/**
 * Pure reducer: (state, event) -> state. Control events (RESET/FAIL/CLEAR_ERROR) are
 * always honored. Advancing events apply their payload and move to the next step ONLY
 * when they match the current step's expected milestone; otherwise the state is returned
 * unchanged (idempotent — safe against duplicate/out-of-order events).
 */
export function ceremonyReducer(state: CeremonyState, event: CeremonyEvent): CeremonyState {
  switch (event.type) {
    case 'RESET':
      return initCeremony(state.role, state.startedAt);
    case 'CLEAR_ERROR':
      return state.error === null ? state : { ...state, error: null };
    case 'FAIL':
      return { ...state, error: event.error };
    default:
      break;
  }

  const step = state.step;
  if (step === 'complete') return state; // terminal — ignore advancing events
  if (event.type !== ADVANCING_EVENT[step]) return state; // out-of-order — no-op

  let patch: Partial<CeremonyState>;
  switch (event.type) {
    case 'HANDSHAKE_ESTABLISHED':
      patch = { peerRef: event.peerRef };
      break;
    case 'CARD_CONVEYED':
      patch = { peerFingerprint: event.peerFingerprint, peerName: event.peerName ?? null };
      break;
    case 'EDGE_PERSISTED':
      patch = { edgeId: event.edgeId };
      break;
    case 'LATTICE_RENDERED':
      patch = {};
      break;
    case 'SHARD_GIVEN':
      patch = { shardGiven: true };
      break;
    default:
      patch = {};
  }

  return { ...state, ...patch, step: nextStep(step), error: null };
}
