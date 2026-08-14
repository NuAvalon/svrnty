// src/lib/ceremony/machine.selftest.ts
//
// Standalone, framework-free proof of the ceremony state machine (task #482).
// Run:  npx tsx src/lib/ceremony/machine.selftest.ts
// Exits non-zero on the first failed assertion. Pure logic — no browser, no DOM.

import {
  ceremonyReducer,
  initCeremony,
  nextStep,
  stepIndex,
  isComplete,
  canAdvance,
  ceremonyProgress,
  stepLabel,
  CEREMONY_STEP_ORDER,
  type CeremonyState,
  type CeremonyEvent,
} from './machine';

let passed = 0;
function assert(cond: boolean, msg: string): void {
  if (!cond) {
    console.error(`  ✗ FAIL: ${msg}`);
    process.exit(1);
  }
  passed++;
}

const T0 = '2026-08-11T21:00:00.000Z';

// Drive a state through a list of events (fold).
function drive(state: CeremonyState, events: CeremonyEvent[]): CeremonyState {
  return events.reduce(ceremonyReducer, state);
}

// ── 1. Happy path (initiator): all five milestones advance in order ──
{
  let s = initCeremony('initiator', T0);
  assert(s.step === 'handshake', 'starts at handshake');
  assert(s.error === null && s.peerRef === null, 'fresh state is clean');

  s = ceremonyReducer(s, { type: 'HANDSHAKE_ESTABLISHED', peerRef: 'A1B2C3' });
  assert(s.step === 'card', 'handshake -> card');
  assert(s.peerRef === 'A1B2C3', 'peerRef captured');

  s = ceremonyReducer(s, { type: 'CARD_CONVEYED', peerFingerprint: 'fp-peer', peerName: 'Bob' });
  assert(s.step === 'edge', 'card -> edge');
  assert(s.peerFingerprint === 'fp-peer' && s.peerName === 'Bob', 'card artifacts captured');

  s = ceremonyReducer(s, { type: 'EDGE_PERSISTED', edgeId: 'edge-42' });
  assert(s.step === 'lattice', 'edge -> lattice');
  assert(s.edgeId === 'edge-42', 'edgeId captured');

  s = ceremonyReducer(s, { type: 'LATTICE_RENDERED' });
  assert(s.step === 'tear', 'lattice -> tear');

  s = ceremonyReducer(s, { type: 'SHARD_GIVEN' });
  assert(s.step === 'complete', 'tear -> complete');
  assert(s.shardGiven === true, 'shardGiven set');
  assert(isComplete(s), 'isComplete true at end');
  console.log('  ✓ happy path (initiator) advances through all 5 steps');
}

// ── 2. Guard: out-of-order advancing events are no-ops ──
{
  const s = initCeremony('initiator', T0); // on handshake
  const jumped = ceremonyReducer(s, { type: 'EDGE_PERSISTED', edgeId: 'x' });
  assert(jumped.step === 'handshake', 'cannot skip to edge from handshake');
  assert(jumped.edgeId === null, 'skipped event leaves no artifact');
  assert(jumped === s || JSON.stringify(jumped) === JSON.stringify(s), 'out-of-order event is a pure no-op');
  console.log('  ✓ out-of-order events are ignored (no skip, no corruption)');
}

// ── 3. Idempotency: duplicate advancing event does not double-advance ──
{
  let s = initCeremony('joiner', T0);
  s = ceremonyReducer(s, { type: 'HANDSHAKE_ESTABLISHED', peerRef: 'CODE1' });
  const once = s.step;
  s = ceremonyReducer(s, { type: 'HANDSHAKE_ESTABLISHED', peerRef: 'CODE2' });
  assert(once === 'card' && s.step === 'card', 'duplicate handshake stays on card');
  assert(s.peerRef === 'CODE1', 'duplicate does not overwrite the captured artifact');
  console.log('  ✓ duplicate advancing events do not double-advance');
}

// ── 4. Control events: FAIL / CLEAR_ERROR / RESET ──
{
  let s = initCeremony('initiator', T0);
  s = ceremonyReducer(s, { type: 'HANDSHAKE_ESTABLISHED', peerRef: 'Z9' });
  s = ceremonyReducer(s, { type: 'FAIL', error: 'relay timeout' });
  assert(s.error === 'relay timeout', 'FAIL sets error');
  assert(s.step === 'card', 'FAIL does not change the step');

  s = ceremonyReducer(s, { type: 'CLEAR_ERROR' });
  assert(s.error === null, 'CLEAR_ERROR clears error');

  s = ceremonyReducer(s, { type: 'RESET' });
  assert(s.step === 'handshake' && s.peerRef === null, 'RESET returns to a fresh handshake');
  assert(s.role === 'initiator' && s.startedAt === T0, 'RESET preserves role + startedAt');
  console.log('  ✓ control events (FAIL / CLEAR_ERROR / RESET) behave');
}

// ── 5. Terminal: events after complete are no-ops ──
{
  const full: CeremonyEvent[] = [
    { type: 'HANDSHAKE_ESTABLISHED', peerRef: 'p' },
    { type: 'CARD_CONVEYED', peerFingerprint: 'f' },
    { type: 'EDGE_PERSISTED', edgeId: 'e' },
    { type: 'LATTICE_RENDERED' },
    { type: 'SHARD_GIVEN' },
  ];
  let s = drive(initCeremony('joiner', T0), full);
  assert(s.step === 'complete', 'reaches complete');
  const after = ceremonyReducer(s, { type: 'SHARD_GIVEN' });
  assert(after.step === 'complete', 'events after complete are ignored');
  console.log('  ✓ terminal state absorbs further advancing events');
}

// ── 6. Helpers ──
{
  assert(nextStep('handshake') === 'card', 'nextStep handshake->card');
  assert(nextStep('tear') === 'complete', 'nextStep tear->complete');
  assert(nextStep('complete') === 'complete', 'nextStep complete->complete');
  assert(stepIndex('handshake') === 0 && stepIndex('complete') === 5, 'stepIndex bounds');
  assert(CEREMONY_STEP_ORDER.length === 6, 'six steps incl complete');

  const fresh = initCeremony('initiator', T0);
  assert(ceremonyProgress(fresh) === 0, 'progress 0 at handshake');
  const done = drive(fresh, [
    { type: 'HANDSHAKE_ESTABLISHED', peerRef: 'p' },
    { type: 'CARD_CONVEYED', peerFingerprint: 'f' },
    { type: 'EDGE_PERSISTED', edgeId: 'e' },
    { type: 'LATTICE_RENDERED' },
    { type: 'SHARD_GIVEN' },
  ]);
  assert(ceremonyProgress(done) === 1, 'progress 1 at complete');
  assert(canAdvance(fresh, { type: 'HANDSHAKE_ESTABLISHED', peerRef: 'p' }), 'canAdvance true for the right event');
  assert(!canAdvance(fresh, { type: 'EDGE_PERSISTED', edgeId: 'e' }), 'canAdvance false for the wrong event');
  assert(!canAdvance(done, { type: 'SHARD_GIVEN' }), 'canAdvance false when complete');
  assert(stepLabel('tear') === 'The tear', 'stepLabel maps');
  console.log('  ✓ helpers (nextStep / stepIndex / progress / canAdvance / labels)');
}

console.log(`\n✓ ALL ${passed} assertions passed — ceremony machine spine verified.`);
