// src/lib/ceremony/useCeremony.ts
'use client';
//
// React binding for the ceremony state machine (task #482). Thin wrapper over the pure
// reducer in ./machine — the hook owns only the React plumbing (useReducer + stable
// action callbacks + injecting the clock at init). All transition logic stays in the
// proven, unit-tested reducer so this layer has nothing to test on its own.

import { useReducer, useMemo, useCallback } from 'react';
import {
  ceremonyReducer,
  initCeremony,
  ceremonyProgress,
  isComplete,
  type CeremonyRole,
  type CeremonyState,
  type CeremonyEvent,
} from './machine';

export interface CeremonyController {
  state: CeremonyState;
  /** 0..1 progress through the active steps. */
  progress: number;
  /** True once the flow reaches the terminal `complete` step. */
  complete: boolean;
  /** Escape hatch — dispatch any raw event. */
  dispatch: (event: CeremonyEvent) => void;

  // Semantic actions (one per milestone) — stable identities, safe as effect deps.
  handshakeEstablished: (peerRef: string) => void;
  cardConveyed: (peerFingerprint: string, peerName?: string | null) => void;
  edgePersisted: (edgeId: string) => void;
  latticeRendered: () => void;
  shardGiven: () => void;
  fail: (error: string) => void;
  clearError: () => void;
  reset: () => void;
}

/**
 * Drive a ceremony for a fixed `role`. The role is captured once at mount (a ceremony
 * instance is one role); to switch roles, remount (e.g. `key={role}`) or call `reset`,
 * which preserves the role and returns to a fresh handshake.
 */
export function useCeremony(role: CeremonyRole): CeremonyController {
  const [state, dispatch] = useReducer(
    ceremonyReducer,
    role,
    (r) => initCeremony(r, new Date().toISOString()),
  );

  const handshakeEstablished = useCallback(
    (peerRef: string) => dispatch({ type: 'HANDSHAKE_ESTABLISHED', peerRef }),
    [],
  );
  const cardConveyed = useCallback(
    (peerFingerprint: string, peerName?: string | null) =>
      dispatch({ type: 'CARD_CONVEYED', peerFingerprint, peerName }),
    [],
  );
  const edgePersisted = useCallback(
    (edgeId: string) => dispatch({ type: 'EDGE_PERSISTED', edgeId }),
    [],
  );
  const latticeRendered = useCallback(() => dispatch({ type: 'LATTICE_RENDERED' }), []);
  const shardGiven = useCallback(() => dispatch({ type: 'SHARD_GIVEN' }), []);
  const fail = useCallback((error: string) => dispatch({ type: 'FAIL', error }), []);
  const clearError = useCallback(() => dispatch({ type: 'CLEAR_ERROR' }), []);
  const reset = useCallback(() => dispatch({ type: 'RESET' }), []);

  return useMemo(
    () => ({
      state,
      progress: ceremonyProgress(state),
      complete: isComplete(state),
      dispatch,
      handshakeEstablished,
      cardConveyed,
      edgePersisted,
      latticeRendered,
      shardGiven,
      fail,
      clearError,
      reset,
    }),
    [
      state,
      handshakeEstablished,
      cardConveyed,
      edgePersisted,
      latticeRendered,
      shardGiven,
      fail,
      clearError,
      reset,
    ],
  );
}
