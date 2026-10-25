// src/components/compose/compose-registry.ts
// The ONE ComposeController of this tab, shared by the host (mounted at the app shell) and the Settings pin panel (mounted far away in the tree).
// Module state, not React context: the two components are not ancestors of each other.
import { useEffect, useState, useSyncExternalStore } from 'react';
import type { ComposeController, ControllerSnapshot } from './compose-controller';

let active: ComposeController | null = null;
const listeners = new Set<() => void>();

export function setActiveComposeController(c: ComposeController | null): void {
  if (active === c) return;
  active = c;
  for (const l of [...listeners]) l();
}

export function getActiveComposeController(): ComposeController | null {
  return active;
}

function subscribeRegistry(l: () => void): () => void {
  listeners.add(l);
  return () => {
    listeners.delete(l);
  };
}

/** The tab's controller (or null while none is mounted: signed out, locked, or before the first render). */
export function useActiveComposeController(): ComposeController | null {
  return useSyncExternalStore(subscribeRegistry, getActiveComposeController, () => null);
}

/** The controller's current snapshot, following both a controller swap and every change inside it. */
export function useComposeSnapshot(): ControllerSnapshot | null {
  const c = useActiveComposeController();
  const [snap, setSnap] = useState<ControllerSnapshot | null>(c ? c.getSnapshot() : null);
  useEffect(() => {
    if (!c) {
      setSnap(null);
      return;
    }
    setSnap(c.getSnapshot());
    return c.subscribe(() => setSnap(c.getSnapshot()));
  }, [c]);
  return snap;
}
