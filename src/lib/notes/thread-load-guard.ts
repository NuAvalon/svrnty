// src/lib/notes/thread-load-guard.ts
// The inbox's thread-selection effect re-runs whenever `threads` gets a NEW array identity, which loadThreads() produces on EVERY reload, and used to
// call loadNotes (a full-thread decrypt) from there, OUTSIDE the reload gate: a second, uncoalesced decrypt per reload. This guard answers "has the
// target thread actually changed since the last load?" so steady-state refreshes go through the gate only. A switch (A -> B -> A) or the first arrival
// creating the thread still loads.
export interface ThreadLoadGuard {
  /** true exactly when `nextThreadId` differs from the last one that was loaded (null = no thread yet). */
  shouldLoad(nextThreadId: string | null): boolean;
}

export function createThreadLoadGuard(): ThreadLoadGuard {
  let last: string | null | undefined; // undefined = nothing loaded yet
  return {
    shouldLoad(next) {
      if (last === next) return false;
      last = next;
      return true;
    },
  };
}
