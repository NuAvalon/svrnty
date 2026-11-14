// src/lib/crypto/argon2.worker.ts — the worker entry. All behaviour lives in argon2-worker-core.ts; this only connects it to the message port.
import { handleArgon2Request, ARGON2_READY } from './argon2-worker-core';

const scope = self as unknown as {
  onmessage: ((ev: { data: unknown }) => void) | null;
  postMessage(msg: unknown, transfer?: Transferable[]): void;
};

// Loaded: tell the page this worker STARTED, so a later error event means it ran and died (never re-run on the page), not that it could not start.
scope.postMessage(ARGON2_READY);

scope.onmessage = (ev) => {
  const res = handleArgon2Request(ev.data);
  scope.postMessage(res, res.ok ? [res.key] : []);
};
