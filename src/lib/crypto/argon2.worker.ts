// src/lib/crypto/argon2.worker.ts — the worker entry. All behaviour lives in argon2-worker-core.ts; this only connects it to the message port.
import { handleArgon2Request } from './argon2-worker-core';

const scope = self as unknown as {
  onmessage: ((ev: { data: unknown }) => void) | null;
  postMessage(msg: unknown, transfer?: Transferable[]): void;
};

scope.onmessage = (ev) => {
  const res = handleArgon2Request(ev.data);
  scope.postMessage(res, res.ok ? [res.key] : []);
};
