// src/lib/crypto/kdf-worker-factory.ts — the ONE place that names the worker script.
// `new Worker(new URL(..., import.meta.url))` is the form Next's bundler turns into a same-origin chunk. `import.meta` is a syntax error in a CommonJS
// loader (Playwright's, for one), so this module is loaded by kdf-offthread.ts with a dynamic import() and ONLY where a Worker exists: the modules that
// import vault.ts (the e2e specs, scripts) never load it.

import type { Argon2WorkerLike } from './kdf-offthread';

export function createArgon2Worker(): Argon2WorkerLike {
  return new Worker(new URL('./argon2.worker.ts', import.meta.url)) as unknown as Argon2WorkerLike;
}
