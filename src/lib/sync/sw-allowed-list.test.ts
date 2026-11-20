// The service worker must NEVER handle the satellite's allowed-senders list (#959). The worker answers every /api/ GET network-first WITH cache write-through and falls back to the cached copy
// when the network fails. For this one endpoint that is wrong twice: a stale cached list would hide a row that is owed a DELETE (a failed GET must read as UNKNOWN, never as an old answer),
// and the owner's allowed list (who they allow) would sit in plaintext in Cache Storage. This test RUNS the worker's fetch handler against stubs, so it fails if the exclusion is removed.
// Run: node --import tsx --test src/lib/sync/sw-allowed-list.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const SRC = readFileSync(join(process.cwd(), 'public/sw.js'), 'utf8');

/** Load the worker with a stubbed ServiceWorkerGlobalScope and return its handlers, the cache name it declares and what it cached. */
function loadWorker() {
  const handlers: Record<string, (e: unknown) => void> = {};
  const self = { addEventListener: (t: string, fn: (e: unknown) => void) => { handlers[t] = fn; }, location: { origin: 'https://app.test' }, skipWaiting: () => Promise.resolve(), clients: { claim: () => Promise.resolve(), matchAll: async () => [] } };
  const puts: string[] = [];
  const caches = { open: async () => ({ addAll: async () => {}, put: async (r: { url: string }) => { puts.push(r.url); } }), match: async () => undefined, keys: async () => [], delete: async () => true };
  const fetchStub = async () => new Response('{"allowed":[]}', { status: 200 });
  new Function('self', 'caches', 'fetch', 'URL', 'Response', SRC)(self, caches, fetchStub, URL, Response);
  const name = /const CACHE_NAME = '([^']+)'/.exec(SRC)?.[1] ?? '';
  return { handlers, puts, name };
}

/** Fire the worker's fetch handler for a GET and report whether it took the request (respondWith) and what it cached. */
async function fire(url: string, method = 'GET') {
  const w = loadWorker();
  let handled = false; let pending: Promise<unknown> | undefined;
  const request = { method, url, mode: 'cors', headers: new Headers({ accept: 'application/json' }) };
  w.handlers.fetch({ request, respondWith: (p: Promise<unknown>) => { handled = true; pending = p; } });
  if (pending) await pending;
  await new Promise((r) => setTimeout(r, 5));
  return { handled, cached: w.puts };
}

test('SW1 a GET of the allowed-senders list is NOT handled by the worker: not intercepted, not cached, never answered from an old copy', async () => {
  for (const url of ['https://app.test/api/satellite/allowed/' + 'ab'.repeat(32), 'https://app.test/api/satellite/allowed/' + 'ab'.repeat(32) + '?x=1', 'https://app.test/api/satellite/allowed/' + 'ab'.repeat(32) + '/inbound']) {
    const r = await fire(url);
    assert.equal(r.handled, false, `the worker must leave ${url} to the browser`);
    assert.deepEqual(r.cached, [], 'and nothing is written to the cache');
  }
});

test('SW2 CONTROL: the worker still handles other /api/ GETs and build assets network-first, so SW1 is looking at a real exclusion and not a worker that handles nothing', async () => {
  const api = await fire('https://app.test/api/satellite/inbox/' + 'ab'.repeat(32));
  assert.equal(api.handled, true, 'another /api/ GET is still handled');
  assert.equal((await fire('https://app.test/_next/static/chunk.js')).handled, true);
  assert.equal((await fire('https://app.test/api/satellite/allowed/' + 'ab'.repeat(32), 'POST')).handled, false, 'non-GET requests were never handled');
});

test('SW3 the cache name is bumped past v4, so browsers install this worker and its activate step purges any list an earlier worker cached', () => {
  const { name } = loadWorker();
  const v = /^svrnty-v(\d+)$/.exec(name);
  assert.ok(v, `the cache name is svrnty-v<n> (got ${name})`);
  assert.ok(Number(v![1]) >= 5, `bumped past v4 (got ${name})`);
});
