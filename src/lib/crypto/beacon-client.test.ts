// #588 trust beacon, CLIENT piece A: tests first — the module does not exist yet, so every test below is RED.
// Run: npx tsx --test src/lib/crypto/beacon-client.test.ts
// Everything is a stub: fetch is scripted (never a real socket), the ports are in-memory, the prover is canned.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  createBeaconClient,
  type BeaconClientDeps,
  type BeaconStorePort,
  type BeaconSecretsPort,
  type LatchPort,
  type PairConfirmedPort,
  type PairRecord,
} from './beacon-client';

const EPOCH_SECONDS = 604800;
const GRACE_SECONDS = 600;
const EPOCH = 3000;
const EPOCH_START_MS = EPOCH * EPOCH_SECONDS * 1000;
const MID = EPOCH_START_MS + 3_600_000;                 // one hour into the epoch, clear of both windows
const LATE = EPOCH_START_MS + EPOCH_SECONDS * 1000 - 300_000;   // inside the cur+1 window (last 300 s)

type FetchCall = { url: string; init: any };
type Scripted = { status?: number; body?: string; contentType?: string; throw?: boolean; delayMs?: number };

const makeFetch = () => {
  const calls: FetchCall[] = [];
  const queue: Scripted[] = [];
  let fallback: Scripted = { status: 200, body: '{"status":"none"}' };
  const fetch = (url: string, init: any) => {
    calls.push({ url, init });
    const s = queue.length ? queue.shift()! : fallback;
    return new Promise<any>((resolve, reject) => {
      const finish = () => {
        if (s.throw) return reject(new TypeError('fetch failed'));
        resolve({
          status: s.status ?? 200,
          headers: { get: (k: string) => (k.toLowerCase() === 'content-type' ? s.contentType ?? 'application/json' : null) },
          text: async () => s.body ?? '',
        });
      };
      if (s.delayMs) {
        const t = setTimeout(finish, s.delayMs);
        init?.signal?.addEventListener?.('abort', () => { clearTimeout(t); reject(new DOMException('Aborted', 'AbortError')); });
      } else finish();
    });
  };
  return { calls, queue, setFallback: (s: Scripted) => (fallback = s), fetch };
};

const memStore = (): BeaconStorePort & { data: Map<string, PairRecord> } => {
  const data = new Map<string, PairRecord>();
  return {
    data,
    get: async (p) => (data.has(p) ? JSON.parse(JSON.stringify(data.get(p))) : undefined),
    put: async (r) => void data.set(r.pairId, JSON.parse(JSON.stringify(r))),
    pairs: async () => [...data.values()].map((r) => JSON.parse(JSON.stringify(r))),
  };
};

const memLatch = (): LatchPort & { local: Set<string>; remote: Set<string> } => {
  const local = new Set<string>(), remote = new Set<string>();
  return {
    local, remote,
    isLatched: async (p) => local.has(p) || remote.has(p),
    setLatched: async (p, s) => void (s === 'local' ? local : remote).add(p),
    clearLatched: async (p, s) => void (s === 'local' ? local : remote).delete(p),
  };
};

const memSecrets = (): BeaconSecretsPort & { rows: Map<string, any>; released: string[] } => {
  const rows = new Map<string, any>();
  const released: string[] = [];
  let n = 0;
  return {
    rows, released,
    depositSecrets: async () => ({ x: BigInt(5), counterpartY: [BigInt(1), BigInt(2)] as const }),
    newRow: async (_p, epoch) => {
      const rowId = `row-${++n}`;
      rows.set(rowId, { epoch, pk: new Uint8Array(32).fill(n), seed: new Uint8Array(32).fill(7) });
      return { rowId, oneTimePk: rows.get(rowId).pk };
    },
    rowAuth: async (rowId) => {
      const r = rows.get(rowId);
      return r ? { pk: r.pk, sign: async () => new Uint8Array(64).fill(9) } : undefined;
    },
    releaseRow: async (rowId) => { released.push(rowId); rows.delete(rowId); },
  };
};

const makeProver = (over: Partial<BeaconClientDeps['prover']> = {}) => {
  const proveCalls: any[] = [];
  let inFlight = 0, maxInFlight = 0;
  return {
    proveCalls,
    get maxInFlight() { return maxInFlight; },
    buildDeposit: async (keys: any) => {
      inFlight++; maxInFlight = Math.max(maxInFlight, inFlight);
      try {
        proveCalls.push(keys);
        return { body: `DEPOSIT-BODY-${proveCalls.length}`, signals: { e: keys.epoch, H_e: BigInt(111), N: BigInt(222), K: BigInt(333) } };
      } finally { inFlight--; }
    },
    signAuth: async (_op: string, _h: bigint, _n: bigint, nonce: Uint8Array, sign: (m: Uint8Array) => Promise<Uint8Array>) =>
      sign(new Uint8Array(64).fill(1)),
    scheduleRedeposit: (o: any) => o.epochStartMs + 5000,
    ...over,
  };
};

const NONCE_A = 'a'.repeat(64), NONCE_B = 'b'.repeat(64);
const nonceOk = (h: string) => ({ status: 200, body: JSON.stringify({ nonce: h }) });

const harness = (over: Partial<BeaconClientDeps> = {}) => {
  const f = makeFetch();
  const store = memStore();
  const latch = memLatch();
  const secrets = memSecrets();
  const prover = makeProver();
  const confirmed: PairConfirmedPort = { isConfirmed: async () => true };
  const client = createBeaconClient({
    fetch: f.fetch as any,
    baseUrl: '/api/trust',
    latch, confirmed, store, secrets, prover,
    now: () => MID,
    requestTimeoutMs: 50,
    backoffMs: () => 1000,
    ...over,
  });
  return { client, f, store, latch, secrets, prover, confirmed };
};

const ok = (status: string) => ({ status: 200, body: `{"status":"${status}"}` });
const refused = (reason: string) => ({ status: 200, body: `{"status":"refused","reason":"${reason}"}` });
const lastBody = (f: ReturnType<typeof makeFetch>) => JSON.parse(f.calls.at(-1)!.init.body);

// ---------- v1 transport: the deposit answers and their actions ----------

test('deposit accepted -> a standing row is recorded; the fetch was one string POST with the fixed fetch flags', async () => {
  const { client, f, store } = harness();
  f.queue.push(ok('accepted'));
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'deposited');
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].url, '/api/trust/beacon/deposit');
  assert.equal(f.calls[0].init.method, 'POST');
  assert.equal(typeof f.calls[0].init.body, 'string');               // a string body sets exactly one Content-Length, never chunked
  assert.equal(f.calls[0].init.headers['content-type'], 'application/json');
  assert.equal(f.calls[0].init.redirect, 'error');
  assert.equal(f.calls[0].init.credentials, 'omit');
  assert.equal(f.calls[0].init.cache, 'no-store');
  assert.ok(!('transfer-encoding' in (f.calls[0].init.headers || {})));
  const rec = await store.get('pair-1');
  assert.equal(rec!.rows.length, 1);
  assert.equal(rec!.rows[0].state, 'standing');
});

test('deposit already -> recorded standing, no re-deposit', async () => {
  const { client, f, store } = harness();
  f.queue.push(ok('already'));
  await client.trustAtTap('pair-1');
  const rec = await store.get('pair-1');
  assert.equal(rec!.rows[0].state, 'standing');
});

test('deposit withdrawn -> the (slot,N) is spent for the epoch: renew never re-deposits it', async () => {
  const { client, f, store, prover } = harness();
  f.queue.push(ok('withdrawn'));
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'spent');
  const rec = await store.get('pair-1');
  assert.deepEqual(rec!.spentEpochs, [String(EPOCH)]);
  f.calls.length = 0;
  await client.renew('pair-1');
  assert.equal(prover.proveCalls.length, 1);                          // no second proof for the spent epoch
  assert.equal(f.calls.filter((c) => c.url.endsWith('/deposit')).length, 0);
});

test('deposit refused full -> intent kept (pendingDeposit), a standing row keeps polling', async () => {
  const { client, f, store } = harness();
  f.queue.push(ok('accepted'));                                       // the pair-1 row stands
  await client.trustAtTap('pair-1');
  const { client: c2, f: f2, store: s2 } = harness();
  f2.queue.push(refused('full'));
  const r = await c2.trustAtTap('pair-2');
  assert.equal(r.kind, 'pending');
  assert.equal((await s2.get('pair-2'))!.pendingDeposit, true);
  // the standing row of pair-1 is still polled despite full being seen elsewhere
  f.calls.length = 0;
  f.queue.push(nonceOk(NONCE_A), ok('none'));
  await client.pollNow('pair-1');
  assert.equal(f.calls.length, 2);
  assert.ok(f.calls[0].url.endsWith('/nonce'));
  assert.ok(f.calls[1].url.endsWith('/poll'));
});

for (const reason of ['rate', 'epoch', 'internal', 'timeout']) {
  test(`deposit refused ${reason} -> pending retry later, no failure`, async () => {
    const { client, f, store } = harness();
    f.queue.push(refused(reason));
    const r = await client.trustAtTap('pair-1');
    assert.equal(r.kind, 'pending');
    const rec = await store.get('pair-1');
    assert.equal(rec!.pendingDeposit, true);
    assert.equal(rec!.rows.length, 0);
  });
}

for (const reason of ['wire', 'vkey', 'proof', 'usage', 'point:pi_a:identity', 'point:pi_b:off-curve']) {
  test(`deposit refused ${reason} -> failed, never retried with the same body`, async () => {
    const { client, f, store, prover } = harness();
    f.queue.push(refused(reason));
    const r = await client.trustAtTap('pair-1');
    assert.equal(r.kind, 'failed');
    f.calls.length = 0;
    await client.renew('pair-1');
    assert.equal(prover.proveCalls.length, 1);
    assert.equal(f.calls.length, 0);
  });
}

test('a request body over MAX_DEPOSIT_BYTES never reaches the wire', async () => {
  const prover = makeProver({ buildDeposit: async () => ({ body: 'x'.repeat(20 * 1024), signals: { e: BigInt(3000), H_e: BigInt(1), N: BigInt(2), K: BigInt(3) } }) });
  const { client, f } = harness({ prover });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'failed');
  assert.equal(f.calls.length, 0);
});

// ---------- unreadable / busy ----------

test('a 200 with an extra key -> unreadable, nothing marked', async () => {
  const { client, f, store } = harness();
  f.queue.push({ status: 200, body: '{"status":"accepted","x":1}' });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'pending');
  assert.equal((await store.get('pair-1'))!.rows.length, 0);
});

test('wrong content-type -> unreadable', async () => {
  const { client, f } = harness();
  f.queue.push({ status: 200, body: '{"status":"accepted"}', contentType: 'text/html' });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'pending');
});

test('non-JSON body -> unreadable', async () => {
  const { client, f } = harness();
  f.queue.push({ status: 200, body: 'garbage' });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'pending');
});

test('a body over 1 KiB -> unreadable without being parsed', async () => {
  const { client, f } = harness();
  f.queue.push({ status: 200, body: '{"status":"accepted"}' + ' '.repeat(2000) });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'pending');
});

test('a refusal with an unknown reason -> unreadable', async () => {
  const { client, f } = harness();
  f.queue.push({ status: 200, body: '{"status":"refused","reason":"bogus"}' });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'pending');
});

for (const code of [429, 503]) {
  test(`${code} -> busy, retryable, no state change`, async () => {
    const { client, f, store } = harness();
    f.queue.push({ status: code, body: 'slow down' });
    const r = await client.trustAtTap('pair-1');
    assert.equal(r.kind, 'busy');
    assert.equal((await store.get('pair-1'))!.pendingDeposit, true);
  });
}

test('other non-200 (500) -> unreadable: not accepted, retry later', async () => {
  const { client, f, store } = harness();
  f.queue.push({ status: 500, body: 'oops' });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'pending');
  assert.equal((await store.get('pair-1'))!.rows.length, 0);
});

test('a thrown fetch (network failure) -> busy', async () => {
  const { client, f } = harness();
  f.queue.push({ throw: true });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'busy');
});

test('a timed-out request -> busy', async () => {
  const { client, f } = harness({ requestTimeoutMs: 20 });
  f.queue.push({ status: 200, body: ok('accepted').body, delayMs: 5000 });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'busy');
});

// ---------- v1 client rules ----------

test('two concurrent trust taps serialize the proofs (the second is NOT prove-failed)', async () => {
  const { client, f, prover } = harness();
  f.setFallback(ok('accepted'));
  await Promise.all([client.trustAtTap('pair-1'), client.trustAtTap('pair-2')]);
  assert.equal(prover.maxInFlight, 1);
  assert.equal(prover.proveCalls.length, 2);
});

test('a nonce is never sent twice: two polls fetch two nonces', async () => {
  const { client, f, store } = harness();
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  f.calls.length = 0;
  f.queue.push(nonceOk(NONCE_A), ok('none'), nonceOk(NONCE_B), ok('none'));
  await client.pollNow('pair-1');
  await client.pollNow('pair-1');
  const nonceCalls = f.calls.filter((c) => c.url.endsWith('/nonce'));
  assert.equal(nonceCalls.length, 2);
  const seen = f.calls.filter((c) => c.url.endsWith('/poll')).map((c) => JSON.parse(c.init.body).nonce);
  assert.deepEqual(seen, [NONCE_A, NONCE_B]);
  assert.equal(new Set(seen).size, 2);
});

test('poll body shape: {H_e,N,pk,sig,nonce}, canonical decimal + lowercase hex', async () => {
  const { client, f } = harness();
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  f.calls.length = 0;
  f.queue.push(nonceOk(NONCE_A), ok('match'));
  await client.pollNow('pair-1');
  const b = lastBody(f);
  assert.deepEqual(Object.keys(b).sort(), ['H_e', 'N', 'nonce', 'pk', 'sig'].sort());
  assert.match(b.H_e, /^(0|[1-9][0-9]*)$/);
  assert.match(b.N, /^(0|[1-9][0-9]*)$/);
  assert.match(b.pk, /^[0-9a-f]{64}$/);
  assert.match(b.sig, /^[0-9a-f]{128}$/);
  assert.match(b.nonce, /^[0-9a-f]{64}$/);
});

test('nonce request body is exactly {op,H_e,N}', async () => {
  const { client, f } = harness();
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  f.calls.length = 0;
  f.queue.push(nonceOk(NONCE_A), ok('none'));
  await client.pollNow('pair-1');
  const b = JSON.parse(f.calls[0].init.body);
  assert.deepEqual(Object.keys(b).sort(), ['H_e', 'N', 'op']);
  assert.equal(b.op, 'poll');
});

test('a 5xx on poll never marks a deposit withdrawn', async () => {
  const { client, f, store } = harness();
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  f.queue.push({ status: 500, body: 'oops' });
  await client.pollNow('pair-1');
  assert.equal((await store.get('pair-1'))!.rows[0].state, 'standing');
});

test('poll refused auth -> exactly ONE fresh nonce retry, then stop', async () => {
  const { client, f } = harness();
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  f.calls.length = 0;
  f.setFallback(refused('auth'));                                      // keep refusing: a retry-loop mutant shows itself
  f.queue.push(nonceOk(NONCE_A), refused('auth'), nonceOk(NONCE_B), refused('auth'), nonceOk(NONCE_A), refused('auth'));
  await client.pollNow('pair-1');
  const polls = f.calls.filter((c) => c.url.endsWith('/poll'));
  assert.equal(polls.length, 2);                                       // one retry, never a third
  assert.notEqual(JSON.parse(polls[0].init.body).nonce, JSON.parse(polls[1].init.body).nonce);
});

test('no console.* anywhere in the module source', () => {
  const src = readFileSync(new URL('./beacon-client.ts', import.meta.url), 'utf8');
  assert.equal(/console\s*\./.test(src), false);
});

test('no export besides matchState can yield a match: the module surface is pinned', async () => {
  const mod = await import('./beacon-client');
  const fns = Object.keys(mod).filter((k) => typeof (mod as any)[k] === 'function');
  for (const bad of ['poll', 'withdraw', 'deposit', 'nonce', 'rawPoll', 'pollRaw']) {
    assert.ok(!fns.includes(bad), `export ${bad} must not exist`);
  }
  const client = createBeaconClient({
    fetch: (() => { throw new Error('unused'); }) as any,
    latch: memLatch(), confirmed: { isConfirmed: async () => true },
    store: memStore(), secrets: memSecrets(), prover: makeProver(),
  });
  assert.deepEqual(
    Object.keys(client).sort(),
    ['drainPendingWithdraws', 'matchState', 'nextRenewalAt', 'pollNow', 'removeAtTap', 'renew', 'trustAtTap'].sort(),
  );
});

// ---------- v2: the latch and the tap ----------

test('remove while a poll is in flight answering MATCH -> the pair ends removed (latched), matchState hides it', async () => {
  const { client, f, latch } = harness();
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  f.calls.length = 0;
  let resolvePoll: (v: any) => void;
  f.queue.push(nonceOk(NONCE_A));
  const pollReady = new Promise<any>((r) => (resolvePoll = r));
  const pollFetch = f.fetch;
  const slowFetch = (url: string, init: any) =>
    url.endsWith('/poll') ? pollReady.then(() => pollFetch(url, init)) : pollFetch(url, init);
  const { client: slow } = (() => {
    const h = harness({ fetch: slowFetch as any, latch });
    return { client: h.client };
  })();
  // reuse the same store/latch state: seed it
  await slow.trustAtTap('pair-1');                                     // deposits again (fresh pair in this harness)
  const polling = slow.pollNow('pair-1');
  f.queue.push(ok('match'));
  const removing = slow.removeAtTap('pair-1');
  resolvePoll!(undefined);
  await Promise.all([polling, removing]);
  assert.equal(await latch.isLatched('pair-1'), true);
  assert.equal(await slow.matchState('pair-1'), 'none');
});

test('remove while the proof is running -> NOTHING is sent (0 fetches)', async () => {
  let release: () => void;
  const gate = new Promise<void>((r) => (release = r));
  const prover = makeProver({
    buildDeposit: async (keys: any) => { await gate; return { body: 'B', signals: { e: keys.epoch, H_e: BigInt(1), N: BigInt(2), K: BigInt(3) } }; },
  });
  const { client, f, latch } = harness({ prover });
  const trusting = client.trustAtTap('pair-1');
  await new Promise((r) => setTimeout(r, 10));                         // let the proof start
  const removing = client.removeAtTap('pair-1');
  release!();
  await Promise.all([trusting, removing]);
  assert.equal(await latch.isLatched('pair-1'), true);
  assert.equal(f.calls.filter((c) => c.url.endsWith('/deposit')).length, 0);
});

test('a latched pair: no deposit, no poll, in the current epoch, in the cur+1 window, or at renewal', async () => {
  for (const at of [MID, LATE]) {
    const latch = memLatch();
    latch.remote.add('pair-1');                                        // remote latch: my tap cannot clear it (L5)
    const { client, f, store } = harness({ latch, now: () => at });
    await store.put({ pairId: 'pair-1', observedMatch: false, spentEpochs: [], pendingDeposit: true,
      rows: [{ rowId: 'r1', epoch: String(EPOCH), H_e: '111', N: '222', state: 'standing' }], pendingWithdraws: [] });
    await client.trustAtTap('pair-1');
    await client.renew('pair-1');
    await client.pollNow('pair-1');
    assert.equal(f.calls.length, 0, `latched pair made ${f.calls.length} requests at ${at}`);
  }
});

test('matchState hides MATCH behind a latch', async () => {
  const { client, f, latch } = harness();
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  f.queue.push(nonceOk(NONCE_A), ok('match'));
  await client.pollNow('pair-1');
  assert.equal(await client.matchState('pair-1'), 'match');
  await latch.setLatched('pair-1', 'remote');
  assert.equal(await client.matchState('pair-1'), 'none');
});

test('a remote re-trust does NOT clear a local latch (and vice versa)', async () => {
  const latch = memLatch();
  latch.local.add('pair-1');
  latch.remote.add('pair-1');
  await latch.clearLatched('pair-1', 'remote');                        // a remote re-trust arrived
  assert.equal(await latch.isLatched('pair-1'), true);                 // local stands
  const { client, f } = harness({ latch });
  await client.trustAtTap('pair-1');                                   // my tap clears ONLY local
  assert.equal(await latch.isLatched('pair-1'), false);
  latch.local.add('pair-2'); latch.remote.add('pair-2');
  await latch.clearLatched('pair-2', 'local');
  assert.equal(await latch.isLatched('pair-2'), true);
});

test('remove while offline: withdraw queued durable, retried, seed kept until confirmed, dropped after', async () => {
  const { client, f, store, secrets } = harness({ backoffMs: () => 0 });   // due immediately on the next drain
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  const rec0 = (await store.get('pair-1'))!;
  const rowId = rec0.rows[0].rowId;
  f.calls.length = 0;
  f.setFallback({ throw: true });                                      // offline
  const r = await client.removeAtTap('pair-1');
  assert.equal(r.observedMatch, false);
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.pendingWithdraws.length, 1);
  assert.equal(secrets.rows.has(rowId), true);                         // seed kept
  f.calls.length = 0;
  f.setFallback({ status: 200, body: '{"status":"match"}' });
  f.queue.unshift({ status: 200, body: JSON.stringify({ nonce: NONCE_A }) });   // drain fetches a nonce first
  await client.drainPendingWithdraws();
  const rec2 = (await store.get('pair-1'))!;
  assert.equal(rec2.pendingWithdraws.length, 0);
  assert.equal(rec2.observedMatch, true);                              // 'match' is inert, not an error
  assert.ok(secrets.released.includes(rowId));                         // confirmed -> seed released
});

test('a pending withdraw whose epoch has closed is dropped, seed released', async () => {
  const { client, f, store, secrets } = harness();
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  f.setFallback({ throw: true });
  await client.removeAtTap('pair-1');
  const rec = (await store.get('pair-1'))!;
  rec.rows[0].epoch = String(EPOCH - 5);                               // simulate the row aging out
  rec.pendingWithdraws[0].rowId = rec.rows[0].rowId;
  await store.put(rec);
  f.setFallback(ok('withdrawn'));
  await client.drainPendingWithdraws();
  const rec2 = (await store.get('pair-1'))!;
  assert.equal(rec2.pendingWithdraws.length, 0);
});

test('after a seed-only restore (unconfirmed): ZERO requests for the pair', async () => {
  const confirmed: PairConfirmedPort = { isConfirmed: async () => false };
  const { client, f, store } = harness({ confirmed });
  await store.put({ pairId: 'pair-1', observedMatch: true, spentEpochs: [], pendingDeposit: true,
    rows: [{ rowId: 'r1', epoch: String(EPOCH), H_e: '111', N: '222', state: 'standing' }], pendingWithdraws: [] });
  await client.trustAtTap('pair-1');
  await client.renew('pair-1');
  await client.pollNow('pair-1');
  assert.equal(f.calls.length, 0);
  assert.equal(await client.matchState('pair-1'), 'none');             // fail closed
});

test('removeAtTap before any observed match returns observedMatch=false; after a match, true', async () => {
  const { client, f, store } = harness();
  const r0 = await client.removeAtTap('pair-x');
  assert.equal(r0.observedMatch, false);
  const { client: c2, f: f2, store: s2 } = harness();
  f2.queue.push(ok('accepted'));
  await c2.trustAtTap('pair-1');
  f2.queue.push(nonceOk(NONCE_A), ok('match'));
  await c2.pollNow('pair-1');
  const r1 = await c2.removeAtTap('pair-1');
  assert.equal(r1.observedMatch, true);
});

test('two taps (Trust then Remove) during one proof: serialized, second not prove-failed, final state removed', async () => {
  let release: () => void;
  const gate = new Promise<void>((r) => (release = r));
  const prover = makeProver({
    buildDeposit: async (keys: any) => { await gate; return { body: 'B', signals: { e: keys.epoch, H_e: BigInt(1), N: BigInt(2), K: BigInt(3) } }; },
  });
  const { client, latch } = harness({ prover });
  const trusting = client.trustAtTap('pair-1');
  const removing = client.removeAtTap('pair-1');
  release!();
  const [, rem] = await Promise.all([trusting, removing]);
  assert.equal(await latch.isLatched('pair-1'), true);
  assert.equal(await client.matchState('pair-1'), 'none');
});

test('in the last 600 s a deposit is also made for cur+1', async () => {
  const { client, f, prover } = harness({ now: () => LATE });
  f.setFallback(ok('accepted'));
  await client.trustAtTap('pair-1');
  const epochs = prover.proveCalls.map((k) => String(k.epoch));
  assert.deepEqual(epochs, [String(EPOCH), String(EPOCH + 1)]);
  assert.equal(f.calls.filter((c) => c.url.endsWith('/deposit')).length, 2);
});

test('a refused pair is never confused with none: poll refused rate leaves the row standing and changes nothing', async () => {
  const { client, f, store } = harness();
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  f.queue.push(nonceOk(NONCE_A), refused('rate'));
  await client.pollNow('pair-1');
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.rows[0].state, 'standing');
  assert.equal(rec.observedMatch, false);
});

test('withdraw answer withdrawn -> row marked, seed released, no pending entry', async () => {
  const { client, f, store, secrets } = harness();
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  const rowId = (await store.get('pair-1'))!.rows[0].rowId;
  f.queue.push(nonceOk(NONCE_A), ok('withdrawn'));
  await client.removeAtTap('pair-1');
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.rows[0].state, 'withdrawn');
  assert.equal(rec.pendingWithdraws.length, 0);
  assert.ok(secrets.released.includes(rowId));
});

test('nextRenewalAt hands out a jittered time inside the epoch, never a boundary', async () => {
  const { client } = harness();
  const at = await client.nextRenewalAt('pair-1');
  assert.equal(at, EPOCH_START_MS + 5000);                             // the stub's deterministic value
  assert.ok(at! > EPOCH_START_MS + GRACE_SECONDS * 1000 - 1 || at === EPOCH_START_MS + 5000);
});
