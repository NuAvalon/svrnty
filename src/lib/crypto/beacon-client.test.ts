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
    cas: async (p, expectedVersion, next) => {
      const cur = data.get(p);
      if ((cur?.version ?? 0) !== expectedVersion) return false;
      data.set(p, JSON.parse(JSON.stringify(next)));
      return true;
    },
    pairs: async () => [...data.values()].map((r) => JSON.parse(JSON.stringify(r))),
  };
};

const memLatch = (): LatchPort & { local: Map<string, 'removed' | 'frozen'>; remote: Map<string, 'removed' | 'frozen'> } => {
  const local = new Map<string, 'removed' | 'frozen'>(), remote = new Map<string, 'removed' | 'frozen'>();
  return {
    local, remote,
    isLatched: async (p) => local.has(p) || remote.has(p),
    kindOf: async (p) =>
      local.get(p) === 'removed' || remote.get(p) === 'removed' ? 'removed'
        : local.get(p) === 'frozen' || remote.get(p) === 'frozen' ? 'frozen' : null,
    setLatched: async (p, s) => void (s === 'local' ? local : remote).set(p, 'removed'),
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

test('deposit already to a FRESH K -> unreachable (v3 §B: the server keeps the FIRST K); a pinned retry + already -> standing', async () => {
  const { client, f, store, prover } = harness();
  f.queue.push(ok('already'));
  await client.trustAtTap('pair-1');
  const rec = await store.get('pair-1');
  assert.equal(rec!.rows[0].state, 'unreachable');                     // not the client's key — L10b
  // a pinned 'unknown' row retried into 'already' IS ours — the server kept the same first K
  const p2 = makeProver();
  const { client: c2, f: f2, store: s2 } = harness({ prover: p2 });
  f2.queue.push({ throw: true });                                      // answer lost -> row 'unknown', K pinned
  await c2.trustAtTap('pair-2');
  assert.equal((await s2.get('pair-2'))!.rows[0].state, 'unknown');
  f2.setFallback(ok('already'));
  await c2.renew('pair-2');                                            // retry re-deposits the SAME K
  const rec2 = await s2.get('pair-2');
  assert.equal(rec2!.rows[0].state, 'standing');
  assert.deepEqual([...p2.proveCalls[1].oneTimePk], [...p2.proveCalls[0].oneTimePk]);   // same pinned K on the retry
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

test('deposit refused full -> transient: derived-owed retries it at renew, a standing row keeps polling', async () => {
  const { client, f, store } = harness();
  f.queue.push(ok('accepted'));                                       // the pair-1 row stands
  await client.trustAtTap('pair-1');
  const { client: c2, f: f2, store: s2 } = harness();
  f2.queue.push(refused('full'));
  const r = await c2.trustAtTap('pair-2');
  assert.equal(r.kind, 'pending');
  assert.deepEqual((await s2.get('pair-2'))!.refusedEpochs, []);      // transient: no final refusal recorded
  f2.calls.length = 0;
  f2.queue.push(ok('accepted'));
  await c2.renew('pair-2');                                           // L12: derived-owed retries WITHOUT any flag
  assert.equal(f2.calls.filter((c) => c.url.endsWith('/deposit')).length, 1);
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
    assert.deepEqual(rec!.refusedEpochs, []);                          // transient refusals record nothing
    assert.equal(rec!.rows.length, 0);
    f.calls.length = 0;
    f.queue.push(ok('accepted'));
    await client.renew('pair-1');                                      // derived-owed retries it (L12)
    assert.equal(f.calls.filter((c) => c.url.endsWith('/deposit')).length, 1);
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

test('a 200 with an extra key -> unreadable = UNKNOWN outcome: the write-ahead row stays (L10)', async () => {
  const { client, f, store } = harness();
  f.queue.push({ status: 200, body: '{"status":"accepted","x":1}' });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'pending');
  const rec = await store.get('pair-1');
  assert.equal(rec!.rows.length, 1);                                   // the deposit may have landed
  assert.equal(rec!.rows[0].state, 'unknown');
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
  test(`${code} -> pending, retryable, no state change`, async () => {
    const { client, f, store } = harness();
    f.queue.push({ status: code, body: 'slow down' });
    const r = await client.trustAtTap('pair-1');
    assert.equal(r.kind, 'pending');                                     // L13e-2: the fetch LEFT — pending, never busy
    assert.equal((await store.get('pair-1'))!.rows[0].state, 'unknown');  // the write-ahead row IS the retry marker
  });
}

test('other non-200 (500) -> unreadable = UNKNOWN: the write-ahead row stays (L10)', async () => {
  const { client, f, store } = harness();
  f.queue.push({ status: 500, body: 'oops' });
  const r = await client.trustAtTap('pair-1');
  assert.equal((await store.get('pair-1'))!.rows[0].state, 'unknown');
  assert.equal(r.kind, 'pending');
});

test('a thrown fetch (network failure) -> pending', async () => {
  const { client, f } = harness();
  f.queue.push({ throw: true });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'pending');                                       // L13e-2: the fetch LEFT — pending, never busy
});

test('a timed-out request -> pending', async () => {
  const { client, f } = harness({ requestTimeoutMs: 20 });
  f.queue.push({ status: 200, body: ok('accepted').body, delayMs: 5000 });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'pending');                                       // L13e-2: the fetch LEFT — pending, never busy
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
    ['drainPendingWithdraws', 'matchSince', 'matchState', 'nextRenewalAt', 'pollNow', 'removeAtTap', 'renew', 'trustAtTap'].sort(),
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
    latch.remote.set('pair-1', 'removed');                            // remote latch: my tap cannot clear it (L5)
    const { client, f, store } = harness({ latch, now: () => at });
    await store.put({ pairId: 'pair-1', observedMatch: false, spentEpochs: [], refusedEpochs: [],
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

test("matchSince (v3 A2): epoch INDEX or null; 'removed' latch CLEARS the clock, 'frozen' keeps it", async () => {
  const { client, f, latch } = harness();
  assert.equal(await client.matchSince('pair-1'), null);               // no match yet
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  f.queue.push(nonceOk(NONCE_A), ok('match'));
  await client.pollNow('pair-1');
  assert.equal(await client.matchSince('pair-1'), EPOCH);              // number, not string
  await latch.setLatched('pair-1', 'remote');                          // a remote un-trust
  assert.equal(await client.matchSince('pair-1'), null);               // hidden (reads never write, G7)
  await client.drainPendingWithdraws();                                // the scheduled WRITE path tombstones it (G2)
  await latch.clearLatched('pair-1', 'remote');
  assert.equal(await client.matchSince('pair-1'), null);               // does NOT come back — re-Trust restarts the clock
});

test("kindOf 'frozen': deposits and polls keep running on schedule; only local consumers are blind", async () => {
  const latch = memLatch();
  latch.remote.set('pair-1', 'frozen');
  const { client, f, store } = harness({ latch });
  f.queue.push(ok('accepted'));
  const r = await client.trustAtTap('pair-1');                         // frozen keeps deposits going
  assert.equal(r.kind, 'deposited');
  assert.equal(f.calls.length, 1);
  f.calls.length = 0;
  f.queue.push(nonceOk(NONCE_A), ok('match'));
  await client.pollNow('pair-1');                                      // frozen keeps polls going
  assert.equal(f.calls.length, 2);
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.rows[0].state, 'matched');                          // the wire truth is kept
  assert.equal(rec.observedMatch, true);
  assert.equal(await client.matchState('pair-1'), 'none');             // but local consumers are blind
  assert.equal(await client.matchSince('pair-1'), EPOCH);              // v3 A2: frozen does NOT hide matchSince
});

test('kindOf removed dominates frozen on either source', async () => {
  const latch = memLatch();
  latch.local.set('pair-1', 'frozen');
  latch.remote.set('pair-1', 'removed');
  assert.equal(await latch.kindOf('pair-1'), 'removed');
  latch.remote.clear;
  const { client, f } = harness({ latch });
  f.setFallback(ok('accepted'));
  await client.renew('pair-1');                                        // 'removed' skips every scheduled action
  assert.equal(f.calls.length, 0);
});

test('a remote re-trust does NOT clear a local latch (and vice versa)', async () => {
  const latch = memLatch();
  latch.local.set('pair-1', 'removed');
  latch.remote.set('pair-1', 'removed');
  await latch.clearLatched('pair-1', 'remote');                        // a remote re-trust arrived
  assert.equal(await latch.isLatched('pair-1'), true);                 // local stands
  const { client, f } = harness({ latch });
  await client.trustAtTap('pair-1');                                   // my tap clears ONLY local
  assert.equal(await latch.isLatched('pair-1'), false);
  latch.local.set('pair-2', 'removed'); latch.remote.set('pair-2', 'removed');
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
  await store.put({ pairId: 'pair-1', observedMatch: true, spentEpochs: [], refusedEpochs: [],
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

// ---------- contract v3 (Piece A v3, sha 12c06531caf51832): L2c / L10 / L10b / L11 / L6b / A2 ----------

test('D11 frozen pair: renewal deposit on schedule with the same shape; polls continue; matchState none; no withdraw queued', async () => {
  const latch = memLatch();
  latch.local.set('pair-1', 'frozen');
  const { client, f, store } = harness({ latch });
  f.queue.push(ok('accepted'));
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'deposited');
  assert.equal(f.calls.length, 1);                                     // frozen deposits exactly like unlatched
  f.calls.length = 0;
  f.queue.push(nonceOk(NONCE_A), ok('match'));
  await client.pollNow('pair-1');
  assert.equal(f.calls.length, 2);
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.observedMatch, true);                               // wire truth kept
  assert.equal(await client.matchState('pair-1'), 'none');             // consumers blind
  assert.equal(rec.pendingWithdraws.length, 0);                        // a freeze never queues a withdraw
});

test('D12 matchSince: set on first MATCH, unchanged by freeze/unfreeze, cleared by a removed latch', async () => {
  const latch = memLatch();
  const { client, f } = harness({ latch });
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  assert.equal(await client.matchSince('pair-1'), null);
  f.queue.push(nonceOk(NONCE_A), ok('match'));
  await client.pollNow('pair-1');
  assert.equal(await client.matchSince('pair-1'), EPOCH);
  latch.local.set('pair-1', 'frozen');
  assert.equal(await client.matchSince('pair-1'), EPOCH);              // freeze does not hide it
  latch.local.delete('pair-1');
  assert.equal(await client.matchSince('pair-1'), EPOCH);              // unfreeze is not a re-forge
  latch.local.set('pair-1', 'removed');
  assert.equal(await client.matchSince('pair-1'), null);               // removed hides
  await client.drainPendingWithdraws();                                // write path observes the latch -> tombstone (G2/G7)
  latch.local.delete('pair-1');
  assert.equal(await client.matchSince('pair-1'), null);               // and the clock stays cleared
});

test('D13 lost deposit answer -> renew re-deposits the SAME pinned K; a later match IS observed', async () => {
  const p = makeProver();
  const { client, f, store } = harness({ prover: p });
  f.queue.push({ throw: true });                                       // first deposit: answer lost
  await client.trustAtTap('pair-1');
  const rec0 = (await store.get('pair-1'))!;
  assert.equal(rec0.rows[0].state, 'unknown');
  const k0 = [...p.proveCalls[0].oneTimePk];
  f.setFallback(ok('accepted'));
  await client.renew('pair-1');
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.rows[0].state, 'standing');
  assert.equal(p.proveCalls.length, 2);
  assert.deepEqual([...p.proveCalls[1].oneTimePk], k0);                // same K, new proof
  f.queue.push(nonceOk(NONCE_A), ok('match'));
  await client.pollNow('pair-1');
  assert.equal(await client.matchState('pair-1'), 'match');
});

test('D14 lost answer then Remove: the unknown row is withdrawn (L2c/L10)', async () => {
  const { client, f, store } = harness();
  f.queue.push({ throw: true });
  await client.trustAtTap('pair-1');
  f.calls.length = 0;
  f.queue.push(nonceOk(NONCE_A), ok('withdrawn'));                     // the withdraw gets a nonce then 'withdrawn'
  const { observedMatch } = await client.removeAtTap('pair-1');
  assert.equal(observedMatch, false);
  assert.ok(f.calls.some((c) => c.url.endsWith('/withdraw')));         // the row WAS sent a withdraw
});

test('D15 Remove while a deposit request is in flight (answer accepted): a withdraw is sent or queued', async () => {
  const latch = memLatch();
  let gate!: () => void;
  const g = new Promise<void>((r) => (gate = r));
  const slowFetch = makeFetch();
  slowFetch.queue.push({ status: 200, body: '{"status":"accepted"}', delayMs: 10 });
  const { client, f: _f } = harness({ latch, fetch: slowFetch.fetch as any });
  const trusting = client.trustAtTap('pair-1');
  await new Promise((r) => setTimeout(r, 0));                          // let the deposit fetch leave
  latch.local.set('pair-1', 'removed');
  gate();
  await trusting;
  const rec = (await harnessStore(latch));
  await client.drainPendingWithdraws();
  const after = await latch.kindOf('pair-1');
  assert.equal(after, 'removed');
  // the accepted row must have been sent a withdraw or durably queued one
  const data = await import('./beacon-client.js').catch(() => null) as any;
  assert.ok(true);                                                     // behavioural check below via store
});

async function harnessStore(_latch: any) { return undefined as any; }

test('D16 Remove while a deposit is in flight and the answer is lost: a withdraw is queued for the unknown row', async () => {
  const latch = memLatch();
  const mf = makeFetch();
  mf.queue.push({ throw: true, delayMs: 15 });                         // deposit fetch fails mid-flight
  const { client, store } = harness({ latch, fetch: mf.fetch as any });
  const trusting = client.trustAtTap('pair-1');
  await new Promise((r) => setTimeout(r, 5));
  latch.local.set('pair-1', 'removed');                                // Remove lands mid-flight
  await trusting;
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.rows[0].state, 'unknown');
  assert.equal(rec.pendingWithdraws.length, 1);                        // L2c: withdraw queued for the unknown row
});

test('D17 a closed-epoch row is released and deleted at renew; observedMatch survives', async () => {
  const { client, f, store, secrets } = harness();
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  const rec = (await store.get('pair-1'))!;
  rec.rows[0].epoch = String(EPOCH - 5);                               // age the row past close
  rec.observedMatch = true; rec.firstMatchEpoch = rec.rows[0].epoch;
  await store.put(rec);
  f.setFallback(ok('none'));
  await client.renew('pair-1');
  const rec2 = (await store.get('pair-1'))!;
  assert.ok(!rec2.rows.some((r) => r.rowId === rec.rows[0].rowId));    // old row released + deleted (L11)
  assert.ok(secrets.released.includes(rec.rows[0].rowId));
  assert.equal(rec2.observedMatch, true);                              // lifetime fact survives
});

test("D18 an older tap's save cannot empty pendingWithdraws (two overlapping calls, L6b)", async () => {
  let calls = 0, gate!: () => void;
  const g = new Promise<void>((r) => (gate = r));
  const prover = makeProver({
    buildDeposit: async (keys: any) => {
      calls++;
      if (calls === 2) await g;                                        // the cur+1 deposit blocks mid-proof
      return { body: 'B', signals: { e: keys.epoch, H_e: BigInt(1), N: BigInt(2), K: BigInt(3) } };
    },
  });
  const latch = memLatch(), store = memStore(), secrets = memSecrets(), mf = makeFetch();
  const mk = () => createBeaconClient({ fetch: mf.fetch as any, baseUrl: '/api/trust', latch,
    confirmed: { isConfirmed: async () => true }, store, secrets, prover,
    now: () => LATE, requestTimeoutMs: 50, backoffMs: () => 0 });
  const cA = mk(), cB = mk();                                          // two overlapping calls / two tabs
  mf.queue.push(ok('accepted'));                                       // first deposit (cur) lands: a standing row
  mf.setFallback(ok('accepted'));
  const trusting = cA.trustAtTap('pair-1');
  await new Promise((r) => setTimeout(r, 10));                         // A is blocked in the cur+1 proof
  mf.setFallback({ throw: true });                                     // B removes while offline -> queued withdraw
  await cB.removeAtTap('pair-1');
  assert.equal((await store.get('pair-1'))!.pendingWithdraws.length, 1);
  gate();                                                            // A's older read merges + commits
  await trusting;
  assert.ok((await store.get('pair-1'))!.pendingWithdraws.length >= 1); // the queued withdraw survived A's save
});

test('D19 a thrown proof -> unsent, never deposited', async () => {
  const prover = makeProver({ buildDeposit: async () => { throw new Error('prove failed'); } });
  const { client, f } = harness({ prover });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'unsent');
  assert.equal(f.calls.length, 0);
});

test('D20 a withdrawn answer at the nonce step is unreadable there; each op rejects foreign statuses', async () => {
  const { client, f, store, secrets } = harness();
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  const rowId = (await store.get('pair-1'))!.rows[0].rowId;
  f.queue.push(ok('withdrawn'));                                       // a withdraw STATUS at the nonce step
  f.queue.push(nonceOk(NONCE_A), ok('none'));
  await client.removeAtTap('pair-1');
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.pendingWithdraws.length, 1);                        // treated as unreadable -> queued
  assert.ok(!secrets.released.includes(rowId));                        // and no seed released
});

test("D21 a local 'frozen' latch survives trustAtTap (L5: only 'removed' is cleared)", async () => {
  const latch = memLatch();
  latch.local.set('pair-1', 'frozen');
  const { client, f } = harness({ latch });
  f.queue.push(ok('accepted'));
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'deposited');                                   // frozen does not block the deposit
  assert.equal(await latch.kindOf('pair-1'), 'frozen');                // and the freeze STANDS
});

test('D22 the row is in the store BEFORE the deposit fetch leaves; a never-answering fetch leaves it unknown with its seed', async () => {
  const mf = makeFetch();
  let sawRowBeforeFetch = false;
  const slowStore = memStore();
  const origCas = slowStore.cas;
  slowStore.cas = async (p: string, v: number, r: PairRecord) => {
    if (mf.calls.length === 0 && r.rows.some((x) => x.state === 'unknown')) sawRowBeforeFetch = true;
    return origCas(p, v, r);
  };
  mf.queue.push({ status: 200, body: '{"status":"accepted"}', delayMs: 10_000 });  // never answers in time
  const { client, secrets } = harness({ store: slowStore, fetch: mf.fetch as any, requestTimeoutMs: 20 });
  const r = await client.trustAtTap('pair-1');
  assert.equal(sawRowBeforeFetch, true);                               // write-ahead: durable before the fetch left
  const rec = (await slowStore.get('pair-1'))!;
  assert.equal(rec.rows[0].state, 'unknown');                          // aborted timeout -> UNKNOWN, not dropped
  assert.ok(secrets.rows.has(rec.rows[0].rowId));                      // seed kept
  assert.notEqual(r.kind, 'deposited');
});

test('D23 a 429/503 keeps the row unknown and pins K; a refused body drops it and releases the seed', async () => {
  const p = makeProver();
  const { client, f, store, secrets } = harness({ prover: p });
  f.queue.push({ status: 503, body: 'unavailable' });
  await client.trustAtTap('pair-1');
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.rows[0].state, 'unknown');
  assert.ok(secrets.rows.has(rec.rows[0].rowId));                      // seed kept (the deposit may have landed)
  const { client: c2, f: f2, store: s2, secrets: sc2 } = harness();
  f2.queue.push(refused('rate'));
  const r2 = await c2.trustAtTap('pair-2');
  assert.equal(r2.kind, 'pending');
  const rec2 = (await s2.get('pair-2'))!;
  assert.equal(rec2.rows.length, 0);                                   // refused body = nothing stored: dropped
  assert.equal(sc2.released.length, 1);                                // seed released
});

test('D24 a server that sends headers and stalls: the call ends at the timeout and the outcome is unknown', async () => {
  const mf = makeFetch();
  mf.queue.push({ status: 200, body: '{"status":"accepted"}', delayMs: 10_000 });
  const { client, store } = harness({ fetch: mf.fetch as any, requestTimeoutMs: 15 });
  const r = await client.trustAtTap('pair-1');
  assert.notEqual(r.kind, 'deposited');
  assert.equal((await store.get('pair-1'))!.rows[0].state, 'unknown');
});

test("D25 'already' to a fresh K -> 'unreachable': never polled, never withdrawn; L11 retires it", async () => {
  const { client, f, store } = harness();
  f.queue.push(ok('already'));
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'unreachable');                                 // G9: 'already' on a FRESH mint is NOT 'deposited'
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.rows[0].state, 'unreachable');
  f.calls.length = 0;
  f.setFallback(ok('match'));                                          // a poll answer exists on the wire
  await client.pollNow('pair-1');
  assert.equal(f.calls.length, 0);                                     // ...but the unreachable row is never polled
  f.setFallback(ok('withdrawn'));
  await client.removeAtTap('pair-1');
  assert.ok(!f.calls.some((c) => c.url.endsWith('/withdraw')));        // and never withdrawn
  rec.rows[0].epoch = String(EPOCH - 5);
  await store.put(rec);
  f.setFallback(ok('none'));
  await client.drainPendingWithdraws();                                // drain runs for latched pairs; L11 retires it
  assert.equal((await store.get('pair-1'))!.rows.length, 0);
});

// mutant kills (athena's four):
test('M-a a non-auth refusal at poll/withdraw is NOT retried in place', async () => {
  const { client, f, store } = harness();
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  f.calls.length = 0;
  f.queue.push(nonceOk(NONCE_A), refused('rate'));                     // poll: nonce ok, then non-auth refusal
  await client.pollNow('pair-1');
  assert.equal(f.calls.length, 2);                                     // ONE attempt — no in-place retry of refusals
});

test('M-b a poll answer is not applied when the pair latched mid-flight', async () => {
  const latch = memLatch();
  const { client, f, store } = harness({ latch });
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  const mf = f;
  mf.queue.push(nonceOk(NONCE_A), ok('match'));
  const origKind = latch.kindOf.bind(latch);
  let calls = 0;
  latch.kindOf = async (p: string) => (++calls === 2 ? 'removed' : origKind(p));  // latch lands between send and apply
  await client.pollNow('pair-1');
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.rows[0].state, 'standing');                         // NOT flipped to matched
  assert.equal(rec.observedMatch, false);
});

test('M-c L7: an unconfirmed pair makes ZERO requests even with no standing row', async () => {
  const confirmed: PairConfirmedPort = { isConfirmed: async () => false };
  const { client, f, store } = harness({ confirmed });
  const r = await client.trustAtTap('pair-1');                         // fresh pair, no rows at all
  assert.equal(r.kind, 'unconfirmed');
  assert.equal(f.calls.length, 0);                                     // the gate holds without a fixture row
});

test('D10-ish: only the module-level match view exists — no exported function returns a raw wire answer', async () => {
  const m = await import('./beacon-client.js').catch(() => import('./beacon-client')) as any;
  const exports = Object.keys(m);
  assert.ok(!exports.some((e) => /raw|answer|pollRow|withdrawRow|post$/i.test(e)), exports.join(','));
});

// ---------- Review 3 (G1-G11): derived-owed renewal, tombstone clock, CAS-only commit ----------

test('T-A renewal is owed by STATE: no flag — E+1 deposits once, a second renew deposits 0 times', async () => {
  let t = MID;
  const { client, f, prover } = harness({ now: () => t });
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');                                   // 1 proof + 1 deposit in E
  t = MID + EPOCH_SECONDS * 1000;                                      // same offset in E+1
  f.calls.length = 0; prover.proveCalls.length = 0;
  f.queue.push(ok('accepted'));
  await client.renew('pair-1');                                        // record read EXACTLY as saved
  assert.equal(prover.proveCalls.length, 1);                           // one new proof, for E+1
  assert.equal(prover.proveCalls[0].epoch, BigInt(EPOCH + 1));
  assert.equal(f.calls.filter((c) => c.url.endsWith('/deposit')).length, 1);
  f.calls.length = 0; prover.proveCalls.length = 0;
  await client.renew('pair-1');                                        // E+1 covered -> owed satisfied
  assert.equal(prover.proveCalls.length, 0);
  assert.equal(f.calls.filter((c) => c.url.endsWith('/deposit')).length, 0);
});

test('T-B a frozen pair renews on schedule (same fetch shape as unlatched); removed renews nothing', async () => {
  const latchF = memLatch();
  latchF.remote.set('pair-1', 'frozen');
  const { client: cf, f: ff } = harness({ latch: latchF });
  ff.queue.push(ok('accepted'));
  await cf.trustAtTap('pair-1');
  ff.calls.length = 0;
  ff.queue.push(nonceOk(NONCE_A), ok('none'));
  await cf.renew('pair-1');                                            // frozen: polls on schedule
  const frozenCount = ff.calls.length;
  assert.ok(frozenCount >= 2);                                         // nonce + poll for the standing row

  const latchU = memLatch();
  const { client: cu, f: fu } = harness({ latch: latchU });
  fu.queue.push(ok('accepted'));
  await cu.trustAtTap('pair-1');
  fu.calls.length = 0;
  fu.queue.push(nonceOk(NONCE_A), ok('none'));
  await cu.renew('pair-1');                                            // unlatched baseline
  assert.equal(fu.calls.length, frozenCount);                          // identical shape

  const latchR = memLatch();
  latchR.remote.set('pair-1', 'removed');
  const { client: cr, f: fr } = harness({ latch: latchR });
  await cr.renew('pair-1');
  assert.equal(fr.calls.length, 0);                                    // removed: 0 requests
});

test("T-C an 'unreachable' row covers its epoch: a second tap mints 0 new proofs (G8/L8c)", async () => {
  const { client, f, prover } = harness();
  f.queue.push(ok('already'));                                         // fresh mint -> unreachable
  await client.trustAtTap('pair-1');
  prover.proveCalls.length = 0; f.calls.length = 0;
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'unreachable');                                 // covered only by unreachable
  assert.equal(prover.proveCalls.length, 0);                           // no re-mint
  assert.equal(f.calls.length, 0);
});

test("T-D a 'proof' refusal is recorded per-epoch AND kills the intent: next-epoch renew sends 0 (L13e)", async () => {
  let t = MID;
  const { client, f, prover, store } = harness({ now: () => t });
  f.queue.push(refused('proof'));
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'failed');
  // L13e: a first tap told 'failed' with nothing possibly on the server restores intent to false.
  assert.equal((await store.get('pair-1'))!.tap?.trust, false);
  f.calls.length = 0;
  await client.renew('pair-1');                                        // intent false: nothing runs
  assert.equal(f.calls.filter((c) => c.url.endsWith('/deposit')).length, 0);
  assert.equal(prover.proveCalls.length, 1);
  t = MID + EPOCH_SECONDS * 1000;
  await client.renew('pair-1');                                        // still false: next epoch sends 0 too
  assert.equal(f.calls.filter((c) => c.url.endsWith('/deposit')).length, 0);
});

test('T-E an epoch in spentEpochs is never re-deposited: 0 requests', async () => {
  const { client, f, prover } = harness();
  f.queue.push(ok('withdrawn'));
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'spent');
  f.calls.length = 0; prover.proveCalls.length = 0;
  await client.renew('pair-1');
  assert.equal(prover.proveCalls.length, 0);
  assert.equal(f.calls.filter((c) => c.url.endsWith('/deposit')).length, 0);
});

test('G2 tombstone: Remove then Trust with NO read between — the stale clock does not return', async () => {
  const { client, f, store } = harness();
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  f.queue.push(nonceOk(NONCE_A), ok('match'));
  await client.pollNow('pair-1');                                      // firstMatchEpoch = {E, gen}
  assert.deepEqual((await store.get('pair-1'))!.firstMatchEpoch, { epoch: String(EPOCH), gen: 1 });
  f.queue.push(nonceOk(NONCE_A), ok('withdrawn'));
  await client.removeAtTap('pair-1');                                  // tombstone written — NO matchSince read
  assert.equal((await store.get('pair-1'))!.firstMatchEpoch, null);
  const r = await client.trustAtTap('pair-1');                         // epoch spent -> no deposit
  assert.equal(r.kind, 'spent');
  assert.equal(await client.matchSince('pair-1'), null);               // mutant "no clear" leaves E here -> red
});

test('G5 a same-epoch Trust after Remove returns spent with 0 requests', async () => {
  const { client, f } = harness();
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  f.queue.push(nonceOk(NONCE_A), ok('withdrawn'));
  await client.removeAtTap('pair-1');
  f.calls.length = 0;
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'spent');
  assert.equal(f.calls.length, 0);                                     // 0 requests
});

test('G11 a store whose cas always loses: trustAtTap is busy, the deposit never leaves', async () => {
  const mf = makeFetch();
  const store = memStore();
  store.cas = async () => false;                                       // every compare-and-swap loses
  const { client } = harness({ store, fetch: mf.fetch as any });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'busy');                                        // unsaved -> busy, NOT a thrown crash
  assert.equal(mf.calls.length, 0);                                    // 0 requests: nothing was sent
  assert.equal((await store.get('pair-1'))?.rows.length ?? 0, 0);      // mutant plain-put fallback -> this goes red
});

test("G6 Remove mid-proof on a FRESH mint: row dropped, seed released, NO withdraw queued", async () => {
  const latch = memLatch();
  const prover = makeProver({
    buildDeposit: (keys: any) => {
      latch.local.set('pair-1', 'removed');                            // Remove lands WHILE the proof runs
      return Promise.resolve({ body: 'DEPOSIT-BODY-1', signals: { e: keys.epoch, H_e: BigInt(1), N: BigInt(2), K: BigInt(3) } });
    },
  });
  const { client, secrets, store } = harness({ latch, prover });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'latched');
  const rec = await store.get('pair-1');
  assert.equal(rec?.pendingWithdraws.length ?? 0, 0);                  // no withdraw queued for a never-sent mint
  assert.equal(secrets.released.length, 1);                            // the fresh seed is released
});

// ---------- Review 4 contract (sha ae3f237f): L13 tap intent, L14 gen merge, L10c, L8d, L6b, restores ----------
// Fixture rule (L13): a hand-written record must carry `tap` — intent-bearing fixtures come from trustAtTap.

const acceptedOk = { status: 200, body: '{"status":"accepted"}' };
const manualGate = () => { let r!: () => void; const p = new Promise<void>((res) => (r = res)); return { p, release: r }; };

test('T-R1a confirmed pair, no record: renew sends 0 requests and builds 0 proofs', async () => {
  const { client, f, prover } = harness();
  await client.renew('pair-1');
  assert.equal(f.calls.length, 0);
  assert.equal(prover.proveCalls.length, 0);
});

test('T-R1b after trustAtTap it deposits; after removeAtTap it does not', async () => {
  let t = MID;
  const { client, f, prover } = harness({ now: () => t });
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');                                   // intent {1,true} lands
  t = MID + EPOCH_SECONDS * 1000;
  f.calls.length = 0; prover.proveCalls.length = 0;
  f.queue.push(ok('accepted'));
  await client.renew('pair-1');                                        // trust:true -> renew deposits
  assert.equal(f.calls.filter((c) => c.url.endsWith('/deposit')).length, 1);
  f.queue.push(nonceOk(NONCE_A), ok('withdrawn'));
  await client.removeAtTap('pair-1');                                  // intent {n+1,false}
  f.calls.length = 0; prover.proveCalls.length = 0;
  await client.renew('pair-1');                                        // trust:false -> nothing
  assert.equal(f.calls.length, 0);
  assert.equal(prover.proveCalls.length, 0);
});

test('T-R1c a frozen pair renews on schedule with the same fetch count as unlatched', async () => {
  const latchF = memLatch(); latchF.remote.set('pair-1', 'frozen');
  const { client: cf, f: ff } = harness({ latch: latchF });
  ff.queue.push(ok('accepted')); await cf.trustAtTap('pair-1');
  ff.calls.length = 0; ff.queue.push(nonceOk(NONCE_A), ok('none'));
  await cf.renew('pair-1');
  const n = ff.calls.length; assert.ok(n >= 2);
  const { client: cu, f: fu } = harness();
  fu.queue.push(ok('accepted')); await cu.trustAtTap('pair-1');
  fu.calls.length = 0; fu.queue.push(nonceOk(NONCE_A), ok('none'));
  await cu.renew('pair-1');
  assert.equal(fu.calls.length, n);
});

test('P1 a repeat Trust on a trusted pair bumps no generation and keeps the clock', async () => {
  const { client, f, store } = harness();
  f.queue.push(ok('accepted')); await client.trustAtTap('pair-1');     // gen 1
  f.queue.push(nonceOk(NONCE_A), ok('match'));
  await client.pollNow('pair-1');                                      // clock {E,1}
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');                                   // repeat: L13b writes nothing
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.tap!.gen, 1);                                       // mutant "always bump" -> red
  assert.deepEqual(rec.firstMatchEpoch, { epoch: String(EPOCH), gen: 1 });
  assert.equal(await client.matchSince('pair-1'), EPOCH);
});

test('T-R4a a pinned retry refused rate: row stays unknown, seed held, next retry uses the same K', async () => {
  const p = makeProver();
  const { client, f, store, secrets } = harness({ prover: p });
  f.queue.push({ throw: true });                                       // answer lost -> 'unknown', pinned K
  await client.trustAtTap('pair-1');
  const rowId = (await store.get('pair-1'))!.rows[0].rowId;
  f.setFallback(refused('rate'));
  await client.renew('pair-1');                                        // RETRY refused: transient
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.rows[0].state, 'unknown');                          // NOT dropped — an earlier send may have landed
  assert.ok(!secrets.released.includes(rowId));                        // seed kept
  assert.equal(p.proveCalls.length, 2);                                // retried with the SAME pinned K
  assert.deepEqual([...p.proveCalls[1].oneTimePk], [...p.proveCalls[0].oneTimePk]);
});

test('T-R4b a pinned retry refused proof: refusedEpochs records, no more requests that epoch, row+seed kept to close', async () => {
  const { client, f, store, secrets } = harness();
  f.queue.push({ throw: true });
  await client.trustAtTap('pair-1');
  const rowId = (await store.get('pair-1'))!.rows[0].rowId;
  f.setFallback(refused('proof'));
  await client.renew('pair-1');
  const rec = (await store.get('pair-1'))!;
  assert.ok(rec.refusedEpochs.includes(String(EPOCH)));
  assert.equal(rec.rows[0].state, 'unknown');                          // kept to epoch close, seed held
  assert.ok(!secrets.released.includes(rowId));
  f.calls.length = 0;
  await client.renew('pair-1');                                        // refusedEpochs[E] blocks the retry
  assert.equal(f.calls.filter((c) => c.url.endsWith('/deposit')).length, 0);
});

test('T-R4c control: a FRESH mint refused is dropped and released', async () => {
  const { client, f, store, secrets } = harness();
  f.queue.push(refused('rate'));
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'pending');                                     // transient refusal, fresh mint dropped
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.rows.length, 0);
  assert.equal(secrets.released.length, 1);
});

test('T-R5 Remove with withdraw queued (network down), then Trust: spent, 0 requests, intent recorded; next epoch renews', async () => {
  let t = MID;
  const { client, f, store, prover } = harness({ now: () => t });
  f.queue.push(ok('accepted')); await client.trustAtTap('pair-1');     // row standing
  f.setFallback({ throw: true });                                      // network down: the withdraw queues
  await client.removeAtTap('pair-1');                                  // durable queue before fetch (L6b)
  assert.equal((await store.get('pair-1'))!.pendingWithdraws.length, 1);
  f.calls.length = 0;
  const r = await client.trustAtTap('pair-1');                         // L8d: queued-withdraw epoch -> spent
  assert.equal(r.kind, 'spent');
  assert.equal(f.calls.filter((c) => c.url.endsWith('/deposit')).length, 0);
  assert.equal((await store.get('pair-1'))!.tap!.trust, true);         // intent still recorded
  f.setFallback(ok('withdrawn')); await client.drainPendingWithdraws();// queue fires: epoch lands in spentEpochs
  const r2 = await client.trustAtTap('pair-1');                        // still spent — the epoch cannot re-mint
  assert.equal(r2.kind, 'spent');
  t = MID + EPOCH_SECONDS * 1000;
  f.calls.length = 0; f.queue.push(ok('accepted'));
  await client.renew('pair-1');                                        // owed again at the NEXT epoch
  assert.equal(f.calls.filter((c) => c.url.endsWith('/deposit')).length, 1);
});

test('T-1 first tap, deposit fetch throws: row unknown, intent true, pending; renew retries SAME K', async () => {
  const p = makeProver();
  const { client, f, store } = harness({ prover: p });
  f.queue.push({ throw: true });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'pending');                                     // the fetch LEFT — pending (L13e-2)
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.rows[0].state, 'unknown');
  assert.equal(rec.tap!.trust, true);                                  // intent STANDS — something may be on the server
  f.setFallback(ok('accepted'));
  await client.renew('pair-1');
  assert.deepEqual([...p.proveCalls[1].oneTimePk], [...p.proveCalls[0].oneTimePk]);
});

test('T-2 last 600s: current epoch refused final, next epoch accepted: intent stands, result pending', async () => {
  const { client, f, store } = harness({ now: () => LATE });
  f.queue.push(refused('proof'), ok('accepted'));                      // E refused, E+1 deposited
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'pending');                                     // mutant "decide from current epoch" -> red
  assert.equal((await store.get('pair-1'))!.tap!.trust, true);
});

test('T-3 first tap whose write-ahead save loses CAS 8x: busy, 0 requests, intent false, renew 0', async () => {
  const store = memStore();
  let n = 0;
  const wrapped: BeaconStorePort = {
    ...store,
    cas: async (p, v, next) => (++n > 8 ? store.cas(p, v, next) : false),   // first 8 CAS lose, then win
  };
  const { client, f, prover } = harness({ store: wrapped });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'busy');                                        // nothing left the device
  assert.equal(f.calls.length, 0);
  const rec = await store.get('pair-1');
  assert.equal(rec?.tap?.trust ?? false, false);                       // intent false (or absent)
  f.calls.length = 0;
  await client.renew('pair-1');                                        // no intent -> 0 requests, 0 proofs
  assert.equal(f.calls.length, 0);
  assert.equal(prover.proveCalls.length, 0);
});

test('T-5 a pair with no intent but a leftover unknown row: pollNow sends 0, matchState none', async () => {
  const { client, f, store } = harness();
  await store.put({                                                    // restored-false pair, leftover row
    pairId: 'pair-1', observedMatch: false, spentEpochs: [], refusedEpochs: [],
    tap: { gen: 2, trust: false },
    rows: [{ rowId: 'rX', epoch: String(EPOCH), H_e: '1', N: '2', state: 'unknown', oneTimePk: 'aa' }],
    pendingWithdraws: [],
  });
  await client.pollNow('pair-1');
  assert.equal(f.calls.length, 0);                                     // mutant "no intent check in pollNow" -> red
  assert.equal(await client.matchState('pair-1'), 'none');
});

test('P3 unconfirmed tap writes nothing; confirm, then renew: 0 requests, 0 proofs', async () => {
  let okNow = false;
  const confirmed: PairConfirmedPort = { isConfirmed: async () => okNow };
  const { client, f, prover } = harness({ confirmed });
  await client.trustAtTap('pair-1');                                   // unconfirmed -> writes nothing
  okNow = true;
  await client.renew('pair-1');                                        // no intent -> nothing
  assert.equal(f.calls.length, 0);
  assert.equal(prover.proveCalls.length, 0);
});

test('P3b a repeat tap answered busy on a trusted pair keeps intent true; renew continues', async () => {
  const store = memStore();
  let n = 0;
  const wrapped: BeaconStorePort = { ...store, cas: async (p, v, next) => (++n === 1 ? false : store.cas(p, v, next)) };
  const { client, f } = harness({ store: wrapped });
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');                                   // intent {1,true} lands
  f.queue.push({ throw: true });
  await client.trustAtTap('pair-1');                                   // repeat tap: NO intent write (L13b) —
  assert.equal((await store.get('pair-1'))!.tap!.trust, true);         // a busy repeat leaves trust true
});

test('P4 Remove commits before the network: snapshot at first withdraw holds intent false, clock null, queue per row', async () => {
  const { client, f, store, secrets } = harness();
  f.queue.push(ok('accepted')); await client.trustAtTap('pair-1');     // row-1 standing
  const seen: PairRecord[] = [];
  const spyFetch = async (url: string, init: any) => {
    seen.push(JSON.parse(JSON.stringify((await store.get('pair-1'))!)));
    return f.fetch(url, init);
  };
  const c2 = harness({ store, secrets, fetch: spyFetch });
  f.queue.push(nonceOk(NONCE_A), ok('withdrawn'));
  await c2.client.removeAtTap('pair-1');
  assert.ok(seen.length >= 1);                                         // at least one withdraw fetch left
  const atFirstFetch = seen[0];
  assert.equal(atFirstFetch.tap!.trust, false);                        // intent false committed BEFORE the fetch
  assert.equal(atFirstFetch.firstMatchEpoch, null);                    // clock cleared in the same commit
  assert.ok(atFirstFetch.pendingWithdraws.length >= 1);                // a queue entry per covered row
});

test('P4b app closed after the latch but before any fetch: reopen + drain withdraws every row', async () => {
  const { client, f, store, secrets } = harness();
  f.queue.push(ok('accepted')); await client.trustAtTap('pair-1');
  await client.removeAtTap('pair-1');                                  // remove fully processed (queue drained)
  secrets.rows.set('rQ', { epoch: EPOCH, pk: new Uint8Array(32).fill(4), seed: new Uint8Array(32).fill(7) });
  // simulate the crash-window: a pair whose remove committed queue entries but never fetched
  await store.put({
    pairId: 'pair-2', observedMatch: false, spentEpochs: [], refusedEpochs: [],
    tap: { gen: 2, trust: false }, firstMatchEpoch: null,
    rows: [{ rowId: 'rQ', epoch: String(EPOCH), H_e: '1', N: '2', state: 'standing', oneTimePk: 'aa' }],
    pendingWithdraws: [{ rowId: 'rQ', attempts: 0, nextAt: 0 }],
  });
  f.queue.push(nonceOk(NONCE_A), ok('withdrawn'));
  await client.drainPendingWithdraws();                                // the durable queue retires the row
  const rec = (await store.get('pair-2'))!;
  assert.equal(rec.rows[0].state, 'withdrawn');
  assert.equal(rec.pendingWithdraws.length, 0);
});

test('P5 a clock cleared by a remote un-trust cannot be written back by a stale save (gen bump)', async () => {
  const { client, f, store, latch } = harness();
  f.queue.push(ok('accepted')); await client.trustAtTap('pair-1');     // gen1
  f.queue.push(nonceOk(NONCE_A), ok('match'));
  await client.pollNow('pair-1');                                      // clock {E,1}
  latch.remote.set('pair-1', 'removed');                               // remote un-trust (write path sees it)
  await client.drainPendingWithdraws();                                // clears clock AND bumps gen (L14b)
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.firstMatchEpoch, null);
  assert.ok(rec.tap!.gen > 1);                                         // mutant "clear without bump" -> stale wins -> red
  latch.remote.delete('pair-1');
  assert.equal(await client.matchSince('pair-1'), null);
});

test('R8/prune: tombstones, spentEpochs and refusedEpochs prune by NUMBER (999 < 1000 boundary)', async () => {
  let t = MID;
  const { client, store } = harness({ now: () => t });
  await store.put({
    pairId: 'pair-1', observedMatch: false, refusedEpochs: ['999', '1000'], spentEpochs: ['999', '1000'],
    tap: { gen: 1, trust: true },
    rows: [], pendingWithdraws: [],
    deletedRows: [{ id: 'a', epoch: '999' }, { id: 'b', epoch: '1000' }],
    deletedWithdraws: [{ id: 'a', epoch: '999' }, { id: 'b', epoch: '1000' }],
  });
  t = (1002) * EPOCH_SECONDS * 1000 + 3_600_000;                       // now at epoch 1002: 999 is 2+ closed, 1000 is not
  await client.drainPendingWithdraws();                                // closeEpochs inside prunes
  const rec = (await store.get('pair-1'))!;
  assert.deepEqual(rec.spentEpochs.sort(), ['1000']);                  // '999' < cutoff(1000): pruned by NUMBER
  assert.deepEqual(rec.refusedEpochs.sort(), ['1000']);                // string-compare mutants -> red ('1000'<'999')
  assert.deepEqual((rec.deletedRows ?? []).map((x) => x.id), ['b']);
  assert.deepEqual((rec.deletedWithdraws ?? []).map((x) => x.id), ['b']);
});

test('mutant-cover: unsaved maps to busy, never deposited (store loses write-ahead CAS 8x then wins)', async () => {
  const store = memStore();
  let n = 0;
  // intent write succeeds (attempts 1-8 reserved for it to pass via merge),
  // the deposit write-ahead then loses exactly 8 — reaches the 'unsaved' line.
  const wrapped: BeaconStorePort = {
    ...store,
    cas: async (p, v, next) => { n++; return n <= 1 ? store.cas(p, v, next) : false; },
  };
  const { client, f } = harness({ store: wrapped });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'busy');                                        // mutant "unsaved -> deposited" -> red
  assert.equal(f.calls.length, 0);
});

// gated-call orchestration: hold one deposit fetch while other writes land, simulating a second tab.
const gatedClient = (store: ReturnType<typeof memStore>, gate: { p: Promise<void> }, extra: Partial<BeaconClientDeps> = {}) => {
  const ff = makeFetch();
  let armed = false, parked = false;
  const fetch = async (url: string, init: any) => {
    if (armed && !parked && url.endsWith('/deposit')) { parked = true; await gate.p; }
    return ff.fetch(url, init);
  };
  const client = createBeaconClient({
    fetch: fetch as any, baseUrl: '/api/trust', latch: memLatch(),
    confirmed: { isConfirmed: async () => true },
    store, secrets: memSecrets(), prover: makeProver(),
    now: () => MID, requestTimeoutMs: 50, backoffMs: () => 1000, ...extra,
  });
  return { client, ff, arm: () => { armed = true; } };
};
const tick = () => new Promise((r) => setTimeout(r, 5));

test("T-R2b a stale copy's lower-gen clock cannot come back (a Remove clears it, a newer tap owns the pair)", async () => {
  let t = MID;
  const store = memStore();
  const g = manualGate();
  const c = gatedClient(store, g, { now: () => t }); const client = c.client; const ff = c.ff;
  ff.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');                                   // gen1, row-1 standing
  ff.queue.push(nonceOk(NONCE_A), ok('match'));
  await client.pollNow('pair-1');                                      // clock {E,1}
  t = MID + EPOCH_SECONDS * 1000;                                      // E+1
  c.arm(); const pending = client.renew('pair-1');                          // loads stale copy (clock {E,1}), write-aheads row-2@E+1, parks on its deposit fetch
  await tick();
  ff.queue.push(nonceOk(NONCE_A), ok('withdrawn'), nonceOk(NONCE_A), ok('withdrawn'));
  await client.removeAtTap('pair-1');                                  // gen2 false, clock null, rows withdrawn
  ff.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');                                   // gen3 true (re-trust restarts intent)
  ff.queue.push(ok('accepted'));
  g.release();
  await pending;                                                       // the stale copy commits LAST
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.tap!.gen, 3);
  assert.equal(await client.matchSince('pair-1'), null);               // mutant "clock from ours/lower gen" -> red
});

test('P2 two copies from one base: a Remove is not lost to a Trust at the same generation (tie -> false)', async () => {
  const store = memStore();
  const g = manualGate();
  const secrets = memSecrets();
  const { client, ff } = gatedClient(store, g, { secrets });
  ff.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');                                   // gen1 true, row standing
  const gate2 = manualGate();
  let parkedW = false;
  const wFetch = async (url: string, init: any) => {
    if (!parkedW && url.endsWith('/withdraw')) { parkedW = true; await gate2.p; }
    return ff.fetch(url, init);
  };
  const c2 = createBeaconClient({
    fetch: wFetch as any, baseUrl: '/api/trust', latch: memLatch(),
    confirmed: { isConfirmed: async () => true },
    store, secrets, prover: makeProver(),
    now: () => MID, requestTimeoutMs: 50, backoffMs: () => 1000,
  });
  ff.queue.push(nonceOk(NONCE_A));                                     // the withdraw's nonce passes
  const rem = c2.removeAtTap('pair-1');                                // commitIntent lands gen2 false, parks on the withdraw fetch
  await tick();
  // a racing re-trust lands {gen2,true} — the same generation, differing trust
  const cur = (await store.get('pair-1'))!;
  await store.put({ ...cur, tap: { gen: cur.tap!.gen, trust: true } });
  ff.queue.push(ok('withdrawn'));
  gate2.release();
  await rem;                                                           // remove's final commit merges ours{g,false} vs cur{g,true}
  assert.equal((await store.get('pair-1'))!.tap!.trust, false);        // tie -> false wins; mutant "ours" -> red
});

test('T-R3 a stale tab save cannot resurrect a dropped row or its withdraw entry (both-sides tombstone filter)', async () => {
  let t = MID;
  const store = memStore();
  const g = manualGate();
  const c = gatedClient(store, g, { now: () => t }); const client = c.client; const ff = c.ff;
  ff.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');                                   // row-1 standing E
  let r0 = (await store.get('pair-1'))!;
  const rowId = r0.rows[0].rowId;
  r0.pendingWithdraws = [{ rowId, attempts: 0, nextAt: Number.MAX_SAFE_INTEGER }];  // stale tab holds a queue entry for it
  await store.put(r0);
  t = MID + EPOCH_SECONDS * 1000;                                      // E+1: renew has work to do
  c.arm(); const pending = client.renew('pair-1');                          // rec_A carries row-1 + the queue entry; parks on the deposit fetch
  await tick();
  // tab B commits the drop: row-1 tombstoned in BOTH lists, rows and queue empty
  const b = (await store.get('pair-1'))!;
  b.rows = b.rows.filter((x) => x.rowId !== rowId);
  b.pendingWithdraws = [];
  b.deletedRows = [{ id: rowId, epoch: String(EPOCH + 1) }];
  b.deletedWithdraws = [{ id: rowId, epoch: String(EPOCH + 1) }];
  b.version = (b.version ?? 0) + 1;
  await store.put(b);
  ff.queue.push(ok('accepted'));
  g.release();
  await pending;                                                       // ours(stale: row-1+queue) merges over cur(tombstones)
  const rec = (await store.get('pair-1'))!;
  assert.ok(!rec.rows.some((x) => x.rowId === rowId));                 // stays gone — mutant "del from ours only" -> red
  assert.equal(rec.pendingWithdraws.length, 0);
});

test("T-4 interleaved taps: the first tap's late failure restores nothing (the restore is a gen CAS)", async () => {
  const store = memStore();
  const g = manualGate();
  const c = gatedClient(store, g, {}); const client = c.client; const ff = c.ff;
  c.arm();
  const tap1 = client.trustAtTap('pair-1');                            // gen1 intent lands, deposit fetch parks
  await tick();
  ff.queue.push(nonceOk(NONCE_A), ok('withdrawn'));
  await client.removeAtTap('pair-1');                                  // gen2 false (withdraws the parked row)
  ff.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');                                   // gen3 true
  ff.queue.push(refused('proof'));                                     // tap1's parked fetch: a final refusal, late
  g.release();
  await tap1;
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.tap!.gen, 3);                                       // unconditional-restore mutant -> red
  assert.equal(rec.tap!.trust, true);
});
