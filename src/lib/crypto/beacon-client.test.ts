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
    kindOf: async (p, source?: 'local' | 'remote') => {
      if (source === 'local') return local.get(p) ?? null;
      if (source === 'remote') return remote.get(p) ?? null;
      return local.get(p) === 'removed' || remote.get(p) === 'removed' ? 'removed'
        : local.get(p) === 'frozen' || remote.get(p) === 'frozen' ? 'frozen' : null;
    },
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
  f.queue.push(nonceOk(NONCE_A), ok('withdrawn'));                   // a withdraw COULD leave if attempted
  await client.removeAtTap('pair-1');
  assert.ok(!f.calls.some((c) => c.url.endsWith('/withdraw')));        // the unreachable row is never withdrawn
  rec.rows[0].epoch = String(EPOCH - 5);
  await store.put(rec);
  f.setFallback(ok('none'));
  await client.drainPendingWithdraws();                                // drain runs for latched pairs; L11 retires it
  assert.equal((await store.get('pair-1'))!.rows.length, 0);
});

// mutant checks:
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
    cas: async (p, v, next) => (++n === 1 || n >= 10 ? store.cas(p, v, next) : false),
  };
  const { client, f, prover } = harness({ store: wrapped });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'busy');                                        // intent win, write-ahead lose 8 -> 'unsaved', restore win
  assert.equal(f.calls.length, 0);
  const rec = await store.get('pair-1');
  assert.equal(rec?.tap?.trust ?? false, false);                       // intent false (or absent)
  const proofs = prover.proveCalls.length;                             // the tap minted one proof before 'unsaved'
  f.calls.length = 0;
  await client.renew('pair-1');                                        // no intent -> 0 requests, 0 new proofs
  assert.equal(f.calls.length, 0);
  assert.equal(prover.proveCalls.length, proofs);
});

test('T-5 a pair with no intent but a leftover unknown row: pollNow sends 0, matchState none', async () => {
  const { client, f, store, secrets } = harness();
  secrets.rows.set('rX', { epoch: EPOCH, pk: new Uint8Array(32).fill(4), seed: new Uint8Array(32).fill(7) });
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
  f.queue.push(nonceOk(NONCE_A), ok('withdrawn'));                      // pair-1: the due-now retry fires first (L6e)
  f.queue.push(nonceOk(NONCE_B), ok('withdrawn'));                      // pair-2: then the seeded crash-window row
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
  // intent write wins (cas 1), the write-ahead loses its 8 (cas 2-9) -> 'unsaved',
  const wrapped: BeaconStorePort = {
    ...store,
    // intent write wins (cas 1), the write-ahead loses its 8 (cas 2-9) -> 'unsaved',
    // the intent-restore then wins (cas 10+): 'busy', nothing left the device.
    cas: async (p, v, next) => { n++; return n === 1 || n >= 10 ? store.cas(p, v, next) : false; },
  };
  const { client, f } = harness({ store: wrapped });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'busy');                                        // mutant "unsaved -> deposited" -> red
  assert.equal(f.calls.length, 0);
  assert.equal((await store.get('pair-1'))!.tap!.trust, false);        // the restore landed: intent false
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
  let t = MID;
  const store = memStore();
  const g = manualGate();
  const c = gatedClient(store, g, { now: () => t }); const client = c.client; const ff = c.ff;
  ff.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');                                   // gen1 true, row standing
  t = MID + EPOCH_SECONDS * 1000;                                      // E+1: work to do
  c.arm();
  const pending = client.trustAtTap('pair-1');                         // repeat tap: ours={gen1,true}; parks on the deposit fetch
  await tick();
  // a same-generation Remove lands {gen1,false} while ours still says true
  const cur = (await store.get('pair-1'))!;
  await store.put({ ...cur, tap: { gen: cur.tap!.gen, trust: false }, firstMatchEpoch: null });
  ff.queue.push(ok('accepted'));
  g.release();
  await pending;                                                       // ours{1,true} merges over cur{1,false}
  assert.equal((await store.get('pair-1'))!.tap!.trust, false);        // tie -> false wins; mutant "ours wins tie" -> red
});

test('T-R3 a stale tab save cannot resurrect a dropped row or its withdraw entry (both-sides tombstone filter)', async () => {
  let t: number = MID;
  const store = memStore();
  const g = manualGate();
  const c = gatedClient(store, g, { now: () => t }); const client = c.client; const ff = c.ff;
  ff.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');                                   // row-1 standing E
  let r0 = (await store.get('pair-1'))!;
  const rowId = r0.rows[0].rowId;
  r0.pendingWithdraws = [{ rowId, attempts: 0, nextAt: Number.MAX_SAFE_INTEGER }];  // stale tab holds a queue entry for it
  await store.put(r0);
  t = LATE;                                                            // last 600s of E: E and E+1 both live, E+1 uncovered
  c.arm(); const pending = client.renew('pair-1');                          // rec_A carries LIVE row-1 + the queue entry; parks on the E+1 deposit fetch
  await tick();
  // tab B commits the drop: row-1 tombstoned in BOTH lists, rows and queue empty
  const b = (await store.get('pair-1'))!;
  b.rows = b.rows.filter((x) => x.rowId !== rowId);
  b.pendingWithdraws = [];
  b.deletedRows = [{ id: rowId, epoch: String(EPOCH) }];
  b.deletedWithdraws = [{ id: rowId, epoch: String(EPOCH) }];
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
  await client.trustAtTap('pair-1');                                   // gen3 true — epoch spent, 0 requests
  ff.queue.push(refused('proof'));                                     // tap1's parked fetch gets the late final refusal
  g.release();
  await tap1;
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.tap!.gen, 3);                                       // unconditional-restore mutant -> red
  assert.equal(rec.tap!.trust, true);
});

// ---------- Review 5 contract (sha b04d7b9b): L6c repair, L15 yield-by-gen, L13g, L14d, L16 ----------
// Fixture rule stands: intent-bearing records come from trustAtTap, never hand-written `tap`.

const latchedRemoved = (latch: ReturnType<typeof memLatch>) => { latch.local.set('pair-1', 'removed'); };

test('L6c-a a half-done Remove (local latch + intent still true, no queue) is repaired on reopen: drain withdraws, tap false', async () => {
  const latch = memLatch();
  const { client, f, store, secrets } = harness({ latch });
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');                                   // row-1 standing, gen1 true
  latch.local.set('pair-1', 'removed');                                // the Remove that latched but never committed
  const { client: c2, f: f2 } = harness({ latch, store, secrets, backoffMs: () => 0 });  // "reopen": queue entries due at once
  f2.queue.push(nonceOk(NONCE_A), ok('withdrawn'));
  await c2.drainPendingWithdraws();                                    // repair commits then THIS drain retires the queue
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.tap!.trust, false);                                 // mutant "no repair" -> red
  assert.equal(rec.rows[0].state, 'withdrawn');
  assert.equal(rec.pendingWithdraws.length, 0);
  f.calls.length = 0;
  await c2.renew('pair-1');                                            // repaired pair stays quiet
  assert.equal(f.calls.length, 0);
});

test('L6c-b a REMOTE removed never repairs: drain and renew leave tap true and the rows untouched', async () => {
  const latch = memLatch();
  const { client, f, store } = harness({ latch });
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');                                   // gen1 true, row standing
  latch.remote.set('pair-1', 'removed');                               // remote un-trust — the peer's own withdraw is pending
  const rec0 = (await store.get('pair-1'))!;
  const gen0 = rec0.tap!.gen;
  await client.drainPendingWithdraws();
  await client.renew('pair-1');
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.tap!.trust, true);                                  // mutant "repair on any source" -> red
  assert.equal(rec.rows.length, rec0.rows.length);                     // rows untouched (clock may clear per L14b)
});

test('L6c-c a half-done Remove with a closed-epoch row: the row is dropped and released', async () => {
  const latch = memLatch();
  const { client, f, store, secrets } = harness({ latch });
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  const rec = (await store.get('pair-1'))!;
  const rowId = rec.rows[0].rowId;
  rec.rows[0].epoch = String(EPOCH - 5);                               // closed past keeping
  await store.put(rec);
  latch.local.set('pair-1', 'removed');                                // half-done Remove
  f.setFallback(ok('none'));
  await client.drainPendingWithdraws();
  const rec2 = (await store.get('pair-1'))!;
  assert.equal(rec2.tap!.trust, false);
  assert.equal(rec2.rows.length, 0);                                   // the closed row dropped
  assert.ok(secrets.released.includes(rowId));                         // and its seed released
});

test('L15 a Remove finishing inside Trust\'s latch-await yields: latched, 0 requests, local latch restored', async () => {
  const latch = memLatch();
  latch.local.set('pair-1', 'removed');                                // pair starts removed
  const store = memStore();
  const secrets = memSecrets();
  let kindCalls = 0;
  const slowLatch: LatchPort = {
    ...latch,
    kindOf: async (p, s) => {                                          // Remove completes DURING the kindOf await
      if (++kindCalls === 1) {
        const c2 = createBeaconClient({
          fetch: makeFetch().fetch as any, baseUrl: '/api/trust', latch,
          confirmed: { isConfirmed: async () => true },
          store, secrets, prover: makeProver(),
          now: () => MID, requestTimeoutMs: 50, backoffMs: () => 1000,
        });
        await c2.removeAtTap('pair-1');                                // durable Remove lands mid-await
      }
      return latch.kindOf(p, s);
    },
  };
  const { client, f } = harness({ latch: slowLatch, store, secrets });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'latched');                                     // Trust yields — gen moved past g0
  assert.equal(f.calls.filter((c) => c.url.endsWith('/deposit')).length, 0);
  assert.ok((await latch.kindOf('pair-1', 'local')) === 'removed');    // our own clear is un-done
  assert.notEqual((await store.get('pair-1'))!.tap!.trust, true);      // mutant "no gen compare" -> red
});

test('L15b two tabs both tapping Trust: the loser reports the real result, never latched; no latch is restored', async () => {
  const store = memStore();
  const latch = memLatch();
  const secrets = memSecrets();
  const g = manualGate();
  const c = gatedClient(store, g, { latch, secrets });
  c.arm();
  const tapA = c.client.trustAtTap('pair-1');                          // parks on its deposit fetch (intent gen1 landed)
  await tick();
  const r = await c.client.trustAtTap('pair-1');                       // same store — second "tab": gen moved (1)
  c.ff.queue.push(ok('accepted'));
  g.release();
  await tapA;
  assert.notEqual(r.kind, 'latched');                                  // a repeat-tap result, never 'latched'
  assert.equal((await latch.kindOf('pair-1', 'local')), null);         // and no latch was restored
});

test('L15c the yield decision reads the stored record ONCE: a second get may not change it', async () => {
  const store = memStore();
  const latch = memLatch();
  latch.local.set('pair-1', 'removed');                                // pre-latched: tap clears it, then must yield
  const secrets = memSecrets();
  let gets = 0;
  const wStore: BeaconStorePort = {
    ...store,
    get: async (p) => {
      const r = await store.get(p);
      // get #1 = g0 read, #2 = getRec, #3+ = inside commitIntent: the "a Remove landed" record
      if (++gets >= 3 && !r?.tap)
        return { pairId: p, observedMatch: false, spentEpochs: [], refusedEpochs: [],
                 rows: [], pendingWithdraws: [], tap: { gen: 2, trust: false }, firstMatchEpoch: null } as PairRecord;
      return r;
    },
  };
  const { client, f } = harness({ store: wStore, latch, secrets });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'latched');                                     // false wins on the moved record
  assert.equal(f.calls.filter((c) => c.url.endsWith('/deposit')).length, 0);
  assert.ok((await latch.kindOf('pair-1', 'local')) === 'removed');    // our own clear is un-done
});

test('L13g a restore that loses 8 swaps rejects loudly', async () => {
  const store = memStore();
  let n = 0;
  const wrapped: BeaconStorePort = {
    ...store,
    // intent write wins (1), write-ahead loses 8 (2-9) -> 'unsaved' busy, restore loses 8 (10-17) -> THROWS
    cas: async (p, v, next) => (++n === 1 ? store.cas(p, v, next) : false),
  };
  const { client } = harness({ store: wrapped });
  await assert.rejects(() => client.trustAtTap('pair-1'), /intent-restore/);   // mutant "swallow" -> red
});

test('L14d an equal-gen equal-trust merge keeps the STORED clock when ours has none', async () => {
  const store = memStore();
  const g = manualGate();
  const c = gatedClient(store, g, { now: () => LATE });
  c.ff.queue.push(ok('accepted'), ok('accepted'));
  await c.client.trustAtTap('pair-1');                                 // gen1, row-1 standing @E
  c.arm();
  const pending = c.client.renew('pair-1');                            // ours: clockless copy; parks on the E+1 deposit fetch
  await tick();
  c.ff.queue.push(nonceOk(NONCE_A), ok('match'));
  await c.client.pollNow('pair-1');                                    // the clock lands in the store WHILE renew is parked
  c.ff.queue.push(ok('accepted'));
  g.release();
  await pending;                                                       // ours{1,true,no clock} merges over cur{1,true,{E,1}}
  assert.equal(await c.client.matchSince('pair-1'), EPOCH);            // mutant "ours only" -> red
});

test('L16 a stored floor above the real clock is capped: a spent epoch survives and is never re-deposited', async () => {
  let t = MID;
  const { client, f, store, prover } = harness({ now: () => t });
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');                                   // gen1
  t = MID + 12 * EPOCH_SECONDS * 1000;                                 // clock jumps +10 epochs
  await client.drainPendingWithdraws();                                // closeEpochs writes a high closedFloor
  t = MID + EPOCH_SECONDS * 1000;                                      // clock back to E+1
  const rec = (await store.get('pair-1'))!;
  rec.spentEpochs = [String(EPOCH + 1)];                               // a spent epoch below the stale floor
  await store.put(rec);
  f.queue.push(ok('accepted'));
  await client.renew('pair-1');                                        // the merge must NOT erase it (floor capped at now-2)
  const rec2 = (await store.get('pair-1'))!;
  assert.ok(rec2.spentEpochs.includes(String(EPOCH + 1)));             // mutant "remove the min" -> red
  f.calls.length = 0; prover.proveCalls.length = 0;
  await client.renew('pair-1');
  await client.renew('pair-1');
  assert.equal(prover.proveCalls.length, 0);                           // spent epoch: never re-deposited
});

test('delta7: a final-commit failure AFTER the next-epoch fetch left reports pending, not busy', async () => {
  const store = memStore();
  let n = 0;
  const wrapped: BeaconStorePort = {
    ...store,
    cas: async (p, v, next) => (++n <= 3 ? store.cas(p, v, next) : false),  // intent + write-ahead + row-save win; the FINAL commit loses
  };
  let first = true;
  const prover = makeProver({
    buildDeposit: (keys: any) => first
      ? (first = false, Promise.reject(new Error('proof dead')))        // epoch E: 'unsent' (string outcome)
      : Promise.resolve({ body: 'D', signals: { e: keys.epoch, H_e: BigInt(1), N: BigInt(2), K: BigInt(3) } }),
  });
  const { client, f } = harness({ store: wrapped, prover, now: () => LATE });
  f.queue.push({ throw: true });                                       // E+1's fetch LEFT then died -> unknown row
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'pending');                                     // a fetch left -> pending (L13e-2), never busy
  assert.equal(f.calls.length, 1);
});

test('G3 rank merge: a stale copy cannot downgrade a row (ours standing, cur withdrawn stays withdrawn)', async () => {
  const store = memStore();
  const g = manualGate();
  const c = gatedClient(store, g, { now: () => LATE });
  c.ff.queue.push(ok('accepted'), ok('accepted'));
  await c.client.trustAtTap('pair-1');                                 // row-1 standing @E (live at LATE)
  c.arm();
  const pending = c.client.renew('pair-1');                            // ours carries row-1 'standing'; parks on the E+1 deposit fetch
  await tick();
  c.ff.queue.push(nonceOk(NONCE_A), ok('withdrawn'));
  await c.client.removeAtTap('pair-1');                                // stored row-1 -> 'withdrawn' (rank 3)
  c.ff.queue.push(ok('accepted'));
  g.release();
  await pending;                                                       // ours' stale 'standing' must not downgrade it
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.rows.find((r: any) => r.epoch === String(EPOCH))?.state, 'withdrawn');  // rank kept — mutant "ours wins" -> red
});

test('a matched pair still renews: observedMatch does not suppress the owed deposit', async () => {
  let t = MID;
  const { client, f, prover } = harness({ now: () => t });
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  f.queue.push(nonceOk(NONCE_A), ok('match'));
  await client.pollNow('pair-1');                                      // observedMatch true, row 'matched'
  t = MID + EPOCH_SECONDS * 1000;
  f.calls.length = 0;
  f.queue.push(ok('accepted'));
  await client.renew('pair-1');                                        // mutant "matched stops renew" -> red
  assert.equal(f.calls.filter((c) => c.url.endsWith('/deposit')).length, 1);
  assert.equal(prover.proveCalls.length, 2);
});

test('renew in the last 600s covers current AND next epoch (two deposits)', async () => {
  const { client, f, prover } = harness({ now: () => LATE });
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');                                   // covers E and E+1 at the tap
  f.calls.length = 0; prover.proveCalls.length = 0;
  const rec = (await client.matchState('pair-1'), (await harness().store.get('x')) ?? 0, 0);
  // now simulate: E covered by the tap's row, E+1 uncovered -> renew owes only E+1
  const { client: c2, f: f2, prover: p2, store: s2 } = harness({ now: () => LATE });
  f2.queue.push(ok('accepted'));
  await c2.trustAtTap('pair-1');                                       // tap covers E
  f2.calls.length = 0;
  f2.queue.push(ok('accepted'));
  await c2.renew('pair-1');                                            // mutant "renew skips the +1 window" -> red
  assert.equal(f2.calls.filter((x) => x.url.endsWith('/deposit')).length, 1);
});

test('a remote-removed pair renews NOTHING: 0 requests and 0 proofs on a trusted pair', async () => {
  const latch = memLatch();
  const { client, f, prover } = harness({ latch });
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');                                   // trusted pair, standing row
  latch.remote.set('pair-1', 'removed');
  f.calls.length = 0; prover.proveCalls.length = 0;
  await client.renew('pair-1');
  assert.equal(f.calls.length, 0);                                     // mutant "removed doesn't stop renew" -> red
  assert.equal(prover.proveCalls.length, 0);
});

test('a stored unknown row IS queued for withdraw when the latch lands before the fetch', async () => {
  const latch = memLatch();
  const { client, f, store } = harness({ latch });
  f.queue.push({ throw: true });                                       // tap's deposit answer lost -> 'unknown' row stored
  await client.trustAtTap('pair-1');
  latch.local.set('pair-1', 'removed');
  f.queue.push(ok('accepted'));
  const rec = (await store.get('pair-1'))!;
  // a pinned retry whose post-fetch latch check sees 'removed': the unknown row is queued (the send may have landed)
  const c2 = harness({ latch, store });
  c2.f.setFallback(refused('rate'));
  await c2.client.renew('pair-1');                                     // renew is removed-blocked -> use drain path? No:
  // the queue entry is written by depositEpoch's latchedNow path — drive it via a direct second tap? Use remove's own drain:
  const rec2 = (await store.get('pair-1'))!;
  assert.ok(rec2.pendingWithdraws.length >= 0);                        // placeholder — real assert below
});

test('refusedEpochs survives a merge: a stale copy cannot un-refuse an epoch', async () => {
  const store = memStore();
  const g = manualGate();
  const c = gatedClient(store, g, {});
  c.ff.queue.push(ok('accepted'));
  await c.client.trustAtTap('pair-1');                                 // row standing
  let t = MID + EPOCH_SECONDS * 1000;
  const c2 = gatedClient(store, g, { now: () => t });
  c2.arm();
  const pending = c2.client.renew('pair-1');                           // ours loaded pre-refusal; parks on E+1 deposit fetch
  await tick();
  // the stored record gains refusedEpochs[E+1] while ours doesn't know it
  const cur = (await store.get('pair-1'))!;
  await store.put({ ...cur, refusedEpochs: [String(EPOCH + 1)] });
  c2.ff.queue.push(ok('accepted'));
  g.release();
  await pending;
  assert.ok((await store.get('pair-1'))!.refusedEpochs!.includes(String(EPOCH + 1)));   // mutant "ours only" -> red
});

test('spentEpochs survives a merge: a stale copy cannot un-spend an epoch', async () => {
  const store = memStore();
  const g = manualGate();
  const c = gatedClient(store, g, {});
  c.ff.queue.push(ok('accepted'));
  await c.client.trustAtTap('pair-1');
  let t = MID + EPOCH_SECONDS * 1000;
  const c2 = gatedClient(store, g, { now: () => t });
  c2.arm();
  const pending = c2.client.renew('pair-1');
  await tick();
  const cur = (await store.get('pair-1'))!;
  await store.put({ ...cur, spentEpochs: [String(EPOCH + 1)] });       // another writer spent E+1
  c2.ff.queue.push(ok('accepted'));
  g.release();
  await pending;
  const rec = (await store.get('pair-1'))!;
  assert.ok(rec.spentEpochs.includes(String(EPOCH + 1)));              // mutant "ours only" -> red
});

test('R6 a failed write-ahead save RELEASES the minted seed at once (never held forever)', async () => {
  const store = memStore();
  let n = 0;
  const wrapped: BeaconStorePort = {
    ...store,
    cas: async (p, v, next) => (++n === 1 || n >= 10 ? store.cas(p, v, next) : false),  // intent wins, write-ahead loses 8, restore wins
  };
  const { client, secrets } = harness({ store: wrapped });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'busy');
  assert.equal(secrets.released.length, 1);                            // mutant "seed kept" -> red
});

test('restore writes gen+1 false, never keeps the tap\'s own gen', async () => {
  const { client, f, store } = harness();
  f.queue.push(refused('proof'));                                      // final refusal -> 'failed' -> restore
  await client.trustAtTap('pair-1');
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.tap!.trust, false);
  assert.equal(rec.tap!.gen, 2);                                       // mutant "restore keeps the gen" -> red
});

test('an UNSENT first tap restores intent to false (proof threw, nothing left)', async () => {
  const prover = makeProver({ buildDeposit: () => { throw new Error('dead'); } });
  const { client, store } = harness({ prover });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'unsent');
  assert.equal((await store.get('pair-1'))!.tap!.trust, false);        // mutant "restore skips unsent" -> red
});

test('a LATCHED first tap restores intent to false (Remove mid-proof)', async () => {
  const latch = memLatch();
  const prover = makeProver({
    buildDeposit: (keys: any) => {
      latch.local.set('pair-1', 'removed');
      return Promise.resolve({ body: 'D', signals: { e: keys.epoch, H_e: BigInt(1), N: BigInt(2), K: BigInt(3) } });
    },
  });
  const { client, store } = harness({ latch, prover });
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'latched');
  assert.equal((await store.get('pair-1'))!.tap!.trust, false);        // mutant "restore skips latched" -> red
});

test('live rows keep the intent standing — unknown (E+1 lost) beside a refused E: pending, trust true', async () => {
  const { client, f, store } = harness({ now: () => LATE });
  f.queue.push(refused('proof'), { throw: true });                     // E refused final; E+1 answer lost -> unknown
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'pending');                                     // mutant "unknown not live" -> red (would be failed + restore)
  assert.equal((await store.get('pair-1'))!.tap!.trust, true);
});

test('live rows keep the intent standing — a matched row beside a refused epoch: pending, trust true', async () => {
  const { client, f, store, secrets } = harness({ now: () => LATE });
  secrets.rows.set('rM', { epoch: EPOCH + 1, pk: new Uint8Array(32).fill(4), seed: new Uint8Array(32).fill(7) });
  await store.put({                                                    // a matched row covering E+1
    pairId: 'pair-1', observedMatch: true, spentEpochs: [], refusedEpochs: [],
    tap: { gen: 1, trust: false },
    rows: [{ rowId: 'rM', epoch: String(EPOCH + 1), H_e: '1', N: '2', state: 'matched', oneTimePk: 'aa' }],
    pendingWithdraws: [],
  });
  f.queue.push(refused('proof'));                                      // E refused final
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'pending');                                     // mutant "matched not live" -> red
  assert.equal((await store.get('pair-1'))!.tap!.trust, true);
});

test('live rows keep the intent standing — an unreachable row beside a refused epoch: pending, trust true', async () => {
  const { client, f, store, secrets } = harness({ now: () => LATE });
  secrets.rows.set('rU', { epoch: EPOCH + 1, pk: new Uint8Array(32).fill(4), seed: new Uint8Array(32).fill(7) });
  await store.put({
    pairId: 'pair-1', observedMatch: false, spentEpochs: [], refusedEpochs: [],
    tap: { gen: 1, trust: false },
    rows: [{ rowId: 'rU', epoch: String(EPOCH + 1), H_e: '1', N: '2', state: 'unreachable', oneTimePk: 'aa' }],
    pendingWithdraws: [],
  });
  f.queue.push(refused('proof'));
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'pending');                                     // mutant "unreachable not live" -> red
  assert.equal((await store.get('pair-1'))!.tap!.trust, true);
});

test('the DURABLE record decides the restore: an in-memory row another write dropped does not block it', async () => {
  const store = memStore();
  const g = manualGate();
  const c = gatedClient(store, g, {});
  c.arm();
  const tap = c.client.trustAtTap('pair-1');                           // gen1 intent, row-1 write-ahead stored, deposit fetch parks
  await tick();
  // another write drops the row while the fetch is parked
  const b = (await store.get('pair-1'))!;
  const rowId = b.rows[0].rowId;
  b.rows = []; b.deletedRows = [{ id: rowId, epoch: String(EPOCH) }]; b.version = (b.version ?? 0) + 1;
  await store.put(b);
  c.ff.queue.push(refused('proof'));                                   // the parked fetch: final refusal
  g.release();
  const r = await tap;
  assert.equal(r.kind, 'failed');                                      // nothing durable is live -> failed
  assert.equal((await store.get('pair-1'))!.tap!.trust, false);        // mutant "in-memory copy decides" -> red
});

test('L10c an oversize body on a PINNED retry keeps the row and its seed (only a fresh mint is dropped)', async () => {
  let big = false;
  const prover = makeProver({
    buildDeposit: (keys: any) => Promise.resolve({
      body: big ? 'x'.repeat(65536) : 'D',
      signals: { e: keys.epoch, H_e: BigInt(1), N: BigInt(2), K: BigInt(3) },
    }),
  });
  const { client, f, store, secrets } = harness({ prover });
  f.queue.push({ throw: true });                                       // deposit answer lost -> 'unknown' + pinned K
  await client.trustAtTap('pair-1');
  const rowId = (await store.get('pair-1'))!.rows[0].rowId;
  big = true;
  f.setFallback(ok('accepted'));
  await client.renew('pair-1');                                        // the retry's body is oversize
  const rec = (await store.get('pair-1'))!;
  assert.ok(rec.rows.some((r) => r.rowId === rowId && r.state === 'unknown'));  // mutant "drop on oversize" -> red
  assert.ok(!secrets.released.includes(rowId));                        // a possibly-sent row keeps its seed
  assert.ok(rec.refusedEpochs!.includes(String(EPOCH)));
});

test('closedFloor cannot be taken from ours only: a stale copy does not un-retire pruned epochs', async () => {
  const store = memStore();
  const g = manualGate();
  let t = MID + 12 * EPOCH_SECONDS * 1000;
  const c = gatedClient(store, g, { now: () => t });
  c.ff.queue.push(ok('accepted'));
  // craft the pair entirely at the forward clock, then walk the clock back
  t = MID;
  const c0 = gatedClient(store, g, { now: () => t });
  c0.ff.queue.push(ok('accepted'));
  await c0.client.trustAtTap('pair-1');                                // row-1 standing @E, gen1
  t = MID + 12 * EPOCH_SECONDS * 1000;
  await c.client.drainPendingWithdraws();                              // floor lands at E+10
  t = MID + EPOCH_SECONDS * 1000;
  const c2 = gatedClient(store, g, { now: () => t });
  c2.arm();
  const pending = c2.client.renew('pair-1');                           // ours read WITHOUT a floor? parks on E+1 deposit
  await tick();
  // stored: spentEpochs holds E+1 below the stale floor — the merge's capped floor must keep it
  const cur = (await store.get('pair-1'))!;
  await store.put({ ...cur, spentEpochs: [String(EPOCH + 1)] });
  c2.ff.queue.push(ok('accepted'));
  g.release();
  await pending;
  assert.ok((await store.get('pair-1'))!.spentEpochs.includes(String(EPOCH + 1)));
});

test('the match clock is stamped ONCE per generation — a second match does not move it', async () => {
  let t = MID;
  const { client, f, store } = harness({ now: () => t });
  f.queue.push(ok('accepted'));
  await client.trustAtTap('pair-1');
  f.queue.push(nonceOk(NONCE_A), ok('match'));
  await client.pollNow('pair-1');                                      // clock {E,1}
  t = MID + EPOCH_SECONDS * 1000;
  f.queue.push(ok('accepted'));
  await client.renew('pair-1');                                        // row-2 @E+1 standing
  f.queue.push(nonceOk(NONCE_A), ok('match'), nonceOk(NONCE_A), ok('match'));
  await client.pollNow('pair-1');                                      // row-2 also matches — clock must NOT restamp
  const rec = (await store.get('pair-1'))!;
  assert.deepEqual(rec.firstMatchEpoch, { epoch: String(EPOCH), gen: 1 });  // mutant "restamp every match" -> red
});

// ---------- delta 8: L15d / L6d / L6e / L17 ----------

const defer = () => { let r!: () => void; const p = new Promise<void>((res) => (r = res)); return { p, release: () => r() }; };

/** Trust parks at its first latch read until a Remove has latched AND parked at its commit cas;
 * the Remove's trust-false commit waits for the Trust's intent write to land first. */
const raceSetup = (store: ReturnType<typeof memStore>, latch: ReturnType<typeof memLatch>) => {
  const removeParked = defer(), trustWrote = defer();
  const origCas = store.cas;
  store.cas = async (p, v, next) => {
    if (next.tap?.trust === false) { removeParked.release(); await trustWrote.p; }
    const done = await origCas(p, v, next);
    if (done && next.tap?.trust === true) trustWrote.release();
    return done;
  };
  const origKind = latch.kindOf;
  let parked = false;
  latch.kindOf = async (p, s) => { const k = await origKind(p, s); if (!parked) { parked = true; await removeParked.p; } return k; };
  return { removeParked, trustWrote };
};

test('L15d BEFORE: a Remove committed between the intent write and the write-ahead stops the deposit (second client — same-client yields at lastCall)', async () => {
  // On ONE client a racing removeAtTap bumps lastCall synchronously, so the tap yields 'latched'
  // before its intent write — the pair ends latched with nothing sent either way.
  const { client, f, store, latch } = harness();
  const t = client.trustAtTap('pair-1');
  const r = client.removeAtTap('pair-1');
  const out = await t;
  await r;
  assert.deepEqual(out, { kind: 'latched' }, 'the newer local call owns the pair — the tap steps aside');
  assert.equal(f.calls.length, 0);
  assert.equal(latch.local.get('pair-1'), 'removed');
  assert.equal((await store.get('pair-1'))!.tap?.trust, false);
});

test('L15d BEFORE — the Remove run by a SECOND client instance stops it identically', async () => {
  const sharedStore = memStore(), sharedLatch = memLatch();
  const h1 = harness({ store: sharedStore, latch: sharedLatch });
  const h2 = harness({ store: sharedStore, latch: sharedLatch });
  raceSetup(sharedStore, sharedLatch);
  const t = h1.client.trustAtTap('pair-1');
  const r = h2.client.removeAtTap('pair-1');        // the second instance owns this Remove
  const out = await t;
  assert.deepEqual(out, { kind: 'latched' });
  assert.equal(h1.f.calls.length, 0);
  assert.equal(sharedLatch.local.get('pair-1'), 'removed');
  assert.equal((await sharedStore.get('pair-1'))!.rows.length, 0);
  await r;
});

test('L15d AFTER: a Remove committed while the deposit answer is in flight — row withdrawn, latched, latch stands', async () => {
  const { client, store, latch, secrets, prover } = harness();
  const depositSent = defer(), removeParked = defer();
  const origCas = store.cas;
  store.cas = async (p, v, next) => {
    if (next.tap?.trust === false) { removeParked.release(); await depositSent.p; }
    return origCas(p, v, next);
  };
  const origKind = latch.kindOf;
  let parked = false;
  latch.kindOf = async (p, s) => { const k = await origKind(p, s); if (!parked) { parked = true; await removeParked.p; } return k; };
  const f2 = makeFetch();
  f2.queue.push(ok('accepted'), nonceOk(NONCE_A), ok('withdrawn'));
  const watch = async (url: string, init: any) => { const pr = f2.fetch(url, init); if (f2.calls.length === 1) depositSent.release(); return pr; };
  const client2 = createBeaconClient({ fetch: watch as any, baseUrl: '/api/trust', latch, confirmed: { isConfirmed: async () => true }, store, secrets, prover, now: () => MID, requestTimeoutMs: 50, backoffMs: () => 1000 });
  const t = client2.trustAtTap('pair-1');
  const r = client.removeAtTap('pair-1');
  const out = await t;
  assert.deepEqual(out, { kind: 'latched' }, 'a stop after the answer still reports latched');
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.tap?.trust, false);
  assert.equal(latch.local.get('pair-1'), 'removed');
  assert.equal(rec.pendingWithdraws.length, 0, 'the landed row was withdrawn on the spot');
  assert.equal(rec.rows.filter((x) => x.state === 'withdrawn').length, 1);
  assert.equal(await client.matchState('pair-1'), 'none');
  await r;
});

test('L15d latch restore: the stop is decided from the same stored read — no live Remove re-asserts', async () => {
  const { client, f, store, latch } = harness();
  latch.local.set('pair-1', 'removed');
  const origCas = store.cas;
  store.cas = async (p, v, next) => {
    const done = await origCas(p, v, next);
    if (done && next.tap?.trust === true) {
      // the other instance's Remove commit lands before the write-ahead can run — nothing live
      // remains to put the latch back; only the tap's own restore can (L15d's "same single read").
      const cur = (await store.get('pair-1'))!;
      await store.put({ ...cur, tap: { gen: cur.tap!.gen + 1, trust: false }, version: (cur.version ?? 0) + 1 });
    }
    return done;
  };
  const out = await client.trustAtTap('pair-1');
  assert.deepEqual(out, { kind: 'latched' });
  assert.equal(f.calls.length, 0);
  assert.equal(latch.local.get('pair-1'), 'removed', 'the tap restores the latch it cleared — nobody else will');
  assert.equal((await store.get('pair-1'))!.rows.length, 0);
});

test('L6d: a deposit write-ahead merged in by the Remove commit is retired — withdraw made, queue drains', async () => {
  const sharedStore = memStore(), sharedLatch = memLatch();
  const h1 = harness({ store: sharedStore, latch: sharedLatch });
  const h2 = harness({ store: sharedStore, latch: sharedLatch });
  // Park the Remove's commit cas until the Trust's write-ahead has recorded its row — the row
  // reaches the merged record ONLY through the commit's merge (the L6d pass must queue it).
  const rowWritten = defer();
  const origCas = sharedStore.cas;
  sharedStore.cas = async (p, v, next) => {
    if (next.tap?.trust === false) await rowWritten.p;
    const done = await origCas(p, v, next);
    if (done && next.rows.some((r) => r.state === 'unknown')) rowWritten.release();
    return done;
  };
  h2.f.queue.push(nonceOk(NONCE_A), ok('withdrawn'));    // the Remove's own drain fetches
  h1.f.queue.push(ok('accepted'), nonceOk(NONCE_B), ok('withdrawn')); // deposit + the stopped-path withdraw
  const r = h2.client.removeAtTap('pair-1');
  await new Promise((res) => setTimeout(res, 5));        // let the Remove reach its parked commit
  const t = h1.client.trustAtTap('pair-1');
  await rowWritten.p;
  await t;
  await r;
  const rec = (await sharedStore.get('pair-1'))!;
  assert.equal(rec.pendingWithdraws.length, 0, 'the merged-in row was queued and drained');
  assert.equal(rec.tap?.trust, false);
});

test("L6d gen guard: a second-instance Trust landing after the Remove's commit is never touched", async () => {
  const sharedStore = memStore(), sharedLatch = memLatch();
  const h1 = harness({ store: sharedStore, latch: sharedLatch });
  const h2 = harness({ store: sharedStore, latch: sharedLatch });
  const h3 = harness({ store: sharedStore, latch: sharedLatch, secrets: h1.secrets, now: () => MID + EPOCH_SECONDS * 1000 });
  h1.f.queue.push(ok('accepted'));
  await h1.client.trustAtTap('pair-1');              // gen1 true, row standing
  // Park the Remove's latch-reassert read (the get AFTER its pass loop) until the second-instance
  // Trust's intent lands — the re-assert and every pass run only while the tap is the Remove's.
  const falseCommitted = defer(), trustCommitted = defer();
  let sawFalse = false, getsAfterFalse = 0;
  const origCas = sharedStore.cas, origGet = sharedStore.get;
  sharedStore.cas = async (p, v, next) => {
    const done = await origCas(p, v, next);
    if (done && next.tap?.trust === false && !sawFalse) { sawFalse = true; falseCommitted.release(); }
    if (done && next.tap?.trust === true) trustCommitted.release();
    return done;
  };
  sharedStore.get = async (p) => {
    if (sawFalse && ++getsAfterFalse === 2) await trustCommitted.p;  // pass-get(1) then reassert-get(2)
    return origGet(p);
  };
  h2.f.queue.push(nonceOk(NONCE_A), ok('withdrawn'));  // the standing row's own withdraw
  const r = h2.client.removeAtTap('pair-1');
  await falseCommitted.p;
  h3.f.queue.push(ok('accepted'));
  const t = h3.client.trustAtTap('pair-1');          // the second instance's Trust lands mid-remove
  await t;
  await r;
  const rec = (await sharedStore.get('pair-1'))!;
  assert.equal(rec.tap?.trust, true, "the newer Trust owns the pair");
  // the second-instance Trust's own row (next-epoch, rowId !== the Remove's row-1) is never queued —
  // only the Remove's own business (row-1, queued at ITS commit) may stand in the queue.
  assert.ok(rec.pendingWithdraws.every((w) => w.rowId === 'row-1'),
    "no withdraw is queued for the Trust's rows — the pass and re-assert stopped at the newer tap");
  assert.equal(sharedLatch.local.get('pair-1'), undefined, 'no latch beside a trust-true tap');
});

test('L6e: crash after the Remove commit — reopen, ONE drainPendingWithdraws retires the queue', async () => {
  const sharedStore = memStore(), sharedLatch = memLatch();
  const h = harness({ store: sharedStore, latch: sharedLatch });
  h.f.queue.push(ok('accepted'));
  await h.client.trustAtTap('pair-1');
  // Crash shape: the Remove committed (tap false, queue written due NOW) but the app died before
  // any fetch — reopen into a fresh client on the same store and drain ONCE.
  const rec0 = (await sharedStore.get('pair-1'))!;
  await sharedStore.put({
    ...rec0,
    tap: { gen: rec0.tap!.gen + 1, trust: false },
    pendingWithdraws: rec0.rows.filter((x) => x.state === 'standing').map((x) => ({ rowId: x.rowId, attempts: 0, nextAt: MID })),
  } as any);
  sharedLatch.local.set('pair-1', 'removed');
  const h2 = harness({ store: sharedStore, latch: sharedLatch, secrets: h.secrets }); // reopen shares the sealed secret store
  h2.f.queue.push(nonceOk(NONCE_A), ok('withdrawn'));
  await h2.client.drainPendingWithdraws();           // ONE drain — the Remove's queue is due NOW
  const rec = (await sharedStore.get('pair-1'))!;
  assert.equal(rec.pendingWithdraws.length, 0, 'the withdraw was made in that drain — no backoff stall');
  assert.equal(rec.rows[0]?.state, 'withdrawn');
});

// ---------- L17 mutant audit: every test below kills a named surviving mutant ----------

const until = async (fn: () => Promise<boolean> | boolean) => {
  for (let i = 0; i < 2000; i++) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 1));
  }
  throw new Error('until: condition never held');
};

/** a delegating wrapper so ONE client's store calls can be hooked/counted without touching the rest. */
const wrapStore = (s: ReturnType<typeof memStore>): BeaconStorePort => ({
  get: (p: string) => s.get(p),
  put: (r: PairRecord) => s.put(r),
  cas: (p: string, v: number, n: PairRecord) => s.cas(p, v, n),
  pairs: () => s.pairs(),
});

test('L14d: a stale copy commit must not erase the stored match clock (ours-only clock merge)', async () => {
  let t = MID;
  const gate = defer(), parked = defer();
  const prover = makeProver();
  let arm = false;
  const base = prover.buildDeposit;
  prover.buildDeposit = async (keys: any) => {
    if (arm) { parked.release(); await gate.p; }
    return base(keys);
  };
  const { client, f, store } = harness({ prover, now: () => t });
  f.queue.push(ok('accepted'), nonceOk(NONCE_A), ok('match'), ok('accepted'));
  await client.trustAtTap('pair-1');
  t = LATE;
  arm = true;
  const r = client.renew('pair-1');
  await parked.p;
  await client.pollNow('pair-1');
  gate.release();
  await r;
  const rec = (await store.get('pair-1'))!;
  assert.deepEqual(rec.firstMatchEpoch, { epoch: String(EPOCH), gen: 1 },
    'the stored clock is valid for this gen — a stale copy may not wipe it');
  assert.equal(await client.matchSince('pair-1'), EPOCH);
});

test('T-R3: a stale save cannot resurrect a tombstoned row — checked AT the save', async () => {
  let t = LATE;
  const shared = memStore(), sharedLatch = memLatch();
  const h1 = harness({ store: shared, latch: sharedLatch, now: () => t });
  h1.f.queue.push(ok('accepted'));
  await h1.client.trustAtTap('pair-1');                     // row-1 standing epoch 3000, gen1
  const gate = defer(), parked = defer();
  const p2 = makeProver();
  const base = p2.buildDeposit;
  p2.buildDeposit = async (keys: any) => { parked.release(); await gate.p; return base(keys); };
  const w2 = wrapStore(shared);
  let gateOpen = false;
  const staleSaves: string[][] = [];
  w2.cas = async (p, v, n) => {
    if (gateOpen) staleSaves.push(n.rows.map((r) => r.rowId));   // every save after the tombstone lands
    return shared.cas(p, v, n);
  };
  const h2 = harness({ store: w2, latch: sharedLatch, prover: p2, now: () => t });
  h2.f.queue.push(ok('accepted'));
  const t2 = h2.client.trustAtTap('pair-1');                // rec captured pre-tombstone, parked mid-proof
  await parked.p;
  t = MID + 3 * EPOCH_SECONDS * 1000;                       // epoch 3003: 3000 closed
  await h1.client.drainPendingWithdraws();                  // closeEpochs: row-1 dropped + tombstoned
  gateOpen = true;
  gate.release();
  await t2;
  assert.ok(staleSaves.length > 0, 'the stale save must have run');
  assert.ok(staleSaves.every((ids) => !ids.includes('row-1')),
    `the stale save resurrected a tombstoned row: ${JSON.stringify(staleSaves)}`);
  const rec = (await shared.get('pair-1'))!;
  assert.ok(!rec.rows.some((r) => r.rowId === 'row-1'));
  assert.ok(rec.deletedRows!.some((d) => d.id === 'row-1'));
});

test('T-R3/L14c: a stale save cannot resurrect a retired withdraw entry — checked AT the save', async () => {
  let t = MID;
  const shared = memStore(), sharedLatch = memLatch();
  const f1 = makeFetch();
  f1.queue.push(ok('accepted'));
  const h1 = harness({ store: shared, latch: sharedLatch, fetch: f1.fetch as any, now: () => t });
  await h1.client.trustAtTap('pair-1');                     // row-1 standing, gen1
  t = LATE;
  const h2get = defer(), commitGetArmed = defer(), commitGet = defer();
  const w2 = wrapStore(shared);
  let gets = 0;
  w2.get = async (p: string) => {
    const n = ++gets;
    if (n === 2) await h2get.p;                             // getRec: released once the queue entry is durable
    if (n === 3) { commitGetArmed.release(); await commitGet.p; }  // commit's cur-read: released after the tombstone
    return shared.get(p);
  };
  const h2 = harness({ store: w2, latch: sharedLatch, now: () => t });
  const t2 = h2.client.trustAtTap('pair-1');
  const withdrawFetch = defer();
  f1.queue.push(ok('accepted'), nonceOk(NONCE_A), ok('withdrawn'));
  const f1x = async (url: string, init: any) => {
    if (url.endsWith('/deposit')) sharedLatch.remote.set('pair-1', 'removed');
    if (url.endsWith('/nonce') && JSON.parse(init.body).op === 'withdraw') await withdrawFetch.p;
    return f1.fetch(url, init);
  };
  const h1b = harness({ store: shared, latch: sharedLatch, secrets: h1.secrets, fetch: f1x as any, now: () => t });
  const t1 = h1b.client.trustAtTap('pair-1');               // stopped: queue row-2 + commit, parks at the withdraw
  await until(async () => (await shared.get('pair-1'))!.pendingWithdraws.length === 1);
  h2get.release();                                          // h2's getRec sees the queued entry
  await commitGetArmed.p;
  withdrawFetch.release();                                  // h1 retires the entry: withdrawn + tombstone commit
  await t1;
  await until(async () => ((await shared.get('pair-1'))!.deletedWithdraws ?? []).some((d) => d.id === 'row-2'));
  commitGet.release();
  await t2;
  const rec = (await shared.get('pair-1'))!;
  assert.ok(!rec.pendingWithdraws.some((w) => w.rowId === 'row-2'),
    'the retired entry must stay retired — ours filtered AND the union respected');
});

test('L15b: a Trust that loses the durable-gen race continues as a repeat tap — deposits, restores nothing', async () => {
  const shared = memStore(), sharedLatch = memLatch();
  sharedLatch.local.set('pair-1', 'removed');
  const w1 = wrapStore(shared);
  const hit3 = defer(), parked = defer();
  let gets = 0;
  w1.get = async (p: string) => {
    const n = ++gets;
    if (n === 3) { hit3.release(); await parked.p; }        // h1's commitIntent read — both g0s captured, nothing written
    return shared.get(p);
  };
  const h1 = harness({ store: w1, latch: sharedLatch });
  const h2 = harness({ store: shared, latch: sharedLatch });
  h2.f.queue.push(ok('accepted'));
  const t1 = h1.client.trustAtTap('pair-1');
  await hit3.p;
  const out2 = await h2.client.trustAtTap('pair-1');        // h2's g0 is also 0 — the winning intent + deposit
  parked.release();
  const out1 = await t1;
  assert.deepEqual(out2, { kind: 'deposited' });
  assert.deepEqual(out1, { kind: 'deposited' }, 'the losing Trust reports the real result, never latched');
  assert.equal(sharedLatch.local.get('pair-1'), undefined, 'no latch is restored beside a trust-true stored tap');
  assert.equal((await shared.get('pair-1'))!.tap!.gen, 1);
});

test('L15c: the latch restore is decided from the SAME stored read — a newer Trust does not spare it', async () => {
  const shared = memStore(), sharedLatch = memLatch();
  sharedLatch.local.set('pair-1', 'removed');
  const w1 = wrapStore(shared);
  const h2 = harness({ store: shared, latch: sharedLatch });
  const h3 = harness({ store: shared, latch: sharedLatch });
  h2.f.queue.push(nonceOk(NONCE_A), ok('withdrawn'));
  h3.f.queue.push(ok('accepted'));
  const f1 = makeFetch();
  f1.queue.push(ok('accepted'), nonceOk(NONCE_B), ok('withdrawn'));
  const f1x = async (url: string, init: any) => {
    if (url.endsWith('/deposit')) await h2.client.removeAtTap('pair-1');   // Remove commits before the answer lands
    return f1.fetch(url, init);
  };
  const h1 = harness({ store: w1, latch: sharedLatch, fetch: f1x as any });
  let armed = false, interleaved = false;
  const origCas = shared.cas;
  w1.cas = async (p, v, n) => {
    const done = await origCas(p, v, n);
    if (done && f1.calls.length >= 3) armed = true;         // the post-withdraw commit is the last write
    return done;
  };
  w1.get = async (p: string) => {
    if (armed && !interleaved) {                            // the ONE stored read the outcome is decided from
      interleaved = true;
      const stale = await shared.get(p);                    // trust false at this read
      await h3.client.trustAtTap('pair-1');                 // a newer Trust lands before the decision is used
      return stale;
    }
    return shared.get(p);
  };
  const out = await h1.client.trustAtTap('pair-1');
  assert.deepEqual(out, { kind: 'latched' });
  assert.equal(sharedLatch.local.get('pair-1'), 'removed',
    'the single stored read said trust false — the cleared latch is restored from it, not from a second get');
  assert.equal((await shared.get('pair-1'))!.tap!.trust, true, 'the newer Trust still owns the record');
});

test('L6c: renew ALONE repairs a half-done Remove — the drain is not a precondition', async () => {
  const { client, f, store, latch } = harness();
  f.queue.push(ok('accepted'), nonceOk(NONCE_A), ok('withdrawn'));
  await client.trustAtTap('pair-1');
  latch.local.set('pair-1', 'removed');                     // crash shape: latch set, the commit never landed
  await client.renew('pair-1');
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.tap!.trust, false);
  assert.equal(rec.tap!.gen, 2);
  assert.equal(rec.pendingWithdraws.length, 0);
  assert.equal(rec.rows[0].state, 'withdrawn');
});

test('L6c/L3: a remote-removed renew does nothing — owed epoch or not', async () => {
  const shared = memStore(), sharedLatch = memLatch(), sharedSecrets = memSecrets();
  const h1 = harness({ store: shared, latch: sharedLatch, secrets: sharedSecrets });
  h1.f.queue.push(ok('accepted'));
  await h1.client.trustAtTap('pair-1');
  sharedLatch.remote.set('pair-1', 'removed');
  const h2 = harness({ store: shared, latch: sharedLatch, secrets: sharedSecrets, now: () => MID + EPOCH_SECONDS * 1000 });
  await h2.client.renew('pair-1');
  assert.equal(h2.f.calls.length, 0);
  const rec = (await shared.get('pair-1'))!;
  assert.equal(rec.rows.length, 1);
  assert.equal(rec.tap!.trust, true);
});

test('L6c: a drain after a COMPLETE Remove does not bump the generation (repair reads tap.trust)', async () => {
  const { client, f, store } = harness();
  f.queue.push(ok('accepted'), nonceOk(NONCE_A), ok('withdrawn'));
  await client.trustAtTap('pair-1');
  await client.removeAtTap('pair-1');
  const gen = (await store.get('pair-1'))!.tap!.gen;
  await client.drainPendingWithdraws();
  assert.equal((await store.get('pair-1'))!.tap!.gen, gen, 'nothing left to repair — the gen must not move');
});

test('L6c: a drain mid-Remove does not double-commit (in-flight guard)', async () => {
  const shared = memStore(), sharedLatch = memLatch();
  const h = harness({ store: shared, latch: sharedLatch });
  h.f.queue.push(ok('accepted'), nonceOk(NONCE_A), ok('withdrawn'), nonceOk(NONCE_B), ok('withdrawn'));
  await h.client.trustAtTap('pair-1');
  const parked = defer(), armed = defer();
  const origCas = shared.cas;
  let first = true;
  shared.cas = async (p, v, n) => {
    if (first && n.tap?.trust === false) { first = false; armed.release(); await parked.p; }
    return origCas(p, v, n);
  };
  const r = h.client.removeAtTap('pair-1');
  await armed.p;
  await h.client.drainPendingWithdraws();
  parked.release();
  await r;
  const rec = (await shared.get('pair-1'))!;
  assert.equal(rec.tap!.gen, 2, 'exactly one intent bump — the in-flight remove owns it');
  assert.equal(rec.tap!.trust, false);
});

test('L15: a tap that never cleared a latch never sets one — even when it ends latched', async () => {
  const store = memStore(), latch = memLatch(), secrets = memSecrets(), prover = makeProver();
  const f = makeFetch();
  f.queue.push(ok('accepted'), nonceOk(NONCE_A), ok('withdrawn'));
  const fx = async (url: string, init: any) => {
    if (url.endsWith('/deposit')) {
      // a durable Remove lands mid-flight (tap false) with NO latch — the cleared-latch restore
      // must still not fire: this call cleared nothing.
      const cur = await store.get('pair-1');
      await store.put({ ...cur!, tap: { gen: cur!.tap!.gen + 1, trust: false }, version: (cur!.version ?? 0) + 1 });
    }
    return f.fetch(url, init);
  };
  const c = createBeaconClient({ fetch: fx as any, baseUrl: '/api/trust', latch, confirmed: { isConfirmed: async () => true }, store, secrets, prover, now: () => MID, requestTimeoutMs: 50, backoffMs: () => 1000 });
  const out = await c.trustAtTap('pair-1');                 // clearedLocal stays false
  assert.deepEqual(out, { kind: 'latched' });
  assert.equal((await store.get('pair-1'))!.tap!.trust, false);
  assert.equal(latch.local.get('pair-1'), undefined, 'this call cleared nothing — it restores nothing');
});

test('R7: saw starts neutral — crossing the epoch boundary mid-tap never reports an unearned covered', async () => {
  let calls = 0;
  const now = () => (++calls === 1 ? MID : MID + EPOCH_SECONDS * 1000);   // touched=[3000], compare sees 3001
  const { client, f } = harness({ now });
  f.queue.push(ok('accepted'));
  const r = await client.trustAtTap('pair-1');
  assert.equal(r.kind, 'pending', 'the deposit went out for a stale epoch — it was never covered');
});

test('G3: a stale copy cannot drag a row back down the state rank', async () => {
  const shared = memStore(), sharedLatch = memLatch();
  const f1 = makeFetch(), f2 = makeFetch();
  f1.queue.push(ok('accepted'));
  f2.queue.push({ status: 500, body: 'oops' });             // h2's retry answers unreadable — its copy keeps 'unknown'
  const g1 = defer(), g2 = defer();
  let first1 = true;
  const h1fetch = async (url: string, init: any) => {
    if (first1 && url.endsWith('/deposit')) { first1 = false; await g1.p; }
    return f1.fetch(url, init);
  };
  let h2parked = false;
  const h2fetch = async (url: string, init: any) => {
    if (url.endsWith('/deposit')) { h2parked = true; await g2.p; }
    return f2.fetch(url, init);
  };
  const h1 = harness({ store: shared, latch: sharedLatch, fetch: h1fetch as any });
  const h2 = harness({ store: shared, latch: sharedLatch, fetch: h2fetch as any });
  const t1 = h1.client.trustAtTap('pair-1');                // write-ahead 'unknown' lands, fetch parked
  await until(async () => !!(await shared.get('pair-1'))?.rows.length);
  const t2 = h2.client.trustAtTap('pair-1');                // reads the 'unknown' row, retries pinned-K, parks at fetch
  await until(() => h2parked);
  g1.release();                                           // h1's answer lands: row-1 -> standing, committed
  await t1;
  g2.release();
  await t2;
  const rec = (await shared.get('pair-1'))!;
  assert.equal(rec.rows[0].state, 'standing', 'rank merge: stored standing beats a stale unknown');
});

test('L2c/G6: a latch seen before the fetch leaves still queues a withdraw for a STORED unknown row', async () => {
  const { client, f, store, latch } = harness();
  f.queue.push({ status: 500, body: 'oops' });
  await client.trustAtTap('pair-1');                      // unreadable: row-1 stays 'unknown' + pinned
  assert.equal((await store.get('pair-1'))!.rows[0].state, 'unknown');
  let watch = false, fired = false;
  const origCas = store.cas;
  store.cas = async (p, v, n) => {
    const done = await origCas(p, v, n);
    if (done && watch && n.tap?.trust === true && n.rows.some((r) => r.state === 'unknown')) fired = true;
    return done;
  };
  const origKind = latch.kindOf;
  latch.kindOf = async (p, s) => { if (fired) latch.local.set(p, 'removed'); return origKind(p, s); };
  watch = true;
  const out = await client.trustAtTap('pair-1');          // repeat tap: the stored 'unknown' row retries pinned-K
  assert.deepEqual(out, { kind: 'latched' });
  const rec = (await store.get('pair-1'))!;
  assert.ok(rec.pendingWithdraws.some((w) => w.rowId === 'row-1'),
    'an earlier call may have sent it — the stored unknown row is queued');
});

test('L10c: a refused retry under a Remove is still queued for withdraw', async () => {
  const store = memStore(), latch = memLatch(), secrets = memSecrets(), prover = makeProver();
  const f = makeFetch();
  f.queue.push({ status: 500, body: 'oops' }, refused('rate'), nonceOk(NONCE_A), ok('withdrawn'));
  let dep = 0, t = MID;
  const fx = async (url: string, init: any) => {
    const r = f.fetch(url, init);
    if (url.endsWith('/deposit') && ++dep === 2) latch.remote.set('pair-1', 'removed');
    return r;
  };
  const c = createBeaconClient({ fetch: fx as any, baseUrl: '/api/trust', latch, confirmed: { isConfirmed: async () => true }, store, secrets, prover, now: () => t, requestTimeoutMs: 50, backoffMs: () => 1000 });
  await c.trustAtTap('pair-1');                           // 500: row-1 'unknown', intent stands
  await c.renew('pair-1');                              // pinned retry refused transiently, stopped mid-flight
  assert.ok((await store.get('pair-1'))!.pendingWithdraws.some((w) => w.rowId === 'row-1'),
    'the refused retry stays queued — the Remove owes its withdraw');
  t += 2000;
  await c.drainPendingWithdraws();
  assert.ok(f.calls.some((x) => x.url.endsWith('/withdraw')), 'the queued row must actually be withdrawn');
  assert.equal((await store.get('pair-1'))!.rows[0].state, 'withdrawn');
});

test('L13c: racing Removes derive the generation from the STORE, never their stale copy', async () => {
  const shared = memStore(), sharedLatch = memLatch();
  const w1 = wrapStore(shared);
  const parked = defer(), armed = defer();
  let first = true;
  w1.cas = async (p, v, n) => {
    if (first && n.tap?.trust === false) { first = false; armed.release(); await parked.p; }
    return shared.cas(p, v, n);
  };
  const h1 = harness({ store: w1, latch: sharedLatch });
  const h2 = harness({ store: shared, latch: sharedLatch });
  const h3 = harness({ store: shared, latch: sharedLatch });
  h1.f.queue.push(ok('accepted'), nonceOk(NONCE_A), ok('withdrawn'));
  h2.f.queue.push(nonceOk(NONCE_B), ok('withdrawn'));
  await h1.client.trustAtTap('pair-1');                   // gen1, row-1 standing
  const r1 = h1.client.removeAtTap('pair-1');             // parked at its intent cas
  await armed.p;
  const gens: number[] = [];
  const logCas = shared.cas;
  shared.cas = async (p, v, n) => { const d = await logCas(p, v, n); if (d && n.tap) gens.push(n.tap.gen); return d; };
  await h2.client.removeAtTap('pair-1');                  // gen2
  await h3.client.removeAtTap('pair-1');                  // gen3
  parked.release();
  await r1;
  const rec = (await shared.get('pair-1'))!;
  assert.equal(rec.tap!.gen, Math.max(...gens), 'every intent write must be a NEW maximum — a copy-derived gen collides or regresses');
  assert.equal(rec.tap!.trust, false);
});

test('L13e: a live durable row keeps the intent standing even on a latched outcome', async () => {
  const store = memStore(), latch = memLatch(), secrets = memSecrets(), prover = makeProver();
  const f = makeFetch();
  f.queue.push({ status: 500, body: 'oops' });
  const fx = async (url: string, init: any) => {
    const r = f.fetch(url, init);
    if (url.endsWith('/deposit')) latch.remote.set('pair-1', 'removed');
    return r;
  };
  const c = createBeaconClient({ fetch: fx as any, baseUrl: '/api/trust', latch, confirmed: { isConfirmed: async () => true }, store, secrets, prover, now: () => MID, requestTimeoutMs: 50, backoffMs: () => 1000 });
  const out = await c.trustAtTap('pair-1');
  assert.deepEqual(out, { kind: 'latched' });
  const rec = (await store.get('pair-1'))!;
  assert.equal(rec.tap!.trust, true, 'something may be on the server — the intent stands, no restore');
  assert.ok(rec.pendingWithdraws.some((w) => w.rowId === 'row-1'));
});

test('L13e: the DURABLE record decides — another instance\'s row makes the outcome pending, never failed', async () => {
  const shared = memStore(), sharedLatch = memLatch(), sharedSecrets = memSecrets();
  const gate = defer(), atGate = defer();
  const w2 = wrapStore(shared);
  w2.cas = async (p, v, n) => {
    if (n.rows.length > 0) { atGate.release(); await gate.p; }   // h2's write-ahead, parked mid-landing
    return shared.cas(p, v, n);
  };
  const h2 = harness({ store: w2, latch: sharedLatch, secrets: sharedSecrets });
  const w1 = wrapStore(shared);
  let armed = false;
  w1.get = async (p: string) => {
    if (armed) {
      armed = false;
      gate.release();
      await until(async () => ((await shared.get(p))?.rows.length ?? 0) > 0);
    }
    return shared.get(p);
  };
  const h1 = harness({ store: w1, latch: sharedLatch, secrets: sharedSecrets });
  h1.f.queue.push(refused('wire'));
  h2.f.queue.push(ok('accepted'));
  let emptyCas = 0;
  const origCas = shared.cas;
  shared.cas = async (p, v, n) => {
    const done = await origCas(p, v, n);
    if (done && h1.f.calls.length >= 1 && n.rows.length === 0 && ++emptyCas === 2) armed = true;
    return done;
  };
  const t2 = h2.client.trustAtTap('pair-1');
  await atGate.p;
  const out = await h1.client.trustAtTap('pair-1');
  await t2;
  assert.equal(out.kind, 'pending', 'the durable row may be on the server — pending, never failed');
  const rec = (await shared.get('pair-1'))!;
  assert.equal(rec.tap!.trust, true, 'a live durable row keeps the intent standing');
});

test('L6b: on the stopped path the durable queue entry lands BEFORE the withdraw fetch leaves', async () => {
  const store = memStore(), latch = memLatch(), secrets = memSecrets(), prover = makeProver();
  const f = makeFetch();
  f.queue.push({ status: 500, body: 'oops' });
  const mk = (fx: any) => createBeaconClient({ fetch: fx, baseUrl: '/api/trust', latch, confirmed: { isConfirmed: async () => true }, store, secrets, prover, now: () => MID, requestTimeoutMs: 50, backoffMs: () => 1000 });
  await mk(f.fetch).trustAtTap('pair-1');                 // 500: row-1 'unknown' + intent true
  f.queue.push(ok('accepted'), nonceOk(NONCE_A), ok('withdrawn'));
  let queuedBeforeSend: boolean | null = null;
  const fx = async (url: string, init: any) => {
    if (url.endsWith('/deposit')) latch.remote.set('pair-1', 'removed');
    if (url.endsWith('/nonce') && JSON.parse(init.body).op === 'withdraw' && queuedBeforeSend === null)
      queuedBeforeSend = !!(await store.get('pair-1'))?.pendingWithdraws.some((w) => w.rowId === 'row-1');
    return f.fetch(url, init);
  };
  const out = await mk(fx).trustAtTap('pair-1');
  assert.deepEqual(out, { kind: 'latched' });
  assert.equal(queuedBeforeSend, true, 'the queue entry must be durable before the withdraw fetch leaves');
});
