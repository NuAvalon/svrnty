// sealedRowUpdate: the glue between the atomic-update loop and the REAL commitIfUnchanged, run against a small in-memory fake of the IndexedDB surface it uses (the same shape as
// commit-if-unchanged.test.ts: writes apply only when the transaction completes and are dropped on abort). It cannot show real browser behaviour (auto-commit timing, cross-tab ordering);
// it shows that the loop and the real commit agree: a write that lands between the read and the commit makes the commit return false, the decision runs again on the newer row, and a wrong
// `expected` would let the stale result through.
// Run: npx tsx --test src/lib/identity/sealed-row-update.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sealedRowUpdate, type SealedRow } from './client-store';
import type { SealedRead } from '../trust/suppression-restore';

type Row = Record<string, unknown>;
class FakeReq<T = unknown> { result: T | undefined; error: unknown = null; onsuccess: (() => void) | null = null; onerror: (() => void) | null = null; }
class FakeTx {
  oncomplete: (() => void) | null = null; onabort: (() => void) | null = null; onerror: (() => void) | null = null; error: unknown = null;
  private queue: Array<{ run: () => void; req: FakeReq }> = []; private writes: Array<() => void> = []; private done = false; private pumping = false;
  constructor(private db: FakeDB, readonly names: string[]) {}
  objectStore(name: string) {
    if (!this.names.includes(name)) throw new Error(`store ${name} is not in this transaction`);
    const m = this.db.stores[name]; const kp = this.db.keyPaths[name];
    const make = <T,>(run: (r: FakeReq<T>) => void): FakeReq<T> => { const r = new FakeReq<T>(); this.enqueue(() => { run(r); r.onsuccess?.(); }, r as FakeReq); return r; };
    return {
      get: (key: string) => make<Row | undefined>((r) => { r.result = m.get(key); }),
      put: (value: Row) => make<void>(() => { this.writes.push(() => m.set(String(value[kp]), value)); }),
      delete: (key: string) => make<void>(() => { this.writes.push(() => { m.delete(key); }); }),
    };
  }
  private enqueue(fn: () => void, req: FakeReq) { this.queue.push({ run: fn, req }); if (!this.pumping) { this.pumping = true; setTimeout(() => this.pump(), 0); } }
  private pump() {
    if (this.done) return;
    const next = this.queue.shift();
    if (next) { next.run(); if (!this.done) setTimeout(() => this.pump(), 0); return; }
    this.pumping = false; this.done = true;
    for (const w of this.writes) w();
    this.oncomplete?.();
  }
  abort() {
    if (this.done) return;
    this.done = true; this.writes = [];
    const pending = this.queue; this.queue = [];
    setTimeout(() => { for (const p of pending) { p.req.error = Object.assign(new Error('The transaction was aborted'), { name: 'AbortError' }); p.req.onerror?.(); } this.onabort?.(); }, 0);
  }
}
class FakeDB {
  stores: Record<string, Map<string, Row>> = { settings: new Map() };
  keyPaths: Record<string, string> = { settings: 'key' };
  transactions = 0;
  transaction(names: string | string[]) { this.transactions++; return new FakeTx(this, Array.isArray(names) ? names : [names]); }
  close() { /* the commit closes it */ }
}

const KEY = 'suppression:owner';
const row = (v: string, iv: string): SealedRow => ({ key: KEY, value: { iv, ciphertext: v } });

/** A record whose sealed form is `{iv, ciphertext: <the value>}`, so the test can read the value back without any crypto. */
function setup(opts: { initial?: SealedRow; unreadable?: boolean; beforeCommit?: (db: FakeDB) => void } = {}) {
  const db = new FakeDB();
  if (opts.initial) db.stores.settings.set(KEY, opts.initial as unknown as Row);
  let seals = 0;
  let reads = 0;
  const update = sealedRowUpdate<string>({
    settingKey: KEY,
    readRow: async () => { reads += 1; return (db.stores.settings.get(KEY) as unknown as SealedRow | undefined) ?? null; },
    openDb: async () => { opts.beforeCommit?.(db); return db as unknown as IDBDatabase; },
    decode: async (r): Promise<SealedRead<string>> => (r === null ? { state: 'absent' } : opts.unreadable ? { state: 'unreadable' } : { state: 'ok', value: r.value.ciphertext }),
    seal: async (v) => { seals += 1; return { iv: `iv${seals}`, ciphertext: v }; },
  });
  return { db, update, reads: () => reads, stored: () => (db.stores.settings.get(KEY) as unknown as SealedRow | undefined)?.value.ciphertext };
}
const once = (fn: (db: FakeDB) => void) => { let done = false; return (db: FakeDB) => { if (!done) { done = true; fn(db); } }; };
const landing = (v: string) => (db: FakeDB) => { db.stores.settings.set(KEY, row(v, 'concurrent') as unknown as Row); };

test('an unchanged row: the write is committed through the real commit, in one transaction', async () => {
  const t = setup({ initial: row('a', 'i0') });
  assert.equal(await t.update((held) => (held.state === 'ok' ? { write: `${held.value}+`, result: 'done' } : { result: 'no' })), 'done');
  assert.equal(t.stored(), 'a+');
  assert.equal(t.db.transactions, 1);
});

test('a write that lands BETWEEN the read and the commit makes the commit fail, and the decision runs again on the newer row', async () => {
  const t = setup({ initial: row('a', 'i0'), beforeCommit: once(landing('a-from-another-tab')) });
  const seen: string[] = [];
  await t.update((held) => { const v = held.state === 'ok' ? held.value : '?'; seen.push(v); return { write: `${v}+`, result: v }; });
  assert.deepEqual(seen, ['a', 'a-from-another-tab'], 'decided on the stale row, then on the newer one');
  assert.equal(t.stored(), 'a-from-another-tab+', 'the concurrent write was built on, not overwritten');
  assert.equal(t.db.transactions, 2, 'one aborted commit, one that applied');
});

test('an ABSENT row that another writer creates before the commit is a conflict, not an overwrite', async () => {
  const t = setup({ beforeCommit: once(landing('created-meanwhile')) });
  const seen: SealedRead<string>['state'][] = [];
  await t.update((held) => { seen.push(held.state); return held.state === 'ok' ? { write: `${held.value}+`, result: 1 } : { write: 'fresh', result: 2 }; });
  assert.deepEqual(seen, ['absent', 'ok']);
  assert.equal(t.stored(), 'created-meanwhile+');
});

test('a row that keeps changing is abandoned after the bounded attempts with NOTHING written by the update', async () => {
  let n = 0;
  const t = setup({ initial: row('a', 'i0'), beforeCommit: (db) => { n += 1; landing(`other${n}`)(db); } });
  await assert.rejects(() => t.update(() => ({ write: 'mine', result: 1 })), /changed too often while it was being updated; nothing was written/);
  assert.notEqual(t.stored(), 'mine');
  assert.equal(n, 5);
});

test('an UNREADABLE row is never overwritten: a write decided on it is refused before any transaction', async () => {
  const t = setup({ initial: row('garbage', 'i0'), unreadable: true });
  await assert.rejects(() => t.update(() => ({ write: 'x', result: 1 })), /Refusing to overwrite a sealed record that cannot be read/);
  assert.equal(t.stored(), 'garbage');
  assert.equal(t.db.transactions, 0);
});

test('a no-write decision opens no transaction and seals nothing', async () => {
  const t = setup({ initial: row('a', 'i0') });
  assert.equal(await t.update((held) => ({ result: held.state })), 'ok');
  assert.equal(t.db.transactions, 0);
  assert.equal(t.stored(), 'a');
});
