// commitIfUnchanged: the one transaction that re-reads the rows a write decided from and writes only if they are unchanged.
//
// Tested against a small in-memory fake of the IndexedDB surface it uses (transaction, objectStore get/put/delete, abort, the three tx
// callbacks). The fake applies writes only when the transaction completes and drops them on abort, and it completes the transaction only
// once its request queue has drained, as IndexedDB does. It cannot show real browser behaviour (auto-commit timing, cross-tab ordering):
// that is the Chromium run, e2e/contact-cas.spec.ts.
//
// Run: npx tsx --test src/lib/identity/commit-if-unchanged.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { commitIfUnchanged } from './client-store';

type Row = Record<string, unknown>;

class FakeReq<T = unknown> {
  result: T | undefined;
  error: unknown = null;
  onsuccess: (() => void) | null = null;
  onerror: (() => void) | null = null;
}

class FakeTx {
  oncomplete: (() => void) | null = null;
  onabort: (() => void) | null = null;
  onerror: (() => void) | null = null;
  error: unknown = null;
  private queue: Array<() => void> = [];
  private writes: Array<() => void> = [];
  private done = false;
  private pumping = false;
  constructor(private db: FakeDB, readonly names: string[]) {}

  objectStore(name: string) {
    if (!this.names.includes(name)) throw new Error(`store ${name} is not in this transaction`);
    const m = this.db.stores[name];
    const kp = this.db.keyPaths[name];
    const make = <T,>(run: (r: FakeReq<T>) => void, failWith?: unknown): FakeReq<T> => {
      const r = new FakeReq<T>();
      this.enqueue(() => {
        if (failWith !== undefined) { r.error = failWith; this.error = failWith; r.onerror?.(); this.abort(); return; }
        run(r);
        r.onsuccess?.();
      });
      return r;
    };
    return {
      get: (key: string) => make<Row | undefined>((r) => { r.result = m.get(key); }, this.db.failGet.has(`${name}:${key}`) ? new Error('get failed') : undefined),
      put: (value: Row) => make<void>(() => { this.writes.push(() => m.set(String(value[kp]), value)); }, this.db.failPut.has(name) ? new Error('put failed') : undefined),
      delete: (key: string) => make<void>(() => { this.writes.push(() => { m.delete(key); }); }),
    };
  }

  private enqueue(fn: () => void) {
    this.queue.push(fn);
    if (!this.pumping) { this.pumping = true; setTimeout(() => this.pump(), 0); }
  }

  private pump() {
    if (this.done) return;
    const next = this.queue.shift();
    if (next) { next(); if (!this.done) setTimeout(() => this.pump(), 0); return; }
    this.pumping = false;
    // the queue drained with nothing pending: the transaction commits, exactly as IndexedDB auto-commits
    this.done = true;
    for (const w of this.writes) w();
    this.oncomplete?.();
  }

  abort() {
    if (this.done) return;
    this.done = true;
    this.writes = [];
    this.queue = [];
    setTimeout(() => this.onabort?.(), 0);
  }
}

class FakeDB {
  stores: Record<string, Map<string, Row>> = { contacts: new Map(), settings: new Map() };
  keyPaths: Record<string, string> = { contacts: 'id', settings: 'key' };
  failGet = new Set<string>();
  failPut = new Set<string>();
  closed = false;
  transactions = 0;
  transaction(names: string | string[]) { this.transactions++; return new FakeTx(this, Array.isArray(names) ? names : [names]); }
  close() { this.closed = true; }
}

const asDb = (d: FakeDB) => d as unknown as IDBDatabase;
const env = (id: string, iv: string, ct = 'c'): Row => ({ id, owner_fingerprint: 'o', enc_version: 1, iv, ciphertext: ct });
const man = (value: string): Row => ({ key: 'contact_manifest:o', value });

function seeded(): FakeDB {
  const d = new FakeDB();
  d.stores.contacts.set('a', env('a', 'i1'));
  d.stores.settings.set('contact_manifest:o', man('m1'));
  return d;
}
const expects = (d: FakeDB) => [
  { store: 'contacts', key: 'a', expected: d.stores.contacts.get('a') ?? null },
  { store: 'settings', key: 'contact_manifest:o', expected: d.stores.settings.get('contact_manifest:o') ?? null },
];
const ops = () => [{ store: 'contacts', value: env('a', 'i2') }, { store: 'settings', value: man('m2') }];

test('unchanged rows: both writes are applied, in the one transaction, and the database is closed', async () => {
  const d = seeded();
  assert.equal(await commitIfUnchanged(asDb(d), expects(d), ops()), true);
  assert.equal(d.stores.contacts.get('a')!.iv, 'i2');
  assert.equal(d.stores.settings.get('contact_manifest:o')!.value, 'm2');
  assert.equal(d.transactions, 1);
  assert.equal(d.closed, true);
});

test('the contact envelope changed: nothing is written, the answer is false', async () => {
  const d = seeded();
  const ex = expects(d);
  d.stores.contacts.set('a', env('a', 'someone-else'));
  assert.equal(await commitIfUnchanged(asDb(d), ex, ops()), false);
  assert.equal(d.stores.contacts.get('a')!.iv, 'someone-else');
  assert.equal(d.stores.settings.get('contact_manifest:o')!.value, 'm1', 'the manifest was not written either');
  assert.equal(d.closed, true);
});

test('only the manifest changed: nothing is written, the answer is false', async () => {
  const d = seeded();
  const ex = expects(d);
  d.stores.settings.set('contact_manifest:o', man('m-other'));
  assert.equal(await commitIfUnchanged(asDb(d), ex, ops()), false);
  assert.equal(d.stores.contacts.get('a')!.iv, 'i1', 'the contact was not written');
  assert.equal(d.stores.settings.get('contact_manifest:o')!.value, 'm-other');
});

test('a row that was absent when read and is present now is a conflict; absent and still absent is not', async () => {
  const d = new FakeDB();
  d.stores.contacts.set('a', env('a', 'i1'));
  const ex = [{ store: 'contacts', key: 'a', expected: d.stores.contacts.get('a') ?? null }, { store: 'settings', key: 'contact_manifest:o', expected: null }];
  assert.equal(await commitIfUnchanged(asDb(d), ex, ops()), true, 'no manifest before, none now');
  const d2 = new FakeDB();
  d2.stores.contacts.set('a', env('a', 'i1'));
  d2.stores.settings.set('contact_manifest:o', man('created-meanwhile'));
  assert.equal(await commitIfUnchanged(asDb(d2), ex, ops()), false, 'a manifest appeared meanwhile');
});

test('a row that was present when read and is gone now is a conflict', async () => {
  const d = seeded();
  const ex = expects(d);
  d.stores.contacts.delete('a');
  assert.equal(await commitIfUnchanged(asDb(d), ex, ops()), false);
  assert.equal(d.stores.contacts.has('a'), false, 'a deleted contact is not resurrected');
});

test('a write error rejects (it is not reported as a conflict) and the transaction writes nothing', async () => {
  const d = seeded();
  d.failPut.add('settings');
  await assert.rejects(() => commitIfUnchanged(asDb(d), expects(d), ops()), /put failed/);
  assert.equal(d.stores.contacts.get('a')!.iv, 'i1');
  assert.equal(d.closed, true);
});

test('a read error rejects and writes nothing', async () => {
  const d = seeded();
  d.failGet.add('settings:contact_manifest:o');
  await assert.rejects(() => commitIfUnchanged(asDb(d), expects(d), ops()), /get failed/);
  assert.equal(d.stores.contacts.get('a')!.iv, 'i1');
});

test('the compare uses the rows as the TRANSACTION sees them, not an earlier read: a change after the caller read is caught', async () => {
  const d = seeded();
  const ex = expects(d);                     // what the caller read
  const p = commitIfUnchanged(asDb(d), ex, ops());
  d.stores.contacts.set('a', env('a', 'raced')); // a write lands after the call but before the transaction reads
  assert.equal(await p, false);
});

test('only the stores named are opened: a transaction over contacts and settings and no other', async () => {
  const d = seeded();
  const seen: string[][] = [];
  const orig = d.transaction.bind(d);
  d.transaction = (names: string | string[]) => { seen.push([...(Array.isArray(names) ? names : [names])].sort()); return orig(names); };
  await commitIfUnchanged(asDb(d), expects(d), ops());
  assert.deepEqual(seen, [['contacts', 'settings']]);
});
