import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * #588 D1: ensureBeaconKeyRecord / importBeaconKeyRecord rely on txAdd being an ATOMIC create-if-absent (two tabs racing to create the same record must end
 * with ONE record, and a restore must never overwrite a held one). client-store has no fake-indexeddb harness, so this takes the REAL txAdd source text out of
 * client-store.ts and runs it in a real browser against a scratch IndexedDB database (not the app's), with openDB stubbed to open that scratch database.
 */
const SRC = readFileSync(join(process.cwd(), 'src/lib/identity/client-store.ts'), 'utf8');
const start = SRC.indexOf('async function txAdd<T>');
const body = SRC.slice(start, SRC.indexOf('\nasync function txDelete', start)).replace('async function txAdd<T>(storeName: string, value: T): Promise<\'added\' | \'exists\'>', 'async function txAdd(storeName, value)');

test('txAdd is create-if-absent: exists on a second add, never overwrites, and exactly ONE of 20 concurrent adds wins', async ({ page }) => {
  expect(start).toBeGreaterThan(0);
  await page.goto('/');
  const result = await page.evaluate(async (fnSource) => {
    const DB = 'scratch-txadd-' + Math.random().toString(36).slice(2);
    const openDB = () => new Promise<IDBDatabase>((resolve, reject) => {
      const r = indexedDB.open(DB, 1);
      r.onupgradeneeded = () => { r.result.createObjectStore('settings', { keyPath: 'key' }); };
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
    // eslint-disable-next-line no-new-func
    const txAdd = new Function('openDB', fnSource + '\nreturn txAdd;')(openDB) as (s: string, v: unknown) => Promise<'added' | 'exists'>;
    const read = async (key: string) => new Promise<any>(async (resolve) => {
      const db = await openDB(); const q = db.transaction('settings', 'readonly').objectStore('settings').get(key); q.onsuccess = () => { resolve(q.result); db.close(); };
    });
    const first = await txAdd('settings', { key: 'k1', value: 'first' });
    const second = await txAdd('settings', { key: 'k1', value: 'second' });
    const afterTwo = (await read('k1')).value;
    const other = await txAdd('settings', { key: 'k2', value: 'other' });
    const racers = await Promise.all(Array.from({ length: 20 }, (_, i) => txAdd('settings', { key: 'race', value: 'racer-' + i })));
    const winner = (await read('race')).value;
    return { first, second, afterTwo, other, wins: racers.filter((r) => r === 'added').length, exists: racers.filter((r) => r === 'exists').length, winner };
  }, body);
  expect(result.first).toBe('added');
  expect(result.second).toBe('exists');
  expect(result.afterTwo).toBe('first');          // the held value was NOT overwritten
  expect(result.other).toBe('added');             // a different key is unaffected
  expect(result.wins).toBe(1);                    // exactly one racer created it
  expect(result.exists).toBe(19);
  expect(String(result.winner)).toMatch(/^racer-\d+$/);
});

test('CONTROL: the same race with a blind put (what ensure would be if it used txPut) ends with 20 "writes", so the test can tell the difference', async ({ page }) => {
  await page.goto('/');
  const wins = await page.evaluate(async () => {
    const DB = 'scratch-txput-' + Math.random().toString(36).slice(2);
    const openDB = () => new Promise<IDBDatabase>((resolve, reject) => {
      const r = indexedDB.open(DB, 1);
      r.onupgradeneeded = () => { r.result.createObjectStore('settings', { keyPath: 'key' }); };
      r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error);
    });
    const put = async (v: unknown) => { const db = await openDB(); return new Promise<'added'>((res, rej) => { const tx = db.transaction('settings', 'readwrite'); tx.objectStore('settings').put(v); tx.oncomplete = () => { db.close(); res('added'); }; tx.onerror = () => rej(tx.error); }); };
    const rs = await Promise.all(Array.from({ length: 20 }, (_, i) => put({ key: 'race', value: 'racer-' + i })));
    return rs.filter((r) => r === 'added').length;
  });
  expect(wins).toBe(20);
});
