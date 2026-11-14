import { test, expect, type Page } from '@playwright/test';
import { build } from 'esbuild';
import { join } from 'node:path';

/**
 * #822 (a) P1: updateBeaconSeeds (client-store.ts) on the REAL code, a REAL IndexedDB and REAL AES-GCM in a real browser, bundled like beacon-ports-idb.spec.ts (client-store has no
 * fake-indexeddb harness; ONE package is stubbed: circomlibjs, imported by beacon-key.ts and never called here). What it proves, which the pure unit tests cannot:
 *  - an ABSENT map is the one allowed starting point; the map at rest is ciphertext (no seed marker);
 *  - concurrent updates all LAND (a compare-and-swap in one transaction), and a CONTROL (the old blind get -> wait -> setBeaconSeeds) LOSES updates, so this harness can tell the difference.
 *    Six writers, not twenty: a lost race re-reads and retries up to 8 times and at least one writer wins each round, so 8 attempts always cover six; real contention here is one tab and a
 *    handful of rows;
 *  - a row that EXISTS but cannot be opened (damaged, or sealed under another passphrase) makes the update THROW and leaves the row byte-for-byte as it was. The old blind setBeaconSeeds
 *    over the same state overwrites it (the control), which is the defect this helper replaces;
 *  - a locked session throws and writes nothing; a mutate that returns a malformed map throws and writes nothing.
 */
let bundle = '';
test.beforeAll(async () => {
  const out = await build({
    stdin: {
      contents: `import { updateBeaconSeeds, getBeaconSeeds, setBeaconSeeds, initSessionKey, lockSession } from '@/lib/identity/client-store';\n(window as any).__h = { updateBeaconSeeds, getBeaconSeeds, setBeaconSeeds, initSessionKey, lockSession };`,
      resolveDir: process.cwd(),
      loader: 'ts',
    },
    bundle: true, format: 'iife', platform: 'browser', write: false, logLevel: 'silent',
    alias: { '@': join(process.cwd(), 'src') },
    define: { 'process.env': '{}' },
    plugins: [{
      name: 'stub-circomlibjs',
      setup(b) {
        b.onResolve({ filter: /^circomlibjs$/ }, () => ({ path: 'circomlibjs', namespace: 'stub' }));
        b.onLoad({ filter: /.*/, namespace: 'stub' }, () => ({ contents: 'module.exports = {};', loader: 'js' }));
      },
    }],
  });
  bundle = out.outputFiles[0].text;
});

const RAW = `
(() => {
  const open = async () => {
    const dbs = await indexedDB.databases();
    if (dbs.length !== 1) throw new Error('expected exactly one database, got ' + dbs.length);
    return new Promise((res, rej) => { const r = indexedDB.open(dbs[0].name); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
  };
  const run = async (mode, f) => { const db = await open(); try { return await new Promise((res, rej) => { const tx = db.transaction('settings', mode); const q = f(tx.objectStore('settings')); tx.oncomplete = () => res(q.result); tx.onerror = () => rej(tx.error); }); } finally { db.close(); } };
  window.__raw = {
    get: (key) => run('readonly', (s) => s.get(key)),
    put: (key, value) => run('readwrite', (s) => s.put({ key, value })),
  };
})();`;

// a valid seed entry: five fields, canonical decimals, a 32-byte seed in base64 (44 chars with one '=')
const ENTRY = `(i) => { const bytes = new Uint8Array(32).fill(i + 1); let s = ''; for (const b of bytes) s += String.fromCharCode(b); return { epoch: '7', H_e: String(1000 + i), N: String(2000 + i), seed: btoa(s), expiresAtMs: 9999999999999 }; }`;
const KEY = `(i) => (1000 + i) + ':' + (2000 + i)`;
const ROW = 'beacon_seeds:alice';

async function harness(page: Page): Promise<void> {
  await page.route('**/__beacon_seeds_harness__', (r) => r.fulfill({ contentType: 'text/html', body: '<!doctype html><title>harness</title>' }));
  await page.goto('/__beacon_seeds_harness__');
  await page.addScriptTag({ content: bundle });
  await page.addScriptTag({ content: RAW });
}

test('ABSENT is the allowed start: an update creates the map, it reads back, the row at rest is ciphertext, and a second update adds and removes', async ({ page }) => {
  await harness(page);
  const r = await page.evaluate(async ([entrySrc, keySrc]) => {
    const w = window as any; const entry = eval(entrySrc), key = eval(keySrc);
    await w.__h.initSessionKey('pw');
    const out: any = {};
    out.before = (await w.__raw.get('beacon_seeds:alice')) ?? 'none';
    out.created = Object.keys(await w.__h.updateBeaconSeeds('alice', (cur: any) => ({ ...cur, [key(0)]: entry(0) })));
    out.read = Object.keys((await w.__h.getBeaconSeeds('alice')) ?? {});
    const row = await w.__raw.get('beacon_seeds:alice');
    const text = JSON.stringify(row?.value);
    out.hasCiphertext = text.includes('ciphertext');
    out.hasSeedMarker = text.includes(entry(0).seed) || text.includes('"expiresAtMs"') || text.includes('"H_e"');
    out.second = Object.keys(await w.__h.updateBeaconSeeds('alice', (cur: any) => { const n = { ...cur, [key(1)]: entry(1) }; delete n[key(0)]; return n; })).sort();
    out.otherOwner = (await w.__h.getBeaconSeeds('bob')) ?? 'null';
    return out;
  }, [ENTRY, KEY]);
  expect(r.before).toBe('none');
  expect(r.created).toEqual(['1000:2000']);
  expect(r.read).toEqual(['1000:2000']);
  expect(r.hasCiphertext).toBe(true);
  expect(r.hasSeedMarker).toBe(false);          // nothing in the row at rest names a seed or a slot
  expect(r.second).toEqual(['1001:2001']);
  expect(r.otherOwner).toBe('null');
});

test('six concurrent updates ALL land; CONTROL: the old blind get -> wait -> setBeaconSeeds loses updates, so the harness can tell the difference', async ({ page }) => {
  await harness(page);
  const r = await page.evaluate(async ([entrySrc, keySrc]) => {
    const w = window as any; const entry = eval(entrySrc), key = eval(keySrc);
    await w.__h.initSessionKey('pw');
    const out: any = {};
    await Promise.all(Array.from({ length: 6 }, (_, i) => w.__h.updateBeaconSeeds('alice', (cur: any) => ({ ...cur, [key(i)]: entry(i) }))));
    out.landed = Object.keys((await w.__h.getBeaconSeeds('alice')) ?? {}).length;
    // CONTROL on a different owner: six writers each read, wait, then blindly write their own addition
    await Promise.all(Array.from({ length: 6 }, async (_, i) => {
      const cur = (await w.__h.getBeaconSeeds('carol')) ?? {};
      await new Promise((res) => setTimeout(res, 20));
      await w.__h.setBeaconSeeds('carol', { ...cur, [key(i)]: entry(i) });
    }));
    out.control = Object.keys((await w.__h.getBeaconSeeds('carol')) ?? {}).length;
    return out;
  }, [ENTRY, KEY]);
  expect(r.landed).toBe(6);                      // none lost
  expect(r.control).toBeLessThan(6);             // the blind put DOES lose some: the difference is visible
});

test('a row that EXISTS but cannot be opened: the update THROWS and the row is left byte-for-byte; the old blind setBeaconSeeds overwrites it (the control, the defect)', async ({ page }) => {
  await harness(page);
  const r = await page.evaluate(async ([entrySrc, keySrc]) => {
    const w = window as any; const entry = eval(entrySrc), key = eval(keySrc);
    await w.__h.initSessionKey('pw');
    await w.__h.updateBeaconSeeds('alice', (cur: any) => ({ ...cur, [key(0)]: entry(0) }));
    const good = await w.__raw.get('beacon_seeds:alice');
    // damage it: a ciphertext that cannot decrypt
    await w.__raw.put('beacon_seeds:alice', { iv: 'AAAAAAAAAAAAAAAA', ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', enc_version: 2 });
    const damaged = JSON.stringify(await w.__raw.get('beacon_seeds:alice'));
    const out: any = {};
    out.readNull = (await w.__h.getBeaconSeeds('alice')) === null;                // absent and unreadable are conflated here: the reason for the new helper
    out.updateThrows = await w.__h.updateBeaconSeeds('alice', (cur: any) => ({ ...cur, [key(1)]: entry(1) })).then(() => 'wrote', (e: Error) => e.name + ': ' + e.message);
    out.untouched = JSON.stringify(await w.__raw.get('beacon_seeds:alice')) === damaged;
    // CONTROL: the blind put over the same state silently overwrites it
    await w.__h.setBeaconSeeds('alice', { [key(2)]: entry(2) });
    out.controlOverwrote = JSON.stringify(await w.__raw.get('beacon_seeds:alice')) !== damaged;
    out.goodWasDifferent = JSON.stringify(good) !== damaged;
    return out;
  }, [ENTRY, KEY]);
  expect(r.goodWasDifferent).toBe(true);
  expect(r.readNull).toBe(true);
  expect(String(r.updateThrows)).toMatch(/OperationError|not readable|not a valid|refusing to overwrite/); // AES-GCM's decrypt failure is a DOMException named OperationError with an empty message
  expect(r.untouched).toBe(true);
  expect(r.controlOverwrote).toBe(true);
});

test('a valid row sealed under ANOTHER passphrase is unreadable: the update throws and leaves it; a locked session throws and writes nothing; a malformed mutate writes nothing', async ({ page }) => {
  await harness(page);
  const r = await page.evaluate(async ([entrySrc, keySrc]) => {
    const w = window as any; const entry = eval(entrySrc), key = eval(keySrc);
    await w.__h.initSessionKey('pw');
    await w.__h.updateBeaconSeeds('alice', (cur: any) => ({ ...cur, [key(0)]: entry(0) }));
    const sealed = JSON.stringify(await w.__raw.get('beacon_seeds:alice'));
    const out: any = {};
    w.__h.lockSession();
    out.lockedThrows = await w.__h.updateBeaconSeeds('alice', (c: any) => c).then(() => 'wrote', (e: Error) => e.name + ': ' + e.message);
    out.lockedUntouched = JSON.stringify(await w.__raw.get('beacon_seeds:alice')) === sealed;
    await w.__h.initSessionKey('a-different-passphrase');
    out.wrongPassThrows = await w.__h.updateBeaconSeeds('alice', (cur: any) => ({ ...cur, [key(1)]: entry(1) })).then(() => 'wrote', (e: Error) => e.name + ': ' + e.message);
    out.wrongPassUntouched = JSON.stringify(await w.__raw.get('beacon_seeds:alice')) === sealed;
    w.__h.lockSession(); await w.__h.initSessionKey('pw');
    out.malformedThrows = await w.__h.updateBeaconSeeds('alice', () => ({ 'not-a-key': { epoch: 'x' } })).then(() => 'wrote', (e: Error) => e.name + ': ' + e.message);
    out.malformedUntouched = JSON.stringify(await w.__raw.get('beacon_seeds:alice')) === sealed;
    out.backIntact = Object.keys((await w.__h.getBeaconSeeds('alice')) ?? {});
    return out;
  }, [ENTRY, KEY]);
  expect(String(r.lockedThrows)).toMatch(/locked/i);
  expect(r.lockedUntouched).toBe(true);
  expect(String(r.wrongPassThrows)).toMatch(/OperationError|not readable|not a valid|refusing to overwrite/);
  expect(r.wrongPassUntouched).toBe(true);
  expect(String(r.malformedThrows)).toMatch(/malformed/i);
  expect(r.malformedUntouched).toBe(true);
  expect(r.backIntact).toEqual(['1000:2000']);      // the right passphrase reads the original back, unharmed
});
