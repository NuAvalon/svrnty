import { test, expect, type Page } from '@playwright/test';
import { build } from 'esbuild';
import { join } from 'node:path';

/**
 * #822 (a) S1b: createBeaconPorts (client-store.ts) on the REAL code, a REAL IndexedDB and REAL AES-GCM in a real browser. client-store has no fake-indexeddb
 * harness, so this bundles the REAL module with esbuild and runs it in a bare same-origin page (the app itself is not loaded). Each test gets a fresh browser
 * context, so a fresh database. ONE package is stubbed in the bundle: circomlibjs (Poseidon, imported by beacon-key.ts and never called here). The unit tests (src/lib/trust/beacon-ports.test.ts) hold the rules over fakes; this file proves the glue under them:
 *  - a write is one compare-and-swap transaction: of 20 concurrent writers of the same version exactly ONE wins, and a CONTROL (read, wait, then put) shows
 *    the same race DOES let several through, so the harness can tell the difference;
 *  - the row at rest is ciphertext (no plaintext marker), keyed by owner and pair;
 *  - a tampered row, a row moved to another pair's key, a row moved to another owner's key, a locked session and a wrong passphrase all THROW on the store
 *    and read 'removed' on the latch, and none of them is read as "absent";
 *  - a failed latch write (locked) leaves nothing behind, and the right passphrase afterwards reads the original record back unharmed.
 */
let bundle = '';
test.beforeAll(async () => {
  const out = await build({
    stdin: {
      contents: `import { createBeaconPorts, initSessionKey, lockSession } from '@/lib/identity/client-store';\n(window as any).__h = { createBeaconPorts, initSessionKey, lockSession };`,
      resolveDir: process.cwd(),
      loader: 'ts',
    },
    bundle: true, format: 'iife', platform: 'browser', write: false, logLevel: 'silent',
    alias: { '@': join(process.cwd(), 'src') },
    define: { 'process.env': '{}' },
    plugins: [{
      // The ONE stub: circomlibjs (the Poseidon hash behind beacon-key.ts) needs Node built-ins a browser bundle does not have, and this harness never calls it.
      name: 'stub-circomlibjs',
      setup(b) {
        b.onResolve({ filter: /^circomlibjs$/ }, () => ({ path: 'circomlibjs', namespace: 'stub' }));
        b.onLoad({ filter: /.*/, namespace: 'stub' }, () => ({ contents: 'module.exports = {};', loader: 'js' }));
      },
    }],
  });
  bundle = out.outputFiles[0].text;
});

// Raw access to the settings store of whatever database the module opened, so a test can read what is AT REST and plant a damaged row.
const RAW = `
(() => {
  const open = async () => {
    const dbs = await indexedDB.databases();
    if (dbs.length !== 1) throw new Error('expected exactly one database, got ' + dbs.length);
    return new Promise((res, rej) => { const r = indexedDB.open(dbs[0].name); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
  };
  const run = async (mode, f) => { const db = await open(); try { return await new Promise((res, rej) => { const tx = db.transaction('settings', mode); const q = f(tx.objectStore('settings')); tx.oncomplete = () => res(q && q.result); tx.onerror = () => rej(tx.error); tx.onabort = () => rej(tx.error); }); } finally { db.close(); } };
  window.__raw = {
    get: (key) => run('readonly', (s) => s.get(key)),
    put: (key, value) => run('readwrite', (s) => s.put({ key, value })),
    keys: () => run('readonly', (s) => s.getAllKeys()),
  };
})();`;

async function harness(page: Page): Promise<void> {
  await page.route('**/__beacon_ports_harness__', (r) => r.fulfill({ contentType: 'text/html', body: '<!doctype html><title>harness</title>' }));
  await page.goto('/__beacon_ports_harness__');
  await page.addScriptTag({ content: bundle });
  await page.addScriptTag({ content: RAW });
}

const REC = `(pairId, version, who) => ({ pairId, observedMatch: false, spentEpochs: [], refusedEpochs: [], rows: [{ note: 'PLAINTEXT-MARKER-4d1c9e', who }], pendingWithdraws: [], version })`;

test('a pair record round-trips through the real database: compare-and-swap by version, ciphertext at rest, owners kept apart', async ({ page }) => {
  await harness(page);
  const r = await page.evaluate(async (recSrc) => {
    const w = window as any; const rec = eval(recSrc);
    await w.__h.initSessionKey('pw');
    const a = w.__h.createBeaconPorts('alice').store; const bob = w.__h.createBeaconPorts('bob').store;
    const out: any = {};
    out.absent = (await a.get('pair-1')) ?? 'undefined';
    out.create = await a.cas('pair-1', 0, rec('pair-1', 1, 'a'));
    out.createAgain = await a.cas('pair-1', 0, rec('pair-1', 1, 'b'));   // stale: version 0 is no longer current
    out.read1 = (await a.get('pair-1'))?.rows?.[0]?.who;
    out.update = await a.cas('pair-1', 1, rec('pair-1', 2, 'c'));
    out.staleUpdate = await a.cas('pair-1', 1, rec('pair-1', 2, 'd'));
    out.read2 = (await a.get('pair-1'))?.version;
    out.pairsAlice = (await a.pairs()).length;
    out.pairsBob = (await bob.pairs()).length;
    out.bobGet = (await bob.get('pair-1')) ?? 'undefined';
    const row = await w.__raw.get('beacon_pair:alice:pair-1');
    out.rowKey = row?.key; out.rowIsString = typeof row?.value === 'string';
    out.rowHasMarker = String(row?.value).includes('PLAINTEXT-MARKER-4d1c9e') || String(row?.value).includes('"who"');
    out.rowHasCiphertext = String(row?.value).includes('ciphertext');
    out.putThrows = await a.put({}).then(() => 'wrote', (e: Error) => e.message);
    return out;
  }, REC);
  expect(r.absent).toBe('undefined');
  expect(r.create).toBe(true);
  expect(r.createAgain).toBe(false);
  expect(r.read1).toBe('a');            // the loser did not overwrite the winner
  expect(r.update).toBe(true);
  expect(r.staleUpdate).toBe(false);
  expect(r.read2).toBe(2);
  expect(r.pairsAlice).toBe(1);
  expect(r.pairsBob).toBe(0);           // another owner on the same device sees nothing
  expect(r.bobGet).toBe('undefined');
  expect(r.rowKey).toBe('beacon_pair:alice:pair-1');
  expect(r.rowIsString).toBe(true);
  expect(r.rowHasCiphertext).toBe(true);
  expect(r.rowHasMarker).toBe(false);   // nothing readable at rest
  expect(r.putThrows).toMatch(/plain put is not supported/);
});

test('exactly ONE of 20 concurrent writers of the same version wins; CONTROL: a read-wait-put version lets many through', async ({ page }) => {
  await harness(page);
  const r = await page.evaluate(async (recSrc) => {
    const w = window as any; const rec = eval(recSrc);
    await w.__h.initSessionKey('pw');
    const a = w.__h.createBeaconPorts('alice').store;
    const wins = (await Promise.all(Array.from({ length: 20 }, (_, i) => a.cas('race', 0, rec('race', 1, 'racer-' + i))))).filter(Boolean).length;
    const winner = (await a.get('race'))?.rows?.[0]?.who;
    // CONTROL: the check-then-act version of the same write (read the row, wait, then put if it was absent) on the same real database.
    const ctl = await Promise.all(Array.from({ length: 20 }, async (_, i) => {
      const seen = await w.__raw.get('ctl-row');
      await new Promise((res) => setTimeout(res, 15));
      if (seen === undefined) { await w.__raw.put('ctl-row', 'racer-' + i); return true; }
      return false;
    }));
    return { wins, winner, version: (await a.get('race'))?.version, ctlWins: ctl.filter(Boolean).length };
  }, REC);
  expect(r.wins).toBe(1);
  expect(String(r.winner)).toMatch(/^racer-\d+$/);
  expect(r.version).toBe(1);
  expect(r.ctlWins).toBeGreaterThan(1);   // the same 20-way race, done wrong, lets several through: so the harness CAN interleave
});

test('damaged, moved, locked and wrong-passphrase rows THROW on the store and read removed on the latch; none reads as absent', async ({ page }) => {
  await harness(page);
  const r = await page.evaluate(async (recSrc) => {
    const w = window as any; const rec = eval(recSrc);
    const threw = (p: Promise<unknown>) => p.then(() => 'returned', () => 'threw');
    await w.__h.initSessionKey('pw');
    const a = w.__h.createBeaconPorts('alice'); const bob = w.__h.createBeaconPorts('bob');
    await a.store.cas('pair-1', 0, rec('pair-1', 1, 'a'));
    await a.latch.setLatched('pair-9', 'local');
    const out: any = { latchSet: await a.latch.kindOf('pair-9') };
    const good = (await w.__raw.get('beacon_pair:alice:pair-1')).value as string;
    const goodLatch = (await w.__raw.get('beacon_latch:alice:local:pair-9')).value as string;
    // 1. a tampered ciphertext
    const p = JSON.parse(good); p.ciphertext = p.ciphertext.slice(0, -4) + (p.ciphertext.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA');
    await w.__raw.put('beacon_pair:alice:pair-1', JSON.stringify(p));
    out.tamperGet = await threw(a.store.get('pair-1')); out.tamperPairs = await threw(a.store.pairs()); out.tamperCas = await threw(a.store.cas('pair-1', 1, rec('pair-1', 2, 'x')));
    await w.__raw.put('beacon_pair:alice:pair-1', good);
    // 2. a good blob moved onto another PAIR's key, and onto another OWNER's key
    await w.__raw.put('beacon_pair:alice:pair-3', good);
    out.movedPair = await threw(a.store.get('pair-3'));
    await w.__raw.put('beacon_pair:bob:pair-1', good);
    out.movedOwner = await threw(bob.store.get('pair-1'));
    // 3. a damaged latch row reads 'removed' (the restrictive answer), and so does one that is not even JSON
    await w.__raw.put('beacon_latch:alice:local:pair-9', 'not json at all');
    out.latchGarbage = await a.latch.kindOf('pair-9', 'local');
    await w.__raw.put('beacon_latch:alice:local:pair-9', goodLatch);
    // 4. locked session: the store cannot read or write; the latch row that exists still reads removed; a latch WRITE fails and leaves no row
    w.__h.lockSession();
    out.lockedGet = await threw(a.store.get('pair-1')); out.lockedCas = await threw(a.store.cas('pair-1', 1, rec('pair-1', 2, 'x')));
    out.lockedLatchExisting = await a.latch.kindOf('pair-9', 'local');
    out.lockedSetLatch = await threw(a.latch.setLatched('pair-7', 'local'));
    out.lockedSetLatchMsg = await a.latch.setLatched('pair-7', 'local').then(() => 'wrote', (e: Error) => e.message);
    out.lockedKeys = (await w.__raw.keys()).filter((k: string) => k.startsWith('beacon_latch:alice:local:pair-7')).length;
    // 5. the wrong passphrase is a tag failure, never "absent"
    await w.__h.initSessionKey('wrong');
    out.wrongGet = await threw(a.store.get('pair-1')); out.wrongLatch = await a.latch.kindOf('pair-9', 'local');
    // 6. the right passphrase reads the original back: nothing above damaged it
    w.__h.lockSession(); await w.__h.initSessionKey('pw');
    out.backWho = (await a.store.get('pair-1'))?.rows?.[0]?.who; out.backVersion = (await a.store.get('pair-1'))?.version;
    out.backLatch = await a.latch.kindOf('pair-9', 'local');
    // 7. the latch can be cleared, and that sticks
    await a.latch.clearLatched('pair-9', 'local'); out.cleared = await a.latch.kindOf('pair-9');
    return out;
  }, REC);
  expect(r.latchSet).toBe('removed');
  expect([r.tamperGet, r.tamperPairs, r.tamperCas]).toEqual(['threw', 'threw', 'threw']);
  expect(r.movedPair).toBe('threw');
  expect(r.movedOwner).toBe('threw');
  expect(r.latchGarbage).toBe('removed');
  expect([r.lockedGet, r.lockedCas]).toEqual(['threw', 'threw']);
  expect(r.lockedLatchExisting).toBe('removed');
  expect(r.lockedSetLatch).toBe('threw');
  expect(r.lockedSetLatchMsg).toMatch(/Session locked/);   // refused for the RIGHT reason, not by an accident further down
  expect(r.lockedKeys).toBe(0);          // the failed write left no row behind
  expect(r.wrongGet).toBe('threw');
  expect(r.wrongLatch).toBe('removed');
  expect(r.backWho).toBe('a');
  expect(r.backVersion).toBe(1);
  expect(r.backLatch).toBe('removed');
  expect(r.cleared).toBeNull();
});

test('a row whose value is missing, not a string, or not a sealed blob is UNREADABLE: the store throws and the latch reads removed, never "absent" or "not latched"', async ({ page }) => {
  await harness(page);
  const r = await page.evaluate(async () => {
    const w = window as any;
    await w.__h.initSessionKey('pw');
    const a = w.__h.createBeaconPorts('alice');
    const out: any = {};
    for (const [name, v] of [['missing', undefined], ['null', null], ['number', 5], ['object', { iv: 'x', ciphertext: 'y' }], ['no_iv', '{"x":1}'], ['not_json', 'zzz']] as const) {
      await w.__raw.put('beacon_pair:alice:pair-1', v);
      out['store_' + name] = await a.store.get('pair-1').then((x: unknown) => 'returned:' + String(x), () => 'threw');
      await w.__raw.put('beacon_latch:alice:local:pair-9', v);
      out['latch_' + name] = await a.latch.kindOf('pair-9', 'local');
    }
    return out;
  });
  for (const name of ['missing', 'null', 'number', 'object', 'no_iv', 'not_json']) {
    expect(r['store_' + name]).toBe('threw');       // never "returned:undefined" (= absent), which a later write would overwrite
    expect(r['latch_' + name]).toBe('removed');     // never null (= not latched), which would let a request through
  }
});
