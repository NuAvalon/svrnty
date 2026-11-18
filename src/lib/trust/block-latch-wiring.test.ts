// src/lib/trust/block-latch-wiring.test.ts
// The WIRING of block-latch.ts, and the dark proof.
//   · DARK PROOF: with a fetch spy, Block / Remove / the restore rebuild / the start-up pass make ZERO requests while the REAL latch (createBeaconLatch over an
//     in-memory store, a sealer that binds its AAD) writes its rows.
//   · SOURCE GUARDS: both screens (the contact book AND the trust map in app/page.tsx) go through the shared helpers and never touch the latch or the suppression write themselves;
//     the importers of block-latch and block-latch-wiring are an allow-list; sample data never reaches the user Remove path; Unblock cannot clear a latch; the
//     unlock repair, the restore re-latch and the export gate are in the order the design says.
// Run: npx tsx --test src/lib/trust/block-latch-wiring.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createBeaconLatch, type BeaconKV, type Sealer } from '@/lib/trust/beacon-ports';
import { VAULT_EXPORT_BLOCKS_REFUSED } from '@/components/export/vault-export-copy';
import { blockWithLatch, removeWithLatch, rebuildLatchesFromCarry, relatchFromRecord } from '@/lib/trust/block-latch';

const OWNER = 'f'.repeat(64);
const [P1, P2, P3, P4] = ['1', '2', '3', '4'].map((c) => c.repeat(64));
const pairIdFor = async (id: string) => `pair-${id.slice(0, 8)}`;

// ---------------------------------------------------------------- the dark proof (real latch, fetch spy)

function memKV(): { kv: BeaconKV; data: Map<string, string> } {
  const data = new Map<string, string>();
  const kv: BeaconKV = {
    async get(k) { return data.get(k); },
    async swap(k, expected, next) {
      if (data.get(k) !== expected) return false;
      if (next === undefined) data.delete(k); else data.set(k, next);
      return true;
    },
    async keys(prefix) { return [...data.keys()].filter((k) => k.startsWith(prefix)); },
  };
  return { kv, data };
}

/** Binds the AAD for real: a blob opened under another AAD throws. */
const sealer: Sealer = {
  async seal(aad, value) { return Buffer.from(`${aad}\u0000${JSON.stringify(value)}`).toString('base64'); },
  async open(aad, blob) {
    const [a, v] = Buffer.from(blob, 'base64').toString('utf8').split('\u0000');
    if (a !== aad) throw new Error('wrong aad');
    return JSON.parse(v);
  },
};

test('DARK PROOF: Block, Remove, the restore rebuild and the start-up pass make 0 requests, and the REAL latch rows are written', async () => {
  const calls: unknown[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (...args: unknown[]) => { calls.push(args); throw new Error('no network in a dark test'); }) as typeof fetch;
  try {
    const { kv, data } = memKV();
    const latch = createBeaconLatch(kv, sealer, OWNER);
    await blockWithLatch({ peerDurableId: P1, pairIdFor, latch, writeBlockFlag: async () => undefined, applySuppression: async () => ({ wrote: true, outcome: 'added' as const }) });
    await removeWithLatch({ durableId: P2, pairIdFor, latch, recordRemoved: async () => undefined, removeContactRecord: async () => undefined });
    const rebuilt = await rebuildLatchesFromCarry({ bookIds: [], persons: [P3], removed: [], pairIdFor, latch });
    const startup = await relatchFromRecord({ readBookIds: async () => [], readPersons: async () => [P4], readRemoved: async () => [], pairIdFor, latch });
    assert.equal(calls.length, 0, 'no beacon request of any kind');
    assert.equal(rebuilt.ok, true);
    assert.equal(startup.outcome, 'relatched');
    for (const id of [P1, P2, P3, P4]) assert.equal(await latch.kindOf(await pairIdFor(id), 'local'), 'removed', `the latch for ${id.slice(0, 1)} is set (kind removed)`);
    assert.equal((await kv.keys('beacon_latch:')).length, 4, 'four sealed latch rows, nothing else written under another prefix');
    assert.deepEqual([...data.keys()].filter((k) => !k.startsWith('beacon_latch:')), []);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('the REAL latch: the start-up pass does not rewrite an id that is already latched (idempotent, no second row, no write)', async () => {
  const { kv } = memKV();
  const latch = createBeaconLatch(kv, sealer, OWNER);
  await latch.setLatched(await pairIdFor(P1), 'local');
  const before = [...(await kv.keys('beacon_latch:'))].sort();
  const r = await relatchFromRecord({ readBookIds: async () => [], readPersons: async () => [P1], readRemoved: async () => [], pairIdFor, latch });
  assert.equal(r.outcome, 'nothing-to-do');
  assert.deepEqual([...(await kv.keys('beacon_latch:'))].sort(), before);
});

// ---------------------------------------------------------------- source guards

const ROOT = process.cwd();
const read = (rel: string): string => readFileSync(join(ROOT, rel), 'utf8');
const codeOnly = (text: string): string => text.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
const walk = (dir: string): string[] => readdirSync(dir).flatMap((f) => {
  const p = join(dir, f);
  if (statSync(p).isDirectory()) return f === 'node_modules' || f === '.next' ? [] : walk(p);
  return /\.(ts|tsx)$/.test(f) && !/\.test\.(ts|tsx)$/.test(f) ? [p] : [];
});
const rel = (f: string): string => f.slice(ROOT.length + 1);
const nonTest = ['src', 'app'].flatMap((d) => { try { return walk(join(ROOT, d)); } catch { return []; } });
const importersOf = (needle: string): string[] => nonTest.filter((f) => codeOnly(readFileSync(f, 'utf8')).includes(needle)).map(rel).sort();

test('S1 BOTH screens (the contact book and the trust map) go through the shared helpers, and never touch the latch or the suppression write themselves', () => {
  for (const file of ['src/components/ContactManagement.tsx', 'app/page.tsx']) {
    const c = codeOnly(read(file));
    assert.match(c, /removeContactWithLatch\(/, `${file}: Remove goes through the helper`);
    assert.match(c, /setContactBlocked\(/, `${file}: Block and Unblock go through the helper`);
    assert.match(c, /if \(!finished\) throw new BlockUnfinishedError\(\);/, `${file}: a Block whose record write did not finish is THROWN (after the refresh), so the existing catch words it`);
    for (const forbidden of ['setLatched', 'clearLatched', 'applyBlockSuppression', 'block-suppression', 'recordRemovedContact']) {
      assert.ok(!c.includes(forbidden), `${file} must not name ${forbidden} (the helper owns it)`);
    }
  }
});

test('S2 importers: block-latch-wiring is imported only by the two screens; block-latch only by the wiring, the identity store (repair) and the export copy (the error class)', () => {
  // the module path with its closing quote, in either import style ('@/lib/trust/...' or '../trust/...'); "block-latch'" is therefore distinct from "block-latch-wiring'"
  assert.deepEqual(importersOf("/trust/block-latch-wiring'"), ['app/page.tsx', 'src/components/ContactManagement.tsx']);
  assert.deepEqual(importersOf("/trust/block-latch'"), ['src/components/export/vault-export-copy.ts', 'src/lib/identity/client-store.ts', 'src/lib/trust/block-latch-wiring.ts']);
});

test('S3 sample data never reaches the user Remove path: sample-circle calls removeContact directly and names none of the latch modules', () => {
  const c = codeOnly(read('src/lib/trust/sample-circle.ts'));
  assert.match(c, /removeContact\(/);
  for (const forbidden of ['block-latch', 'removeContactWithLatch', 'setContactBlocked', 'ContactManagement', 'recordRemovedContact']) assert.ok(!c.includes(forbidden), `sample-circle must not name ${forbidden}`);
});

test('S4 Unblock cannot clear a latch: unblockKeepingLatch has no latch port, and nothing in the latch modules names clearLatched', () => {
  const latch = codeOnly(read('src/lib/trust/block-latch.ts'));
  const head = latch.indexOf('export async function unblockKeepingLatch(');
  assert.ok(head >= 0);
  const sig = latch.slice(latch.indexOf('(', head), latch.indexOf('): Promise', head)); // the parameters only: the function's own name contains "Latch"
  assert.ok(!/latch/i.test(sig), 'the Unblock signature takes no latch');
  for (const f of ['src/lib/trust/block-latch.ts', 'src/lib/trust/block-latch-wiring.ts']) assert.ok(!codeOnly(read(f)).includes('clearLatched'), `${f} never clears a latch`);
});

test('S7 the helpers keep their load-bearing lines: Remove records, Block awaits the suppression write and reports its result, and the export gate really refuses', () => {
  const w = codeOnly(read('src/lib/trust/block-latch-wiring.ts'));
  assert.match(w, /recordRemoved: \(id\) => recordRemovedContact\(ownerFingerprint, id\),/, 'Remove records the removal');
  assert.match(w, /removeContactRecord: \(\) => removeContact\(contactId\),/, 'Remove deletes through the store');
  assert.match(w, /const applySuppression = \(\) => applyBlockSuppression\(ownerFingerprint, durableId, blocked\);/, 'the suppression write is handed over as a promise the orchestration AWAITS');
  assert.ok(!/void applyBlockSuppression/.test(w), 'never fire-and-forget again');
  assert.match(w, /return \{ finished: r\.finished \};/, 'a Block reports whether the record write finished');
  assert.match(w, /await unblockKeepingLatch\(\{ writeBlockFlag, applySuppression \}\);/, 'Unblock goes through the latch-free path');
  const store = read('src/lib/identity/client-store.ts');
  const a = store.indexOf('export async function repairSuppressionOrRefuse(');
  assert.match(codeOnly(store.slice(a, store.indexOf('\n}\n', a))), /=== 'error'\) throw new BlocksIncompleteError\(\);/, 'only an "error" outcome refuses; unreadable/absent is left to the left-out notice');
});

test('S5 the unlock repair runs after the mailbox step, only for verified owners; the restore re-latches AFTER the book is restored', () => {
  const store = read('src/lib/identity/client-store.ts');
  const a = store.indexOf('export async function initSessionKey(');
  const unlock = codeOnly(store.slice(a, store.indexOf('\n}\n', a)));
  const iMail = unlock.indexOf('await ensureDeviceMailboxesOnUnlock();'), iRepair = unlock.indexOf('await repairBlocksOnUnlock();');
  assert.ok(iMail > 0 && iRepair > iMail, 'repairBlocksOnUnlock runs after ensureDeviceMailboxesOnUnlock, inside initSessionKey');
  const b = store.indexOf('async function repairBlocksOnUnlock(');
  assert.match(codeOnly(store.slice(b, store.indexOf('\n}\n', b))), /for \(const owner of _unlockVerifiedOwners\)/, 'only for owners this session verifies');
  // The removed list is append-only, so the re-latch must see the RESTORED BOOK (a removed contact who is back in it follows Block / Trust, not the list):
  // record applied, THEN the contacts restored, THEN the re-latch, THEN the function returns.
  const [iRestore, iContacts, iRelatch, iActive, iReturn] = [
    store.indexOf('await restoreCarriedSuppression(fp,'), store.indexOf('await restoreVaultContacts('),
    store.indexOf('await relatchBlocksForOwner(fp)'), store.indexOf('await setActiveFingerprint(fp);\n  return { fingerprint: fp, contacts: contactsReport, latches };'),
    store.indexOf('return { fingerprint: fp, contacts: contactsReport, latches };'),
  ];
  assert.ok(iRestore > 0 && iContacts > iRestore && iRelatch > iContacts && iActive > iRelatch && iReturn > iActive, 'order: carried record, restored contacts, re-latch, set active, return');
  assert.ok(iActive - iRelatch < 700, 'the re-latch is the last real step before the restore returns (restore-report.test.ts pins setActiveFingerprint directly before the return)');
});

test('S6 the export gate: the dialog repairs before it reads or exports the record, and the refusal maps to its own sentence', () => {
  const d = codeOnly(read('src/components/export/VaultExportDialog.tsx'));
  const a = d.indexOf('const handleExport = async');
  const body = d.slice(a, d.indexOf('\n  };\n', a));
  const [iGate, iAll, iCarry] = [body.indexOf('await repairSuppressionOrRefuse(fingerprint);'), body.indexOf('await exportAll(fingerprint'), body.indexOf('await exportSuppressionCarry(fingerprint)')];
  assert.ok(iGate > 0 && iGate < iAll && iGate < iCarry, 'repair-or-refuse comes before exportAll and exportSuppressionCarry');
  const [iRep, iLook] = [d.indexOf('m.repairSuppressionRecord(fingerprint)'), d.indexOf('m.readSuppressionCarryStatus(fingerprint)')];
  assert.ok(iRep >= 0 && iLook >= 0 && iRep < iLook, 'the status look is taken after the same repair (both must be present: a missing call is not "before")');
  assert.match(codeOnly(read('src/components/export/vault-export-copy.ts')), /err instanceof BlocksIncompleteError\) return VAULT_EXPORT_BLOCKS_REFUSED;/);
});

test('S8 the frozen refusal sentence is exactly the reviewed text (169 characters, sha256 4c88d1c9d584991e), and the restore carries the re-latch report; a missing record reads as no persons, an unreadable one as null', () => {
  assert.equal(VAULT_EXPORT_BLOCKS_REFUSED.length, 169);
  assert.equal(createHash('sha256').update(VAULT_EXPORT_BLOCKS_REFUSED, 'utf8').digest('hex').slice(0, 16), '4c88d1c9d584991e');
  const store = read('src/lib/identity/client-store.ts');
  assert.match(codeOnly(store), /const latches = await relatchBlocksForOwner\(fp\)\.then\(relatchReport, \(\) => RELATCH_ERROR\);/, 'the outcome is reported, not dropped');
  assert.match(codeOnly(store), /return r\.state === 'ok' \? \[\.\.\.r\.value\.persons\] : r\.state === 'absent' \? \[\] : null;/, 'absent is no persons; unreadable is null (the same three-way read as the export look)');
});
