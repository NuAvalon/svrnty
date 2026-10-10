// src/lib/trust/piece2-genesis.test.ts
// Gate for the piece-2 GENESIS-INIT spine hook (task #579, Flint #159801 fail-closed constraint).
// Refutes:
//   · the hook writes an EXPLICIT empty suppression record for a fresh fp (the default-discoverable baseline),
//   · it NEVER writes under an empty/garbage fingerprint,
//   · a throwing writer is SWALLOWED by runGenesisHooks (identity creation never fails on a hook) — fail-closed
//     is the consumer's null-⇒-suppress-all, not a throw here,
//   · registerPiece2GenesisInit installs a hook that fires in the mint flow without rejecting.
// Run: npx tsx --test src/lib/trust/piece2-genesis.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makePiece2GenesisInit, registerPiece2GenesisInit } from './piece2-genesis.js';
import {
  registerGenesisHook,
  runGenesisHooks,
  __clearGenesisHooksForTest,
} from '../identity/identity-genesis-hooks.js';
import { isSuppressionRecord } from './suppression.js';

const FP = 'deadbeef'.repeat(8); // 64 hex

test('writes an EXPLICIT empty suppression record for a fresh fp (default-discoverable baseline)', async () => {
  const writes: Array<{ fp: string; rec: unknown }> = [];
  const hook = makePiece2GenesisInit(async (fp, rec) => { writes.push({ fp, rec }); });
  await hook(FP);
  assert.equal(writes.length, 1, 'wrote once');
  assert.equal(writes[0].fp, FP);
  assert.ok(isSuppressionRecord(writes[0].rec), 'well-formed record');
  assert.deepEqual(writes[0].rec, { global: false, groups: [], persons: [] }, 'empty = never-suppressed baseline');
});

test('no-op on an empty/whitespace fingerprint (never writes under an empty key)', async () => {
  const writes: unknown[] = [];
  const hook = makePiece2GenesisInit(async (fp, rec) => { writes.push({ fp, rec }); });
  await hook('');
  await hook('   ');
  await hook(undefined as unknown as string);
  assert.equal(writes.length, 0, 'never wrote');
});

test('a throwing writer is SWALLOWED by runGenesisHooks (identity creation never fails on a hook)', async () => {
  __clearGenesisHooksForTest();
  let fired = '';
  registerGenesisHook(makePiece2GenesisInit(async (fp) => { fired = fp; throw new Error('store locked'); }));
  await assert.doesNotReject(runGenesisHooks(FP), 'runGenesisHooks swallows the throw');
  assert.equal(fired, FP, 'the hook fired (threw, was swallowed) — consumer null-⇒-suppress-all is the fail-closed');
  __clearGenesisHooksForTest();
});

test('registerPiece2GenesisInit installs a hook that fires in the mint flow without rejecting', async () => {
  __clearGenesisHooksForTest();
  // Registers the REAL hook (wired to the IndexedDB store). With no session it throws "locked" inside the
  // write, which runGenesisHooks swallows — so a genesis run does not reject. Observable registration contract.
  registerPiece2GenesisInit();
  await assert.doesNotReject(runGenesisHooks(FP), 'registered hook fires + is swallowed on the no-session store error');
  __clearGenesisHooksForTest();
});
