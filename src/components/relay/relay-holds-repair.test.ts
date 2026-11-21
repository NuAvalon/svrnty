// Run: npx tsx --test src/components/relay/relay-holds-repair.test.ts
// Repair: ONE deliberate owner press lists ONE person at the relay again. It adds only a row the panel SHOWED, re-reads the book at the moment of the press, sends nothing for a contact that is no longer allowed, and says "repaired" only when the relay confirms.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { repairRow, type RepairDeps } from './relay-holds-repair';
import type { UnderRow } from './relay-holds-model';
import type { PeerConsent } from '@/lib/sync/allowed-sync';

const ALLOW: PeerConsent = { trusted: true, openVisibility: true, blocked: false, perContactPrivate: false };
const BLOCKED: PeerConsent = { ...ALLOW, blocked: true };
const FP_A = 'a'.repeat(64);
const FP_B = 'b'.repeat(64);
const SHOWN: UnderRow[] = [{ fp: FP_A, label: 'Robin', name: 'Robin' }];

interface Rig { deps: RepairDeps; adds: Array<{ fp: string; consent: PeerConsent }>; reads: string[]; wholeReads: { n: number } }
const rig = (o: { consent?: PeerConsent | null | 'throw'; ok?: boolean | 'throw'; hold?: Promise<void>; whole?: boolean | 'throw' } = {}): Rig => {
  const adds: Rig['adds'] = []; const reads: string[] = []; const wholeReads = { n: 0 };
  const deps: RepairDeps = {
    bookWhole: async () => { wholeReads.n++; if (o.whole === 'throw') throw new Error('flag unreadable'); return o.whole ?? true; },
    consentOf: async (fp) => { reads.push(fp); if (o.consent === 'throw') throw new Error('book unreadable'); return o.consent === undefined ? ALLOW : o.consent; },
    reconcileAdd: async (fp, consent) => {
      adds.push({ fp, consent });
      if (o.hold) await o.hold;
      if (o.ok === 'throw') throw new Error('network');
      return o.ok ?? true;
    },
  };
  return { deps, adds, reads, wholeReads };
};

test('RHR1 a row the panel did NOT show is refused: nothing is read and nothing is sent', async () => {
  const r = rig();
  assert.deepEqual(await repairRow(SHOWN, FP_B, r.deps), { kind: 'refused' });
  assert.equal(r.reads.length, 0);
  assert.equal(r.adds.length, 0);
});

test('RHR2 the book is re-read AT THE PRESS: a contact blocked after the panel opened sends NOTHING and reads "gone"', async () => {
  const r = rig({ consent: BLOCKED });
  assert.deepEqual(await repairRow(SHOWN, FP_A, r.deps), { kind: 'gone' });
  assert.deepEqual(r.reads, [FP_A], 'the press-time read happened');
  assert.equal(r.adds.length, 0, 'no ADD for a contact that is no longer allowed');
});

test('RHR3 a contact that is no longer in the book at the press sends nothing and reads "gone"', async () => {
  const r = rig({ consent: null });
  assert.deepEqual(await repairRow(SHOWN, FP_A, r.deps), { kind: 'gone' });
  assert.equal(r.adds.length, 0);
});

test('RHR4 an allowed contact gets exactly ONE add, for the contact\'s own fingerprint as the book stores it, with the consent just read; the relay\'s confirmation makes it "repaired"', async () => {
  const r = rig();
  assert.deepEqual(await repairRow(SHOWN, FP_A, r.deps), { kind: 'repaired' });
  assert.equal(r.adds.length, 1);
  assert.deepEqual(r.adds[0], { fp: FP_A, consent: ALLOW });
});

test('RHR5 a relay that does not confirm (false) or throws is "failed": one attempt, no retry, nothing else called', async () => {
  for (const ok of [false, 'throw'] as const) {
    const r = rig({ ok });
    assert.deepEqual(await repairRow(SHOWN, FP_A, r.deps), { kind: 'failed' }, String(ok));
    assert.equal(r.adds.length, 1, `${String(ok)}: exactly one attempt`);
  }
});

test('RHR6 a book that cannot be read at the press is "unreadable": nothing is sent', async () => {
  const r = rig({ consent: 'throw' });
  assert.deepEqual(await repairRow(SHOWN, FP_A, r.deps), { kind: 'unreadable' });
  assert.equal(r.adds.length, 0);
});

test('RHR7 a second press while the first is still in flight is "busy": one add only', async () => {
  let release!: () => void;
  const hold = new Promise<void>((res) => { release = res; });
  const r = rig({ hold });
  const first = repairRow(SHOWN, FP_A, r.deps);
  await new Promise((res) => setTimeout(res, 5));
  assert.deepEqual(await repairRow(SHOWN, FP_A, r.deps), { kind: 'busy' });
  release();
  assert.deepEqual(await first, { kind: 'repaired' });
  assert.equal(r.adds.length, 1);
  // and once it is finished the same row may be pressed again
  const again = rig();
  assert.deepEqual(await repairRow(SHOWN, FP_A, again.deps), { kind: 'repaired' });
});

test('RHR8 repairRow never throws, whatever the dependencies do', async () => {
  const boom: RepairDeps = { bookWhole: () => { throw new Error('sync throw'); }, consentOf: () => { throw new Error('sync throw'); }, reconcileAdd: () => { throw new Error('sync throw'); } };
  assert.deepEqual(await repairRow(SHOWN, FP_A, boom), { kind: 'unreadable' }, 'a throwing integrity check is "could not check"');
  const rest: RepairDeps = { bookWhole: async () => true, consentOf: () => { throw new Error('sync throw'); }, reconcileAdd: () => { throw new Error('sync throw'); } };
  const out = await repairRow(SHOWN, FP_A, rest);
  assert.ok(['unreadable', 'failed'].includes(out.kind), out.kind);
});

test('RHR9 SHAPE: the module never revokes and never reaches the relay itself: no delete, no remove, no direct add, no fetch, no signing import: the add comes in through the one injected dependency', () => {
  const src = readFileSync('src/components/relay/relay-holds-repair.ts', 'utf8').replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, '');
  assert.doesNotMatch(src, /removeAllowedSender|addAllowedSender|reconcileAllowedForPeer|deleteRow|\bfetch\b|raw-sign|signAllowed/);
});

test('RHR10 a book that is not whole AT THE PRESS sends nothing and is "damaged": no consent is read and no add is sent', async () => {
  const r = rig({ whole: false });
  assert.deepEqual(await repairRow(SHOWN, FP_A, r.deps), { kind: 'damaged' });
  assert.equal(r.wholeReads.n, 1);
  assert.equal(r.reads.length, 0, 'the check comes before any consent is read');
  assert.equal(r.adds.length, 0);
});

test('RHR11 a book-integrity flag that cannot be READ at the press is "unreadable" (we could not check, which is not the same as damaged): nothing is read or sent', async () => {
  const r = rig({ whole: 'throw' });
  assert.deepEqual(await repairRow(SHOWN, FP_A, r.deps), { kind: 'unreadable' });
  assert.equal(r.reads.length, 0);
  assert.equal(r.adds.length, 0);
});

test('RHR12 the check is made at EVERY press: a book that was damaged and is whole again lets the next press add, and a book that was whole and is damaged now sends nothing', async () => {
  const state = { whole: false };
  const r = rig();
  r.deps.bookWhole = async () => state.whole;
  assert.deepEqual(await repairRow(SHOWN, FP_A, r.deps), { kind: 'damaged' });
  assert.equal(r.adds.length, 0);
  state.whole = true;
  assert.deepEqual(await repairRow(SHOWN, FP_A, r.deps), { kind: 'repaired' });
  assert.equal(r.adds.length, 1);
  state.whole = false;
  assert.deepEqual(await repairRow(SHOWN, FP_A, r.deps), { kind: 'damaged' });
  assert.equal(r.adds.length, 1, 'no second add');
});
