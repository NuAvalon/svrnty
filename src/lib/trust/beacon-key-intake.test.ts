// beacon-key-intake: what a screen does with a 'replace' verdict, with every port faked (the real ports are wired in beacon-key-intake-real.ts).
// Run: npx tsx --test src/lib/trust/beacon-key-intake.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { replaceContactBeaconKeyWith, type KeyIntakePorts, type ReplaceTarget } from './beacon-key-intake';
import type { BeaconSeeds } from '../identity/beacon-seeds';
import type { BeaconStorePort, PairRecord } from '../crypto/beacon-client';
import type { Point } from '../crypto/beacon-prover';

const WEEK_MS = 604_800_000, E = 3000, MID = E * WEEK_MS + 3_600_000;
const OLD_PT: Point = [BigInt(11), BigInt(22)];
const CONTACT = { id: 'c1', fingerprint: 'fp-contact', beacon_public_key: 'KEY_OLD', beacon_key_generation: 5 };
const TARGET: ReplaceTarget = { contact: CONTACT, next: { publicKey: 'KEY_NEW', keyGeneration: 6 } };

const memStore = (): BeaconStorePort & { data: Map<string, PairRecord>; writes: { n: number } } => {
  const data = new Map<string, PairRecord>(); const writes = { n: 0 };
  return {
    data, writes,
    get: async (id) => { const r = data.get(id); return r ? structuredClone(r) : undefined; },
    put: async (r) => { writes.n++; data.set(r.pairId, structuredClone(r)); },
    cas: async (id, v, next) => { if ((data.get(id)?.version ?? 0) !== v) return false; writes.n++; data.set(id, structuredClone(next)); return true; },
    pairs: async () => [...data.values()].map((r) => structuredClone(r)),
  };
};
const ports = (over: Partial<KeyIntakePorts> = {}) => {
  const store = memStore(); const log: string[] = []; const slotKeys: Point[] = [];
  let seeds: BeaconSeeds = {};
  const p: KeyIntakePorts = {
    pairIdFor: async (fp) => { log.push(`pairIdFor:${fp}`); return 'pair-1'; },
    decodeKey: async (k) => { log.push(`decode:${k}`); return k === 'KEY_OLD' ? OLD_PT : null; },
    ownSecret: async () => BigInt(123456789),
    seeds: { read: async () => ({ ...seeds }), update: async (m) => { seeds = m({ ...seeds }); return seeds; }, reset: async () => { seeds = {}; } },
    store, confirmed: { isConfirmed: async () => false },
    writeKeyIf: async (id, expected, next) => { log.push(`writeKeyIf:${id}:${expected.publicKey}/${expected.generation}->${next.publicKey}/${next.generation}`); return true; },
    now: () => MID,
    slotOf: async (_x, y, e) => { slotKeys.push(y); return { H_e: String(10_000 + Number(y[0]) * 1000 + Number(e)), N: String(20_000 + Number(y[0]) * 1000 + Number(e)) }; },
    ...over,
  };
  return { p, store, log, slotKeys };
};
const withRow = (store: ReturnType<typeof memStore>) => store.data.set('pair-1', { pairId: 'pair-1', observedMatch: false, spentEpochs: [], refusedEpochs: [], rows: [{ rowId: 'r1', epoch: String(E), H_e: 'h', N: 'n', state: 'standing' }], pendingWithdraws: [], version: 1 });

test('IK1 a replace: the old key is decoded, the pair id is derived from the contact\'s fingerprint, the queue is committed, and the key is written as a compare-and-set on the OLD key and generation', async () => {
  const k = ports(); withRow(k.store);
  assert.deepEqual(await replaceContactBeaconKeyWith(k.p, TARGET), { kind: 'replaced', wasConfirmed: false });
  assert.deepEqual(k.log, ['decode:KEY_OLD', 'pairIdFor:fp-contact', 'writeKeyIf:c1:KEY_OLD/5->KEY_NEW/6']);
  assert.deepEqual(k.store.data.get('pair-1')!.pendingWithdraws.map((w) => w.rowId), ['r1'], 'queued and committed');
});

test('IK2 the plan is made from the OLD key, for THIS pair only: the derivation is only ever asked about the old point', async () => {
  const k = ports(); withRow(k.store);
  await replaceContactBeaconKeyWith(k.p, TARGET);
  assert.ok(k.slotKeys.length > 0, 'the plan did derive');
  assert.ok(k.slotKeys.every((y) => y[0] === OLD_PT[0] && y[1] === OLD_PT[1]), 'every derivation used the OLD key, never the new one');
});

test('IK3 REFUSED, nothing touched: an old key that cannot be decoded to a point (its rows cannot be named), a contact with no well-formed key, and a generation that is not newer', async () => {
  for (const [label, t] of [
    ['undecodable old key', { ...TARGET, contact: { ...CONTACT, beacon_public_key: 'KEY_UNDECODABLE' } }],
    ['no key held', { ...TARGET, contact: { id: 'c1', fingerprint: 'fp-contact' } }],
    ['malformed generation', { ...TARGET, contact: { ...CONTACT, beacon_key_generation: 'x' as unknown as number } }],
    ['not newer', { ...TARGET, next: { publicKey: 'KEY_NEW', keyGeneration: 5 } }],
    ['older', { ...TARGET, next: { publicKey: 'KEY_NEW', keyGeneration: 4 } }],
  ] as Array<[string, ReplaceTarget]>) {
    const k = ports(); withRow(k.store); const before = JSON.stringify(k.store.data.get('pair-1'));
    assert.deepEqual(await replaceContactBeaconKeyWith(k.p, t), { kind: 'refused' }, label);
    assert.ok(!k.log.some((l) => l.startsWith('writeKeyIf')), `${label}: the key was never written`);
    assert.equal(JSON.stringify(k.store.data.get('pair-1')), before, `${label}: the pair record is exactly as it was`);
  }
});

test('IK4 REFUSED, nothing touched: a locked session (the pair id cannot be derived) and an own beacon key that is held but cannot be read', async () => {
  const locked = ports({ pairIdFor: async () => { throw new Error('locked'); } }); withRow(locked.store);
  assert.deepEqual(await replaceContactBeaconKeyWith(locked.p, TARGET), { kind: 'refused' });
  assert.equal(locked.store.writes.n, 0, 'no write reached the pair store');
  const unreadable = ports({ ownSecret: async () => { throw new Error('held but unreadable'); } }); withRow(unreadable.store);
  const before = JSON.stringify(unreadable.store.data.get('pair-1'));
  assert.deepEqual(await replaceContactBeaconKeyWith(unreadable.p, TARGET), { kind: 'refused' }, 'an unreadable own key is NOT "no key": it proves nothing about the rows, so the plan fails and the replace is refused');
  assert.equal(JSON.stringify(unreadable.store.data.get('pair-1')), before);
  assert.ok(!unreadable.log.some((l) => l.startsWith('writeKeyIf')));
});

test('IK5 CONTROL for IK4: an own key that was never held (no secret) is not a failure: there is nothing to plan, and the replace goes ahead', async () => {
  const k = ports({ ownSecret: async () => undefined }); withRow(k.store);
  assert.deepEqual(await replaceContactBeaconKeyWith(k.p, TARGET), { kind: 'replaced', wasConfirmed: false });
});

test('IK6 a key write that does not apply (the contact moved) is a refusal, the queue stays committed, and the outcome never says replaced', async () => {
  const k = ports({ writeKeyIf: async () => false }); withRow(k.store);
  assert.deepEqual(await replaceContactBeaconKeyWith(k.p, TARGET), { kind: 'refused' });
  assert.deepEqual(k.store.data.get('pair-1')!.pendingWithdraws.map((w) => w.rowId), ['r1']);
});

test('IK7 it never throws, whatever a port does: a port that throws synchronously or rejects is a refusal', async () => {
  const sync = ports({ decodeKey: (() => { throw new Error('boom'); }) as KeyIntakePorts['decodeKey'] });
  assert.deepEqual(await replaceContactBeaconKeyWith(sync.p, TARGET), { kind: 'refused' });
});

test('IK8 NO STORAGE IMPORT, NO NETWORK, NO SWITCH: the composer imports no client store, no fetch, no wire switch; only the real-ports file touches storage', () => {
  const strip = (t: string) => t.replace(/\/\/[^\n]*/g, '');
  const src = strip(readFileSync(join(process.cwd(), 'src/lib/trust/beacon-key-intake.ts'), 'utf8'));
  assert.doesNotMatch(src, /\bfetch\b|isBeaconWireLive|claim-gates|createBeaconClient|createBeaconWire|identity\/client-store/);
  const real = strip(readFileSync(join(process.cwd(), 'src/lib/trust/beacon-key-intake-real.ts'), 'utf8'));
  assert.match(real, /identity\/client-store/, 'CONTROL: the real-ports file is where storage is imported');
  assert.doesNotMatch(real, /\bfetch\b|isBeaconWireLive|claim-gates/);
});

// ---- SOURCE-SHAPE pins for the two behaviours of the real-ports file that only the sealed stores can produce (the browser cannot make a key unreadable or move a contact
// mid-write). They are not behaviour tests, and they say so: they stop the file being edited into the unsafe shape without anyone noticing.
const realSrc = () => readFileSync(join(process.cwd(), 'src/lib/trust/beacon-key-intake-real.ts'), 'utf8').replace(/\/\/[^\n]*/g, '');

test('IK9 (source shape) an own beacon key that is held but unreadable THROWS in the real ports, and only a key that was never held answers "none"', () => {
  const src = realSrc();
  assert.match(src, /if \(r\.state === 'none'\) return undefined;/);
  assert.match(src, /if \(r\.state === 'unreadable'\) throw new Error\(/);
  assert.doesNotMatch(src, /unreadable'\)\s*return\s+undefined/, 'an unreadable key is never "no key"');
});

test('IK10 (source shape) the real key write is a compare-and-set on BOTH the old key and the old generation, applied only if both still match', () => {
  const src = realSrc();
  assert.match(src, /updateContactIf\(contactId, \(cur\) =>\s*cur\.beacon_public_key === expected\.publicKey && cur\.beacon_key_generation === expected\.generation\s*\?\s*\{ beacon_public_key: next\.publicKey, beacon_key_generation: next\.generation \}\s*:\s*null\)/);
  assert.match(src, /return r\.applied;/);
});

test('IK11 an old key that cannot be decoded refuses BY THE EXPLICIT RULE, not by a later accident: even with no own beacon key (so no plan would derive anything and nothing could throw), the replace is refused and nothing is written', async () => {
  // With an own key, a null old point happens to throw later, while deriving the plan, and the replace still refuses. With NO own key nothing is derived and nothing throws, so only the
  // explicit check stands between an undecodable old key and a replace. The rule is "if the old rows cannot be named, refuse": it must not depend on what happens to throw.
  const k = ports({ ownSecret: async () => undefined, decodeKey: async () => null }); withRow(k.store);
  const before = JSON.stringify(k.store.data.get('pair-1'));
  assert.deepEqual(await replaceContactBeaconKeyWith(k.p, TARGET), { kind: 'refused' });
  assert.ok(!k.log.some((l) => l.startsWith('writeKeyIf')), 'the key was never written');
  assert.equal(JSON.stringify(k.store.data.get('pair-1')), before, 'the pair record is exactly as it was');
});
