// Run: npx tsx --test src/components/relay/relay-holds-port.test.ts
// The panel's PORT: what the screen is given. It reads the last list the revoke check kept (no request of its own), the owner's book, and asks the existing check to read again. Everything real is injected, so these run in node.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadPanel, mergeBook, makeRelayHoldsPort, type PortIo, type BookRecord } from './relay-holds-port';
import type { AllowedListResult, PeerConsent } from '@/lib/sync/allowed-sync';

const ALLOW: PeerConsent = { trusted: true, openVisibility: true, blocked: false, perContactPrivate: false };
const BLOCKED: PeerConsent = { ...ALLOW, blocked: true };
const A = 'a'.repeat(64), B = 'b'.repeat(64);
const ok = (...fps: string[]): AllowedListResult => ({ status: 'ok', fps });

const io = (o: { read?: { listed: AllowedListResult; at: number } | undefined; records?: BookRecord[] | 'throw'; whole?: boolean | 'throw'; tick?: () => Promise<void>; now?: number } = {}): PortIo & { ticks: number; adds: Array<{ fp: string; consent: PeerConsent }>; bookReads: number } => {
  const s = { ticks: 0, adds: [] as Array<{ fp: string; consent: PeerConsent }>, bookReads: 0 };
  return Object.assign(s, {
    lastRead: () => o.read,
    records: async () => { s.bookReads++; if (o.records === 'throw') throw new Error('locked'); return o.records ?? []; },
    bookWhole: async () => { if (o.whole === 'throw') throw new Error('flag'); return o.whole ?? true; },
    tick: async () => { s.ticks++; if (o.tick) await o.tick(); },
    add: async (fp: string, consent: PeerConsent) => { s.adds.push({ fp, consent }); return true; },
    nowMs: () => o.now ?? 100_000,
  });
};

test('RHP1 NEVER READ (or forgotten on lock) is "unknown", never an empty list: the panel says it could not check', async () => {
  const r = await loadPanel(makeRelayHoldsPort('owner', io({ read: undefined })));
  assert.deepEqual(r, { model: { kind: 'unknown' }, at: undefined });
});

test('RHP2 a good read is compared with the book as it is NOW, and carries the time of the read', async () => {
  const p = makeRelayHoldsPort('owner', io({ read: { listed: ok(A), at: 40_000 }, records: [{ fingerprint: A, name: 'Robin', consent: BLOCKED }, { fingerprint: B, name: 'Sam', consent: ALLOW }] }));
  const r = await loadPanel(p);
  assert.equal(r.at, 40_000);
  assert.deepEqual(r.model, { kind: 'ok', overCount: 1, under: [{ fp: B, label: 'Sam', name: 'Sam' }], noKeyCount: 0 });
});

test('RHP3 a relay that keeps no list is "no-list"; a failed read is "unknown"', async () => {
  assert.deepEqual((await loadPanel(makeRelayHoldsPort('o', io({ read: { listed: { status: 'gone' }, at: 1 } })))).model, { kind: 'no-list' });
  assert.deepEqual((await loadPanel(makeRelayHoldsPort('o', io({ read: { listed: { status: 'unknown' }, at: 1 } })))).model, { kind: 'unknown' });
});

test('RHP4 an integrity flag that is not ok is "book-damaged"; a book or a flag that cannot be READ at all is "unknown" (we cannot say the book is damaged, only that we could not check)', async () => {
  const good = { listed: ok(A), at: 1 };
  assert.deepEqual((await loadPanel(makeRelayHoldsPort('o', io({ read: good, whole: false })))).model, { kind: 'book-damaged' });
  assert.deepEqual((await loadPanel(makeRelayHoldsPort('o', io({ read: good, records: 'throw' })))).model, { kind: 'unknown' });
  assert.deepEqual((await loadPanel(makeRelayHoldsPort('o', io({ read: good, whole: 'throw' })))).model, { kind: 'unknown' });
});

test('RHP5 two records for one fingerprint follow the drain\'s own rule: the row is kept if EITHER allows it; the name is the allowing record\'s, else the first one with a name', () => {
  const m = mergeBook([
    { fingerprint: A, name: '', consent: BLOCKED }, { fingerprint: A, name: 'Robin', consent: ALLOW },
    { fingerprint: B, name: 'Sam', consent: BLOCKED }, { fingerprint: B, name: 'Samuel', consent: BLOCKED },
  ]);
  assert.deepEqual(m.get(A), { name: 'Robin', consent: ALLOW });
  assert.equal(m.get(B)?.consent.blocked, true);
  assert.equal(m.get(B)?.name, 'Sam', 'neither allows: the first record with a name');
  assert.equal(m.size, 2);
});

test('RHP6 refresh asks the existing check to read again and NEVER throws; opening the panel (loadPanel) makes NO request and runs no check', async () => {
  const quiet = io({ read: { listed: ok(), at: 1 } });
  await loadPanel(makeRelayHoldsPort('o', quiet));
  assert.equal(quiet.ticks, 0, 'loading is read-only');
  const p = makeRelayHoldsPort('o', quiet);
  await p.refresh();
  assert.equal(quiet.ticks, 1);
  const boom = makeRelayHoldsPort('o', io({ tick: async () => { throw new Error('network'); } }));
  await assert.doesNotReject(boom.refresh());
});

test('RHP7 Repair\'s book read happens AT THE PRESS, not once at load: a contact blocked between two presses changes the second press\'s outcome', async () => {
  const x = io({ records: [{ fingerprint: A, name: 'Robin', consent: ALLOW }] });
  const p = makeRelayHoldsPort('o', x);
  assert.deepEqual(await p.repair.consentOf(A), ALLOW);
  (x as unknown as { records: () => Promise<BookRecord[]> }).records = async () => [{ fingerprint: A, name: 'Robin', consent: BLOCKED }];
  assert.deepEqual(await p.repair.consentOf(A), BLOCKED, 'read again, not cached');
  assert.equal(await p.repair.consentOf(B), null, 'not in the book');
  assert.equal(await p.repair.reconcileAdd(A, ALLOW), true);
  assert.deepEqual(x.adds, [{ fp: A, consent: ALLOW }]);
});

test('RHP8 an ALLOWED contact with no fingerprint yet is counted (they can never be listed), a blocked one is not, and the count reaches the model', async () => {
  const p = makeRelayHoldsPort('o', io({ read: { listed: ok(A), at: 1 }, records: [
    { fingerprint: A, name: 'Robin', consent: ALLOW },
    { fingerprint: '', name: 'Kit', consent: ALLOW },
    { fingerprint: '', name: 'Lee', consent: BLOCKED },
    { fingerprint: undefined as unknown as string, name: 'Sam', consent: ALLOW },
  ] }));
  assert.equal((await p.book()).noKeyCount, 2);
  assert.deepEqual((await loadPanel(p)).model, { kind: 'ok', overCount: 0, under: [], noKeyCount: 2 });
});

test('RHP9 Repair checks that the book is whole AT THE PRESS: the flag is asked for on every call, never kept from the draw', async () => {
  const x = io({ records: [{ fingerprint: A, name: 'Robin', consent: ALLOW }], whole: true });
  const p = makeRelayHoldsPort('o', x);
  assert.equal(await p.repair.bookWhole(), true);
  (x as unknown as { bookWhole: () => Promise<boolean> }).bookWhole = async () => false;
  assert.equal(await p.repair.bookWhole(), false, 'read again, not kept from before');
  (x as unknown as { bookWhole: () => Promise<boolean> }).bookWhole = async () => { throw new Error('flag'); };
  await assert.rejects(p.repair.bookWhole());
});

test('RHP10 a book that is not whole at the press: Repair sends nothing, and the panel the screen then reloads is the damaged one', async () => {
  const x = io({ read: { listed: ok(), at: 1 }, records: [{ fingerprint: A, name: 'Robin', consent: ALLOW }], whole: false });
  const p = makeRelayHoldsPort('o', x);
  const { repairRow } = await import('./relay-holds-repair');
  assert.deepEqual(await repairRow([{ fp: A, label: 'Robin', name: 'Robin' }], A, p.repair), { kind: 'damaged' });
  assert.deepEqual(x.adds, []);
  assert.equal((await loadPanel(p)).model.kind, 'book-damaged');
});
