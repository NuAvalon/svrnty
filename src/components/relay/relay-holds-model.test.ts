// Run: npx tsx --test src/components/relay/relay-holds-model.test.ts
// The pure model of the "what the relay holds about you" panel: from the relay's own list and the owner's book, who is over-listed (a COUNT: the revoke check's drain takes them off) and who is under-listed (ROWS: the owner may Repair). No I/O.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildPanel, overListedFps, showsAllMatch, type BookEntry } from './relay-holds-model';
import { RELAY_UNKNOWN_SENDER } from './relay-holds-copy';
import { drainAllowedRevokes, resetRevokeState, type AllowedRevokeIo } from '@/lib/sync/allowed-revoke';
import type { AllowedListResult, PeerConsent } from '@/lib/sync/allowed-sync';

const ALLOW: PeerConsent = { trusted: true, openVisibility: true, blocked: false, perContactPrivate: false };
const BLOCKED: PeerConsent = { ...ALLOW, blocked: true };
const PRIVATE: PeerConsent = { ...ALLOW, perContactPrivate: true };
const CLOSED: PeerConsent = { ...ALLOW, openVisibility: false };
const fp = (c: string): string => c.repeat(64).slice(0, 64);                 // a 64-hex fingerprint
const A = fp('a'), B = fp('b'), C = fp('c'), D = fp('d'), E = fp('e'), F = fp('f');
const ok = (...fps: string[]): AllowedListResult => ({ status: 'ok', fps });
const book = (entries: Array<[string, string | null, PeerConsent]>): Map<string, BookEntry> => new Map(entries.map(([k, name, consent]) => [k, { name, consent }]));

test('RHM1 an unknown or gone read is NEVER turned into a list: "unknown" and "no-list" carry no diff at all', () => {
  assert.deepEqual(buildPanel({ status: 'unknown' }, book([[A, 'Robin', ALLOW]]), true), { kind: 'unknown' });
  assert.deepEqual(buildPanel({ status: 'gone' }, book([[A, 'Robin', ALLOW]]), true), { kind: 'no-list' });
  assert.deepEqual(buildPanel(ok(), book([]), true), { kind: 'ok', overCount: 0, under: [], noKeyCount: 0 }, 'a read that WORKED and found nothing is an empty diff, not an unknown');
});

test('RHM2 over-listed = listed, and the book does not allow a row: blocked, go-private, closed visibility, or not in the book at all; counted once per fingerprint, in either case', () => {
  const b = book([[A, 'Robin', BLOCKED], [B, 'Sam', PRIVATE], [C, 'Kit', CLOSED], [D, 'Lee', ALLOW]]);
  const m = buildPanel(ok(A, B, C, D, E), b, true);
  assert.equal(m.kind, 'ok');
  if (m.kind === 'ok') assert.equal(m.overCount, 4, 'A, B, C blocked/private/closed and E not in the book; D is allowed so it stays');
  const dup = buildPanel(ok(A.toUpperCase(), A), book([[A, 'Robin', BLOCKED]]), true);
  if (dup.kind === 'ok') assert.equal(dup.overCount, 1, 'the same fingerprint in two cases is one person');
  assert.deepEqual(overListedFps(ok(A, B, C, D, E), b).sort(), [A, B, C, E].sort());
});

test('RHM3 under-listed = the book allows a row and the relay does not list it: a ROW per contact with its name, compared in lower case, sorted by label then fingerprint', () => {
  const b = book([[A, 'Robin', ALLOW], [B, null, ALLOW], [C, 'Kit', ALLOW], [D, 'Lee', BLOCKED], [E, 'Sam', ALLOW]]);
  const m = buildPanel(ok(C.toUpperCase(), D), b, true);
  assert.equal(m.kind, 'ok');
  if (m.kind !== 'ok') return;
  assert.deepEqual(m.under.map((r) => [r.label, r.fp, r.name]), [['Robin', A, 'Robin'], ['Sam', E, 'Sam'], ['This person', B, null]], 'Kit is listed (upper case on the relay), Lee is blocked so nothing is owed to Lee');
});

test('RHM4 a relay-listed value that is not in the book is COUNTED but never named: no fingerprint of it appears anywhere in the model (no fingerprint on screen, no lookup)', () => {
  const strange = fp('9');
  const m = buildPanel(ok(strange, A), book([[A, 'Robin', ALLOW]]), true);
  assert.equal(m.kind, 'ok');
  if (m.kind === 'ok') assert.equal(m.overCount, 1);
  assert.doesNotMatch(JSON.stringify(m), new RegExp(strange, 'i'));
  assert.equal(typeof RELAY_UNKNOWN_SENDER, 'string');
});

test('RHM5 a damaged contact book is "book-damaged": it cannot say who is gone or who is allowed, so the panel shows its one line, no rows and no Repair, whether the relay read worked or failed', () => {
  assert.deepEqual(buildPanel(ok(A), book([[B, 'Robin', ALLOW]]), false), { kind: 'book-damaged' });
  assert.deepEqual(buildPanel({ status: 'unknown' }, book([[B, 'Robin', ALLOW]]), false), { kind: 'book-damaged' }, 'the book is the problem we can name');
  assert.deepEqual(buildPanel({ status: 'gone' }, book([[B, 'Robin', ALLOW]]), false), { kind: 'no-list' }, 'a relay with no list has nothing to compare, whatever the book');
  assert.deepEqual(buildPanel({ status: 'unknown' }, book([[B, 'Robin', ALLOW]]), true), { kind: 'unknown' }, 'a failed read with a whole book is still "unknown"');
});

test('RHM6 a blocked or removed contact that the relay does not list is not "owed" anything: it is in neither list', () => {
  const m = buildPanel(ok(), book([[A, 'Robin', BLOCKED], [B, 'Sam', CLOSED]]), true);
  assert.deepEqual(m, { kind: 'ok', overCount: 0, under: [], noKeyCount: 0 });
});

test('RHM7 the model object holds no fingerprint of an OVER-listed person and no relay-supplied string at all', () => {
  const m = buildPanel(ok(A, B, C), book([[A, 'Robin', BLOCKED]]), true);
  const json = JSON.stringify(m);
  for (const f of [A, B, C]) assert.doesNotMatch(json, new RegExp(f, 'i'));
});

// RHM8: the model's idea of "over-listed" must be EXACTLY the set the revoke check's drain deletes (complete book), so the panel can never promise a revoke the drain will not make, or hide one it will.
test('RHM8 EQUIVALENCE with the real drain: over-listed set == the fingerprints drainAllowedRevokes deletes, over a table of books and lists', async () => {
  const cases: Array<{ name: string; listed: string[]; b: Map<string, BookEntry> }> = [
    { name: 'empty', listed: [], b: book([]) },
    { name: 'all allowed', listed: [A, B], b: book([[A, 'a', ALLOW], [B, 'b', ALLOW]]) },
    { name: 'blocked listed', listed: [A, B], b: book([[A, 'a', BLOCKED], [B, 'b', ALLOW]]) },
    { name: 'absent listed', listed: [A, B, C], b: book([[A, 'a', ALLOW]]) },
    { name: 'private + closed', listed: [A, B, C], b: book([[A, 'a', PRIVATE], [B, 'b', CLOSED], [C, 'c', ALLOW]]) },
    { name: 'upper-case on the relay', listed: [A.toUpperCase(), B.toUpperCase()], b: book([[A, 'a', BLOCKED], [B, 'b', ALLOW]]) },
    { name: 'allowed but not listed', listed: [A], b: book([[A, 'a', ALLOW], [B, 'b', ALLOW]]) },
    { name: 'mixed', listed: [A, B, C, D, E, F], b: book([[A, 'a', ALLOW], [B, 'b', BLOCKED], [C, 'c', PRIVATE], [D, 'd', CLOSED]]) },
  ];
  for (const c of cases) {
    resetRevokeState();
    const deleted: string[] = [];
    const io: AllowedRevokeIo = { list: async () => ok(...c.listed), deleteRow: async (f) => { deleted.push(f.toLowerCase()); return true; } };
    const consents = new Map([...c.b].map(([k, e]) => [k, e.consent] as const));
    await drainAllowedRevokes('owner', io, { consents: async () => consents, bookComplete: async () => true, sleep: async () => {}, now: () => 0 });
    assert.deepEqual(overListedFps(ok(...c.listed), c.b).sort(), [...new Set(deleted)].sort(), `${c.name}: the model and the drain disagree`);
    const m = buildPanel(ok(...c.listed), c.b, true);
    assert.equal(m.kind, 'ok', c.name);
    if (m.kind === 'ok') assert.equal(m.overCount, new Set(deleted).size, `${c.name}: count`);
  }
});

test('RHM9 contacts the book allows who have NO KEY yet can never be listed and are not in the comparison: they are counted as their own state, never silently dropped', () => {
  const m = buildPanel(ok(A), book([[A, 'Robin', ALLOW]]), true, 2);
  assert.deepEqual(m, { kind: 'ok', overCount: 0, under: [], noKeyCount: 2 });
  for (const bad of [-1, 1.5, Number.NaN]) assert.throws(() => buildPanel(ok(A), book([]), true, bad), /noKeyCount/);
  assert.deepEqual(buildPanel({ status: 'unknown' }, book([]), true, 3), { kind: 'unknown' }, 'only a read that worked carries the count');
});

test('RHM10 "nothing differs" is shown ONLY for a read that worked with zero over-listed, zero under-listed AND zero contacts without a key: an exact relay match with one allowed key-less contact must NOT say "exactly"', () => {
  const exact = book([[A, 'Robin', ALLOW]]);
  assert.equal(showsAllMatch(buildPanel(ok(A), exact, true, 0)), true);
  assert.equal(showsAllMatch(buildPanel(ok(A), exact, true, 1)), false, 'the key-less contact is missing from the comparison');
  assert.equal(showsAllMatch(buildPanel(ok(A, B), exact, true, 0)), false, 'one over-listed');
  assert.equal(showsAllMatch(buildPanel(ok(), exact, true, 0)), false, 'one under-listed');
  for (const m of [{ kind: 'unknown' }, { kind: 'no-list' }, { kind: 'book-damaged' }] as const) assert.equal(showsAllMatch(m), false, m.kind);
});

test('RHM11 a book fingerprint spelled in UPPER case matches the relay\'s lower-case listing: that contact is neither under-listed (no Repair offered) nor over-listed', () => {
  const UP = 'ABCDEF0123'.repeat(6) + 'ABCD';                       // 64 hex digits, upper case: how an OpenPGP fingerprint is often written
  assert.equal(UP.length, 64);
  assert.deepEqual(buildPanel(ok(UP.toLowerCase()), book([[UP, 'Robin', ALLOW]]), true), { kind: 'ok', overCount: 0, under: [], noKeyCount: 0 });
  assert.deepEqual(overListedFps(ok(UP.toLowerCase()), book([[UP, 'Robin', ALLOW]])), []);
});
