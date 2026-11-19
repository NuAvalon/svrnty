// src/lib/trust/readd-removed.test.ts
// Gate: taking one person off the removed list is atomic, fails closed, touches only that id, and is reachable from NOWHERE yet. Every port is a fake; the list store is the real
// compare-and-swap loop (makeUpdate) over an in-memory row.
//   · PLAN: an absent list or an id that is not on it is a no-op; an unreadable list REFUSES; only that one id leaves; the others keep their order.
//   · ATOMIC: a write that lands between the read and the commit is never overwritten (the drop is decided again on the newer list).
//   · WRITER PIN: nothing but this module shrinks the list, and the drop is called only by the identity store.
//   · NOT WIRED: no screen reaches it. The manual add form in particular can never be the removed person (it has no way to create a contact with a bound key), so its handler must
//     never reach the planner or the drop writer; the day the owner's private contact screen is wired, that change updates this pin on purpose.
// Run: npx tsx --test src/lib/trust/readd-removed.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { planRemovedDrop, dropRemoved } from '@/lib/trust/readd-removed';
import { makeUpdate, type SealedRead, type UpdateIO } from '@/lib/trust/suppression-restore';

const A = 'a'.repeat(64);
const B = 'b'.repeat(64);
const C = 'c'.repeat(64);

/** An in-memory sealed row: read gives a token for exactly what it holds; commit succeeds only if the row is still that. */
function memRow(initial: SealedRead<string[]>) {
  const row = { cur: initial, writes: [] as string[][], beforeCommit: undefined as undefined | (() => void) };
  const io: UpdateIO<string[]> = {
    async read() { return { token: JSON.stringify(row.cur), held: row.cur }; },
    async commit(token, value) {
      row.beforeCommit?.();
      row.beforeCommit = undefined;
      if (token !== JSON.stringify(row.cur)) return false;
      row.cur = { state: 'ok', value };
      row.writes.push(value);
      return true;
    },
  };
  return { row, update: makeUpdate<string[]>(io) };
}

test('PLAN: an absent list and an id that is not on the list are no-ops', () => {
  assert.deepEqual(planRemovedDrop({ state: 'absent' }, A), { kind: 'noop' });
  assert.deepEqual(planRemovedDrop({ state: 'ok', value: [B, C] }, A), { kind: 'noop' });
  assert.deepEqual(planRemovedDrop({ state: 'ok', value: [] }, A), { kind: 'noop' });
});

test('PLAN: an UNREADABLE list refuses (fails closed): nothing is dropped on a list that cannot be read', () => {
  assert.deepEqual(planRemovedDrop({ state: 'unreadable' }, A), { kind: 'refuse', why: 'unreadable' });
});

test('PLAN: only that id leaves; the others keep their order', () => {
  assert.deepEqual(planRemovedDrop({ state: 'ok', value: [B, A, C] }, A), { kind: 'write', list: [B, C] });
  assert.deepEqual(planRemovedDrop({ state: 'ok', value: [A] }, A), { kind: 'write', list: [] });
});

test('PLAN: an id that is not a canonical fingerprint cannot be on the list, so it is a no-op even on an unreadable list', () => {
  for (const bad of ['', 'abc', 'A'.repeat(64), 'g'.repeat(64), 'a'.repeat(40), 'a'.repeat(65)]) {
    assert.deepEqual(planRemovedDrop({ state: 'ok', value: [A] }, bad), { kind: 'noop' }, `bad id ${bad.length}`);
    assert.deepEqual(planRemovedDrop({ state: 'unreadable' }, bad), { kind: 'noop' }, `bad id on unreadable ${bad.length}`);
  }
});

test('ATOMIC: the drop writes once, the list reads back without the id, and a second drop is a no-op with no second write', async () => {
  const { row, update } = memRow({ state: 'ok', value: [A, B] });
  assert.equal((await dropRemoved(update, A)).kind, 'write');
  assert.deepEqual(row.cur, { state: 'ok', value: [B] });
  assert.equal((await dropRemoved(update, A)).kind, 'noop');
  assert.equal(row.writes.length, 1, 'no second write');
});

test('ATOMIC: an unreadable stored list is never overwritten, and the refusal says so', async () => {
  const { row, update } = memRow({ state: 'unreadable' });
  assert.deepEqual(await dropRemoved(update, A), { kind: 'refuse', why: 'unreadable' });
  assert.deepEqual(row.cur, { state: 'unreadable' });
  assert.equal(row.writes.length, 0);
});

test('ATOMIC: a write that lands between the read and the commit is kept: the drop is decided again on the newer list', async () => {
  const { row, update } = memRow({ state: 'ok', value: [A, B] });
  row.beforeCommit = () => { row.cur = { state: 'ok', value: [A, B, C] }; }; // another tab's Remove lands first
  assert.equal((await dropRemoved(update, A)).kind, 'write');
  assert.deepEqual(row.cur, { state: 'ok', value: [B, C] }, 'the newer entry C survived; only A left');
});

// ---- the pins: source scans (comments are not code) ----
const SRC = join(process.cwd(), 'src');
const codeOnly = (t: string): string => t.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) { if (name !== 'node_modules') sourceFiles(p, out); continue; }
    if (/\.(ts|tsx)$/.test(name) && !/\.test\.(ts|tsx)$/.test(name) && !/\.d\.ts$/.test(name)) out.push(p);
  }
  return out;
}
const filesWith = (needle: RegExp): string[] =>
  sourceFiles(SRC).filter((f) => needle.test(codeOnly(readFileSync(f, 'utf8')))).map((f) => f.slice(SRC.length + 1)).sort();

test('WRITER PIN: only the identity store and the two list modules touch the list writer, and only this module shrinks it', () => {
  assert.deepEqual(filesWith(/\bupdateRemoved\b/), ['lib/identity/client-store.ts', 'lib/trust/suppression-restore.ts'],
    'a new writer of the removed list must be a deliberate, reviewed change');
  assert.deepEqual(filesWith(/\bplanRemovedDrop\b/), ['lib/trust/readd-removed.ts'], 'the plan is built only here');
  assert.deepEqual(filesWith(/\bdropRemoved\(/), ['lib/identity/client-store.ts', 'lib/trust/readd-removed.ts'], 'the drop is CALLED only by the store');
});

test('NOT WIRED: no screen, import, restore, sync or gate arrival reaches the drop (only the store holds it); this pin changes with the private contact screen, on purpose', () => {
  assert.deepEqual(filesWith(/\bdropRemovedForOwner\b/), ['lib/identity/client-store.ts']);
  assert.deepEqual(filesWith(/trust\/readd-removed['"]/), ['lib/identity/client-store.ts']);
});

test('MANUAL ADD PIN: the manual add handler never reaches the planner or the drop writer (a form without a bound key cannot be the removed person), and addContact itself never drops', () => {
  const cm = codeOnly(readFileSync(join(SRC, 'components', 'ContactManagement.tsx'), 'utf8'));
  const start = cm.indexOf('const handleAddContact = async');
  const end = cm.indexOf('const handleUpdateContact = async');
  assert.ok(start > 0 && end > start, 'the manual add handler is found');
  assert.doesNotMatch(cm.slice(start, end), /planRemovedDrop|dropRemoved|dropRemovedForOwner|readd|removedList/i, 'the manual add handler does not touch the removed list');
  const store = codeOnly(readFileSync(join(SRC, 'lib', 'identity', 'client-store.ts'), 'utf8'));
  const a0 = store.indexOf('export async function addContact(');
  assert.ok(a0 > 0, 'addContact is found');
  const a1 = store.indexOf('\nexport ', a0 + 10);
  assert.doesNotMatch(store.slice(a0, a1), /planRemovedDrop|dropRemoved|dropRemovedForOwner/, 'addContact never drops');
});
