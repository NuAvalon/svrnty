// src/lib/trust/readd-removed.test.ts
// Gate: taking one person off the removed list is atomic, fails closed, touches only that id, and is reached from ONE place (the owner's private Keep button). Every port is a fake; the list store is the real
// compare-and-swap loop (makeUpdate) over an in-memory row.
//   · PLAN: an absent list or an id that is not on it is a no-op; an unreadable list REFUSES; only that one id leaves; the others keep their order.
//   · ATOMIC: a write that lands between the read and the commit is never overwritten (the drop is decided again on the newer list).
//   · WRITER PIN: nothing but this module shrinks the list, and the drop is called only by the identity store.
//   · ONE CALLER (and PRIVATE ONLY, below): only the contact book's Keep handler reaches it, never an import, restore, sync, gate arrival, exchange or the Galaxy. The manual add form in particular can never be the removed person (it has no way to create a contact with a bound key), so its handler must
//     never reach the planner or the drop writer.
// Run: npx tsx --test src/lib/trust/readd-removed.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { planRemovedDrop, dropRemoved, wasRemovedBefore } from '@/lib/trust/readd-removed';
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

test('READER: the notice shows only for a canonical id that is ON a readable list (any case, spaces trimmed); absent, unreadable, a stranger and a keyless contact are all no', () => {
  const list: SealedRead<string[]> = { state: 'ok', value: [A, C] };
  assert.equal(wasRemovedBefore(list, A), true);
  assert.equal(wasRemovedBefore(list, ` ${A.toUpperCase()} `), true);
  assert.equal(wasRemovedBefore(list, B), false);
  assert.equal(wasRemovedBefore({ state: 'ok', value: [] }, A), false);
  assert.equal(wasRemovedBefore({ state: 'absent' }, A), false);
  assert.equal(wasRemovedBefore({ state: 'unreadable' }, A), false);
  assert.equal(wasRemovedBefore(list, ''), false);
  assert.equal(wasRemovedBefore(list, null), false);
  assert.equal(wasRemovedBefore(list, undefined), false);
  assert.equal(wasRemovedBefore(list, 'not-a-fingerprint'), false);
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
const CWD = process.cwd();
const SRC = join(CWD, 'src');
// Every top-level directory that holds APPLICATION TypeScript is scanned. app/ is outside src/, and it is where the second Remove / Block path hid until a browser found it.
const APP_ROOTS = ['app', 'src'];
// Test harnesses and tooling: classified on purpose. A NEW top-level directory with TypeScript fails the ROOTS test until it is classified here or scanned above.
const NOT_APP_ROOTS = ['e2e', 'scripts'];
const codeOnly = (t: string): string => t.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) { if (name !== 'node_modules' && name !== '.next') sourceFiles(p, out); continue; }
    if (/\.(ts|tsx)$/.test(name) && !/\.test\.(ts|tsx)$/.test(name) && !/\.d\.ts$/.test(name)) out.push(p);
  }
  return out;
}
/** The files (paths relative to `cwd`) under `roots` whose code (comments dropped) matches `needle`. */
const scan = (cwd: string, roots: string[], needle: RegExp): string[] =>
  roots.flatMap((r) => (existsSync(join(cwd, r)) ? sourceFiles(join(cwd, r)) : []))
    .filter((f) => needle.test(codeOnly(readFileSync(f, 'utf8')))).map((f) => f.slice(cwd.length + 1)).sort();
const filesWith = (needle: RegExp): string[] => scan(CWD, APP_ROOTS, needle);
/** The text of each `<ContactActionCard ... />` opening element in `code`: it ends at the first `/>` that is not inside a `{ }` prop value. */
function cardElements(code: string): string[] {
  const out: string[] = [];
  let from = 0;
  for (;;) {
    const start = code.indexOf('<ContactActionCard', from);
    if (start < 0) return out;
    let depth = 0;
    let end = -1;
    for (let i = start; i < code.length; i++) {
      const c = code[i];
      if (c === '{') depth++;
      else if (c === '}') depth--;
      else if (depth === 0 && c === '/' && code[i + 1] === '>') { end = i + 2; break; }
    }
    if (end < 0) return out;
    out.push(code.slice(start, end));
    from = end;
  }
}
/** Whether a JSX element's text spreads props into it: a `{` at depth 0 that is not a prop value (`name={...}`). An object spread INSIDE a prop value is deeper and does not count. */
function hasJsxSpread(el: string): boolean {
  let depth = 0;
  for (let i = 0; i < el.length; i++) {
    const c = el[i];
    if (c === '{') {
      if (depth === 0 && !/=\s*$/.test(el.slice(0, i))) return true;
      depth++;
    } else if (c === '}') depth--;
  }
  return false;
}

test('WRITER PIN: only the identity store and the two list modules touch the list writer, and only this module shrinks it', () => {
  assert.deepEqual(filesWith(/\bupdateRemoved\b/), ['src/lib/identity/client-store.ts', 'src/lib/trust/suppression-restore.ts'],
    'a new writer of the removed list must be a deliberate, reviewed change');
  assert.deepEqual(filesWith(/\bplanRemovedDrop\b/), ['src/lib/trust/readd-removed.ts'], 'the plan is built only here');
  assert.deepEqual(filesWith(/\bdropRemoved\(/), ['src/lib/identity/client-store.ts', 'src/lib/trust/readd-removed.ts'], 'the drop is CALLED only by the store');
});

test('ONE CALLER: the drop is reached from the owner\'s contact book alone, from ONE call inside the Keep handler, and that handler is reached only from the notice\'s onKeep (no import, restore, sync, gate arrival, exchange or the Galaxy)', () => {
  assert.deepEqual(filesWith(/\bdropRemovedForOwner\b/), ['src/components/ContactManagement.tsx', 'src/lib/identity/client-store.ts']);
  assert.deepEqual(filesWith(/trust\/readd-removed['"]/), ['src/components/ContactManagement.tsx', 'src/lib/identity/client-store.ts']);
  const cm = codeOnly(readFileSync(join(SRC, 'components', 'ContactManagement.tsx'), 'utf8'));
  assert.equal((cm.match(/\bdropRemovedForOwner\(/g) ?? []).length, 1, 'exactly one call');
  const a = cm.indexOf('const keepRemovedPerson = async');
  const b = cm.indexOf('\n  };', a);
  assert.ok(a > 0 && b > a, 'the Keep handler is found');
  assert.match(cm.slice(a, b), /\bdropRemovedForOwner\(/, 'the one call is inside the Keep handler');
  const uses = cm.match(/\bkeepRemovedPerson\b/g) ?? [];
  assert.equal(uses.length, 2, 'the handler is defined once and used once');
  assert.match(cm, /onKeep: \(\) => \{ void keepRemovedPerson\(\); \}/, 'and the one use is the notice\'s onKeep');
});

test('PRIVATE ONLY: the notice exists only behind an opt-in prop that the contact book alone passes; the Galaxy (shown to people in person) never passes it, so its words cannot render there', () => {
  assert.deepEqual(filesWith(/\bremovedBeforeNotice\b/), ['src/components/ContactManagement.tsx', 'src/components/contacts/ContactActionCard.tsx']);
  assert.deepEqual(filesWith(/\bRemovedBeforeNotice\b/), ['src/components/contacts/ContactActionCard.tsx', 'src/components/contacts/RemovedBeforeNotice.tsx']);
  assert.deepEqual(filesWith(/removed-before-copy/), ['src/components/contacts/RemovedBeforeNotice.tsx']);
  assert.deepEqual(filesWith(/\bwasRemovedBefore\b/), ['src/components/ContactManagement.tsx', 'src/lib/trust/readd-removed.ts']);
  const card = codeOnly(readFileSync(join(SRC, 'components', 'contacts', 'ContactActionCard.tsx'), 'utf8'));
  assert.match(card, /removedBeforeNotice\?: RemovedBeforeNoticeProps;/, 'the prop is optional: a card without it renders no notice');
  assert.match(card, /\{removedBeforeNotice \? <RemovedBeforeNotice \{\.\.\.removedBeforeNotice\} \/> : null\}/, 'and renders it only when given');
  const galaxy = codeOnly(readFileSync(join(SRC, 'components', 'TrustMap.tsx'), 'utf8'));
  assert.doesNotMatch(galaxy, /removedBefore|RemovedBefore|removed-before|You removed this person/i, 'the Galaxy never passes, imports or spells the notice');
  assert.deepEqual(filesWith(/You removed this person before/), ['src/components/contacts/removed-before-copy.ts'], 'the sentence lives in the one copy module');
  // Every mount of the card is known, and none spreads props into it (a spread could forward the opt-in prop through a parent). A new mount fails here until it is looked at.
  assert.deepEqual(filesWith(/<ContactActionCard\b/), ['src/components/ContactManagement.tsx', 'src/components/TrustMap.tsx'], 'the card has exactly these two mounts');
  for (const f of ['src/components/ContactManagement.tsx', 'src/components/TrustMap.tsx']) {
    const spans = cardElements(codeOnly(readFileSync(join(CWD, f), 'utf8')));
    assert.equal(spans.length, 1, `${f}: one card element`);
    assert.equal(hasJsxSpread(spans[0]), false, `${f}: no spread into the card`);
  }
});

test('NEG: the element scan SEES a JSX spread into the card (even when a prop value holds JSX with its own "/>"), and does NOT mistake an object spread inside a prop value for one', () => {
  const planted = '<ContactActionCard a={1} actions={<><X /></>} {...rest} b="2" />\n<Other {...ok} />';
  const els = cardElements(planted);
  assert.equal(els.length, 1);
  assert.equal(hasJsxSpread(els[0]), true);
  assert.doesNotMatch(els[0], /ok/, 'the neighbouring element is not part of the card element');
  const fine = '<ContactActionCard a={cur ? { ...cur, failed: false } : cur} actions={<><X /></>} b="2" />';
  assert.equal(hasJsxSpread(cardElements(fine)[0]), false, 'an object spread inside a prop value is not a JSX spread');
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

test('ROOTS: the pins scan every top-level directory that holds application TypeScript (app/ and src/); a new one fails until it is classified', () => {
  const tops = readdirSync(CWD)
    .filter((n) => !['node_modules', '.next', '.git', 'pw-out'].includes(n) && statSync(join(CWD, n)).isDirectory() && sourceFiles(join(CWD, n)).length > 0)
    .sort();
  assert.deepEqual(tops.filter((t) => !NOT_APP_ROOTS.includes(t)), APP_ROOTS, 'a top-level directory with TypeScript is neither scanned nor classified as a harness');
});

test('NEG: the scan SEES a call to the drop planted under app/ (outside src/), so the pins above would go red; and a comment-only mention is not a call', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'readd-pin-'));
  try {
    mkdirSync(join(tmp, 'app')); mkdirSync(join(tmp, 'src'));
    writeFileSync(join(tmp, 'app', 'page.tsx'), "export const f = () => dropRemovedForOwner('o', 'a'.repeat(64));\n");
    writeFileSync(join(tmp, 'src', 'note.ts'), '// dropRemovedForOwner is mentioned in a comment only\nexport const n = 1;\n');
    assert.deepEqual(scan(tmp, APP_ROOTS, /\bdropRemovedForOwner\b/), ['app/page.tsx']);
    assert.deepEqual(scan(tmp, ['src'], /\bdropRemovedForOwner\b/), [], 'scanning only src/ would have missed it (the gap this closes)');
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
