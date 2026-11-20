// Run: npx tsx --test src/components/held/hold-view-wiring.test.ts
// Static pins for the hold view. Like the other fences these READ source text: they prove the pieces are connected the way the rulings say; the behaviour is run in a real browser by e2e/hold-view.spec.ts.
//   - THE VIEW SENDS NOTHING: no file in the view's folder imports a send, relay, mailbox, ratchet or receipt module, and none uses a network API. Only held-port.ts touches the local stores, and only for four named functions.
//   - THE ENTRY CARRIES NO COUNT and reads nothing until the owner chooses it.
//   - Delete's confirm defaults to CANCEL (it has the focus); moving has no confirm.
//   - The components spell no sentence of their own, and offer no reply and no export (not in this view).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const DIR = 'src/components/held';
const codeOnly = (t: string): string => t.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:\w'"`])\/\/.*$/gm, '$1');
const read = (rel: string): string => readFileSync(join(ROOT, rel), 'utf8');
const code = (rel: string): string => codeOnly(read(rel));
const FILES = readdirSync(join(ROOT, DIR)).filter((f) => /\.(ts|tsx)$/.test(f) && !/\.test\./.test(f)).sort();
/** EVERY module a source text pulls in, in every form: `import x from 'm'`, a side-effect `import 'm'`, `export ... from 'm'`, a dynamic `import('m')` and `require('m')`. (A lazy `import ... from` match swallows a side-effect import into the NEXT line's `from`, so it is not used.) */
const specifiers = (src: string): string[] => {
  const t = codeOnly(src);
  const found = [
    ...t.matchAll(/^(?:import|export)\s+(?:[^'";]*?\sfrom\s+)?['"]([^'"]+)['"]/gm),
    ...t.matchAll(/\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g),
    ...t.matchAll(/\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g),
  ];
  return found.map((m) => m[1]);
};
const imports = (rel: string): string[] => specifiers(read(rel));

test('HW1 the folder is exactly these files (a new one must be added here on purpose, with a reason)', () => {
  assert.deepEqual(FILES, ['HeldMessagesSection.tsx', 'HeldMessagesView.tsx', 'held-port.ts', 'hold-view-copy.ts', 'hold-view-model.ts']);
});

test('HW2 SENDS NOTHING (imports): no file in the folder imports a send, relay, mailbox, ratchet, receipt, outbox or sync module; only held-port.ts touches a store, and only these four', () => {
  const forbidden = /transport|relay|mailbox|ratchet|receipt|send|outbox|deliver|consume|poll|sync\/|direct-session|note-auth/i;
  for (const f of FILES) for (const i of imports(`${DIR}/${f}`)) assert.doesNotMatch(i, forbidden, `${f} imports ${i}`);
  const storeImporters = FILES.filter((f) => imports(`${DIR}/${f}`).some((i) => /messaging\/store$|identity\/client-store$/.test(i)));
  assert.deepEqual(storeImporters, ['held-port.ts'], 'only the port module touches a store');
  const port = read(`${DIR}/held-port.ts`);
  const named = [...port.matchAll(/import\s*\{([^}]*)\}\s*from\s+'@\/lib\/messaging\/store'/g)].flatMap((m) => m[1].split(',').map((s) => s.trim()).filter(Boolean)).sort();
  assert.deepEqual(named, ['deleteHeldNote', 'listHeldFrom', 'listHeldSenders', 'releaseHeldNote']);
  // the view, the model and the section reach the messaging rules only through the pure rule file and the types
  for (const f of ['HeldMessagesView.tsx', 'HeldMessagesSection.tsx', 'hold-view-model.ts']) {
    for (const i of imports(`${DIR}/${f}`)) if (i.startsWith('@/lib/messaging/')) assert.ok(i === '@/lib/messaging/held-note' || i === '@/lib/messaging/types', `${f} imports ${i}`);
  }
});

test('HW2c the fence sees every import form (a control: a fence that cannot see a form proves nothing about it)', () => {
  const sample = [
    "import { a } from '@/x/named';",
    "import b, { c } from '@/x/default-and-named';",
    "import type { T } from '@/x/type-only';",
    "import '@/x/side-effect';",
    "import { d,",
    "  e } from '@/x/multi-line';",
    "export { f } from '@/x/re-export';",
    "export * from '@/x/star';",
    "const g = await import('@/x/dynamic');",
    "const h = require('@/x/required');",
    "// import '@/x/in-a-comment';",
    "/* import '@/x/in-a-block'; */",
  ].join('\n');
  assert.deepEqual(specifiers(sample).sort(), ['@/x/default-and-named', '@/x/dynamic', '@/x/multi-line', '@/x/named', '@/x/re-export', '@/x/required', '@/x/side-effect', '@/x/star', '@/x/type-only']);
});

test('HW2d A FAILED LOAD IS NEVER THE EMPTY STATE (a source-shape pin, NOT a behaviour test: no spec can lock the app\'s own store; the screens\' own load-failed lines are the visible half): the view\'s and the section\'s load catch set the failure flag and set no list', () => {
  const view = code(`${DIR}/HeldMessagesView.tsx`);
  const viewCatch = /await port\.listHeld\(fingerprint\);[\s\S]*?\} catch \{([\s\S]*?)\}\s*\}, \[port, fingerprint\]\)/.exec(view);
  assert.ok(viewCatch, 'the view\'s load catch is found (control: the pattern matches the source it pins)');
  assert.match(viewCatch[1], /setLoadFailed\(true\)/);
  assert.doesNotMatch(viewCatch[1], /setNotes\s*\(/, 'a failed load must not become "nothing held"');
  const section = code(`${DIR}/HeldMessagesSection.tsx`);
  const secCatch = /await Promise\.all\(\[sectionPort\.senders\(\), sectionPort\.frozen\(\)\]\);[\s\S]*?\} catch \{([\s\S]*?)\}\s*\};/.exec(section);
  assert.ok(secCatch, 'the section\'s load catch is found (control)');
  assert.match(secCatch[1], /setLoadFailed\(true\)/);
  assert.doesNotMatch(secCatch[1], /setGroups\s*\(\s*\[/, 'a failed load must not become an empty list of senders');
  assert.match(secCatch[1], /setGroups\(null\)/, 'and the list is cleared, not kept from before');
});

test('HW3 SENDS NOTHING (calls): no file in the folder uses a network or signalling API', () => {
  for (const f of FILES) assert.doesNotMatch(code(`${DIR}/${f}`), /\bfetch\s*\(|XMLHttpRequest|sendBeacon|WebSocket|EventSource|BroadcastChannel|postMessage|navigator\.|Notification\b|window\.open/, f);
});

test('HW4 THE ENTRY CARRIES NO COUNT and reads nothing before the owner chooses it: contact page and panel', () => {
  const cm = code('src/components/ContactManagement.tsx');
  // the page entry: a menu item whose label is the copy constant, shown for a blocked contact with a fingerprint, whether or not anything is held
  assert.match(cm, /\{isContactBlocked\(focused\) && fp \? \(\s*<CardMenuItem\s+testId="held-entry"\s+label=\{HOLD_VIEW_ENTRY\}\s+onClick=\{\(\) => \{ setHeldOpenFor\(fp\.toLowerCase\(\)\); closeMenu\(\); \}\}\s*\/>\s*\) : null\}/, 'the entry is exactly this, with no count');
  assert.doesNotMatch(cm, /listHeld|listHeldSenders|countHeld|held_counts|readHeldCount/, 'the contact page reads no held note and no count: only the view does, once it is opened');
  assert.match(cm, /\{heldOpenFor && fp && heldOpenFor === fp\.toLowerCase\(\) \? \(\s*<HeldMessagesView key=\{heldOpenFor\} fingerprint=\{heldOpenFor\} name=\{focused\.name \|\| null\} port=\{realHeldPort\} \/>\s*\) : null\}/, 'the view is drawn only for the contact the owner opened it for');
  assert.equal((cm.match(/<HeldMessagesView\b/g) ?? []).length, 1);
  // the panel entry: a button whose only child is the label, and the ports are read inside toggle() only
  const sec = code(`${DIR}/HeldMessagesSection.tsx`);
  assert.match(sec, /<button type="button" data-testid="held-section-entry" aria-expanded=\{open\} onClick=\{\(\) => \{ void toggle\(\); \}\} style=\{cardVerbBtnStyle\(\{ muted: true \}\)\}>\s*\{HOLD_VIEW_ENTRY\}\s*<\/button>/);
  const body = sec.slice(sec.indexOf('const toggle = async'), sec.indexOf('return ('));
  assert.equal((sec.match(/sectionPort\.senders\(\)/g) ?? []).length, 1);
  assert.ok(body.includes('sectionPort.senders()'), 'senders are read inside toggle()');
  assert.doesNotMatch(sec.slice(sec.indexOf('return (')), /sectionPort\./, 'and nowhere in the rendering');
});

test('HW5 where it is mounted: the view in the contact page and the section, the section in the panel, and nowhere else', () => {
  const walk = (dir: string): string[] => readdirSync(join(ROOT, dir), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(`${dir}/${e.name}`) : /\.(ts|tsx)$/.test(e.name) && !/\.test\./.test(e.name) ? [`${dir}/${e.name}`] : []));
  const all = [...walk('src'), ...walk('app')];
  const users = (name: string): string[] => all.filter((f) => !f.startsWith(`${DIR}/`) && new RegExp(`<${name}\\b`).test(code(f)));
  assert.deepEqual(users('HeldMessagesView'), ['src/components/ContactManagement.tsx']);
  assert.deepEqual(users('HeldMessagesSection'), ['src/components/SoverentityFrontend.tsx']);
  assert.deepEqual(all.filter((f) => !f.startsWith(`${DIR}/`) && /held\/held-port/.test(read(f))).sort(), ['src/components/ContactManagement.tsx', 'src/components/SoverentityFrontend.tsx']);
});

test('HW6 DELETE defaults to CANCEL: both confirms put the focus on Cancel and never on Delete; moving has no confirm at all', () => {
  const v = code(`${DIR}/HeldMessagesView.tsx`);
  assert.equal((v.match(/autoFocus/g) ?? []).length, 2, 'two confirms, one default each');
  assert.equal((v.match(/data-testid="held-confirm-cancel" autoFocus/g) ?? []).length, 2, 'the focus is on Cancel, both times');
  assert.doesNotMatch(v, /data-testid="held-confirm-delete"[^>]*autoFocus/, 'never on Delete');
  assert.equal((v.match(/setConfirm\(\{ kind:/g) ?? []).length, 2, 'only the two Delete buttons open a confirm');
  assert.match(v, /data-testid="held-move-all" disabled=\{busy\} onClick=\{\(\) => \{ void moveAll\(\); \}\}/, 'Move all goes straight to the move');
  assert.match(v, /data-testid="held-move-one" disabled=\{busy\} onClick=\{\(\) => \{ void moveOne\(n\.note_id\); \}\}/, 'Move goes straight to the move');
});

test('HW7 the components spell NO sentence of their own: every word on screen is a copy constant (and no number of the limits is written in them)', () => {
  for (const f of ['HeldMessagesView.tsx', 'HeldMessagesSection.tsx']) {
    const src = code(`${DIR}/${f}`);
    assert.doesNotMatch(src, />\s*[A-Za-z][^<>{}]*\s[^<>{}]*</, `${f}: no literal text between tags`);
    const lits = [...src.matchAll(/(['"`])((?:(?!\1).)*)\1/g)].map((m) => m[2]);
    assert.deepEqual(lits.filter((t) => /[A-Z][a-z]+( [a-z']+){2,}/.test(t)), [], `${f}: no quoted sentence`);
    assert.doesNotMatch(src, /\b(30|500)\b/, `${f}: the age limit and the cap come from the constants`);
  }
});

test('HW8 NOT IN THIS VIEW: no reply, no export (their own items, with their own reviews): none of the words appears in the components', () => {
  for (const f of ['HeldMessagesView.tsx', 'HeldMessagesSection.tsx', 'hold-view-model.ts']) assert.doesNotMatch(code(`${DIR}/${f}`), /\breply\b|\bexport\b(?! (type|function|const|default|\{))|evidence|download|share/i, f);
});

test('HW9 the unreviewed lines are the ONLY copy not pinned by a hash, and they are marked as such in the copy module', () => {
  const c = read(`${DIR}/hold-view-copy.ts`);
  assert.equal((c.match(/NOT YET REVIEWED/g) ?? []).length, 2, 'two marked blocks: the load failure, and the move results for a sender who is not frozen');
  for (const name of ['HOLD_VIEW_LOAD_FAILED', 'HOLD_VIEW_MOVED_ONE_NOT_FROZEN', 'HOLD_VIEW_MOVED_ALL_NOT_FROZEN']) assert.match(c, new RegExp(`export const ${name} =`), name);
});
