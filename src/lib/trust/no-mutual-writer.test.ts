// Nothing on this device may write "they trust me" or "reciprocal" from a sync signal. A mutual bond is meant to be learned only
// from the blind match; a function that took a boolean and stored it as that state (reciprocal = trusted && theyTrustMe) was a ready-made
// way to show a one-way "they trust me" before a bond is mutual. This is a static source guard over every non-test source file under
// src and app. It is an ALLOW-LIST: wherever either field name appears as a key, an assignment target or a bare name, the value must be
// exactly null or false (or the field's type); a read through a member access is fine. Anything else, including a shorthand, is a
// violation, whatever the form of the value.
// NOT covered: a copy of a WHOLE stored edge (vault merge, restore) carries the owner's own stored value and names neither field.
// Comments: a line that is entirely a comment is ignored; code on the same line as a comment marker is still read, and a comment
// that spells a banned form on a code line is reworded.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const SRC = new URL('../../', import.meta.url).pathname;
const APP = new URL('../../../app/', import.meta.url).pathname;

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) { sourceFiles(p, out); continue; }
    if (!/\.(ts|tsx)$/.test(name) || /\.test\.(ts|tsx)$/.test(name)) continue;
    out.push(p);
  }
  return out;
}

const WHOLE_LINE_COMMENT = /^\s*(?:\/\/|\/\*(?:(?!\*\/).)*\*\/\s*$|\/\*(?!.*\*\/)|\*(?!\/)|\*\/\s*$)/;
const FIELD = /\b(?:they_trust_me|reciprocal)\b/g;
const NULL_OR_FALSE = /^\s*(?:null|false)\s*(?=[,;})\n]|$)/;
const TYPE_FORM = /^\s*\??\s*:\s*(?:boolean(?:\s*\|\s*null)?|unknown)\s*(?=[;,}\n]|$)/;

/** Every place a field name is written, or may be written, with anything other than null or false. */
function violations(text: string): { line: number; text: string }[] {
  const lines = text.split('\n').map(l => (WHOLE_LINE_COMMENT.test(l) ? '' : l));
  const s = lines.join('\n');
  const out: { line: number; text: string }[] = [];
  for (const m of s.matchAll(FIELD)) {
    const i = m.index as number; const end = i + m[0].length;
    const prev = s.slice(0, i).replace(/\s+$/, ''); const after = s.slice(end, end + 80);
    const last = prev.slice(-1);
    let ok: boolean;
    if (last === '.') { // member access (also ?.): a read unless it is assigned
      const a = after.match(/^\s*=(?!=)([\s\S]*)/);
      ok = !a || NULL_OR_FALSE.test(a[1]);
    } else if ((last === "'" || last === '"' || last === '`') && after.startsWith(last)) { // a quoted name
      const rest = after.slice(1);
      const a = /\[\s*$/.test(prev.slice(0, -1)) ? rest.match(/^\s*\]\s*=(?!=)([\s\S]*)/) : null; // x['field'] = value
      const k = rest.match(/^\s*:([\s\S]*)/);                                                     // { 'field': value }
      ok = a ? NULL_OR_FALSE.test(a[1]) : k ? (NULL_OR_FALSE.test(k[1]) || TYPE_FORM.test(rest)) : true; // else a plain string, e.g. a union member
    } else {
      const k = after.match(/^\s*:([\s\S]*)/); const v = after.match(/^\s*=(?!=)([\s\S]*)/);
      ok = k ? (NULL_OR_FALSE.test(k[1]) || TYPE_FORM.test(after)) : v ? NULL_OR_FALSE.test(v[1]) : TYPE_FORM.test(after);
    }
    if (!ok) { const line = s.slice(0, i).split('\n').length; out.push({ line, text: lines[line - 1].trim() }); }
  }
  return out;
}

const files = [...sourceFiles(SRC), ...sourceFiles(APP)];
const rel = (f: string) => (f.startsWith(SRC) ? 'src/' + f.slice(SRC.length) : 'app/' + f.slice(APP.length));
const found = new Map(files.map(f => [rel(f), violations(readFileSync(f, 'utf8'))]));

// The demo seed passes its own flag through; these are its two lines. It is the ONE exemption, and it is exact: a third line
// there is a violation, and so is one of the two going away (the exemption would be stale).
const DEMO_SEED = 'src/lib/trust/sample-circle.ts';
const DEMO_SEED_LINES = ['they_trust_me: c.reciprocal ?? null,', 'reciprocal: !!c.reciprocal,'];

test('the scanner flags every form of a writer (control: each form alone) and passes the allowed forms', () => {
  const bad = [
    'x.they_trust_me = sig;', 'const o = { they_trust_me };', 'const o = { they_trust_me: !!sig };', 'const o = { they_trust_me: (sig) };',
    'const o = { they_trust_me: false || sig };', 'const o = { reciprocal: false || sig };', "x.mutual['reciprocal'] = true;",
    'const o = { they_trust_me: true };', 'const o = { reciprocal: true };', 'x.reciprocal = true;', 'const o = { reciprocal: edge.trusted && sig };',
    'const o = { reciprocal };', 'const { reciprocal } = m;', "const o = { 'reciprocal': true };", 'const o = { "they_trust_me": sig };', 'const o = { they_trust_me:\n  sig };',
    "const u = 'a//b'; const o = { they_trust_me: true };", '/* note */ x.reciprocal = true;', 'x.reciprocal = sig; // done',
  ];
  for (const code of bad) assert.equal(violations(code).length >= 1, true, `must flag: ${code}`);
  const good = [
    'const o = { they_trust_me: null, reciprocal: false };', 'const o = { they_trust_me: false };', 'x.reciprocal = false;', 'x.they_trust_me = null;',
    "x.mutual['reciprocal'] = false;", 'const a = c.mutual?.reciprocal === true;', 'const b = !!e.mutual?.reciprocal;', 'const c = m.they_trust_me !== null;',
    'mutual?: { they_trust_me?: boolean | null; last_sync?: string | null; reciprocal?: boolean };', '  they_trust_me: boolean | null;', '  reciprocal: boolean;',
    '// reciprocal: sig is spelled out in a comment', ' * they_trust_me = true is spelled out in a comment', '/* reciprocal = true */', "type T = 'pending' | 'reciprocal';", "if (k === 'reciprocal') {}", '{ they_trust_me?: unknown; reciprocal?: unknown }',
  ];
  for (const code of good) assert.deepEqual(violations(code), [], `must pass: ${code}`);
});

test('the guard really scans the source tree (control: it sees the files it must see)', () => {
  assert.ok(files.filter(f => f.startsWith(SRC)).length > 200, 'expected many files under src');
  assert.ok(files.filter(f => f.startsWith(APP)).length >= 20, 'expected the files under app');
  assert.ok([...found.keys()].includes('app/page.tsx'), 'control: a known app file is scanned');
  assert.ok(readFileSync(files.find(f => f.endsWith('lib/trust/types.ts')) as string, 'utf8').includes('they_trust_me'), 'control: the field type lives in a scanned file');
});

test('NEG: no source file defines or calls updateMutualState (a boolean from a sync signal stored as mutual state)', () => {
  assert.deepEqual(files.filter(f => /updateMutualState/.test(readFileSync(f, 'utf8'))).map(rel), []);
});

test('NEG: no source file other than the demo seed writes they_trust_me or reciprocal as anything but null or false', () => {
  const all = [...found].filter(([f]) => f !== DEMO_SEED).flatMap(([f, v]) => v.map(x => `${f}:${x.line} ${x.text}`));
  assert.deepEqual(all, []);
});

test('the demo seed holds exactly its two known pass-through lines (a third line, or one going away, is a failure)', () => {
  assert.deepEqual((found.get(DEMO_SEED) ?? []).map(x => x.text).sort(), [...DEMO_SEED_LINES].sort());
});
