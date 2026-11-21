// Who may READ the stored fields mutual.they_trust_me and mutual.reciprocal. A person who is trusted by someone they have not trusted back
// must see nothing that implies it: the only thing a screen paints from trust is the phase from livingEdgeStatus / trustPhaseVisual,
// where an inbound one-way trust is shown exactly as Known. A new module that reads either field directly could paint a one-way state
// around that and nothing would notice. This is a static source guard over every non-test file under src and app: the files that read
// either field must be exactly the list below. A new reader fails it (read the phase through the map above, or add the file here with a
// reason); a file on the list that stops reading fails it too (remove the entry).
// A READ is any mention of a field name that is not a key or a type member, not a plain string, and not a whole-line comment: a member
// access, a bracket access, a destructuring, a bare variable. How the fields are WRITTEN is another test (no-mutual-writer.test.ts).
// NOT covered: a read that never names a field (a whole stored edge passed to a screen), which the trust phase map is the answer to.
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

/** Is the object braces around position i a destructuring PATTERN (a read) and not an object literal (a write)? */
function inPattern(s: string, i: number): boolean {
  let depth = 0; let j = i;
  for (; j >= 0; j--) { if (s[j] === '}') depth++; else if (s[j] === '{') { if (depth === 0) break; depth--; } }
  if (j < 0) return false;
  depth = 0; let k = j;
  for (; k < s.length; k++) { if (s[k] === '{') depth++; else if (s[k] === '}') { depth--; if (depth === 0) break; } }
  const tail = s.slice(k + 1, k + 12); const before = s.slice(0, j).replace(/\s+$/, '').slice(-1);
  return /^\s*=(?![=>])/.test(tail) || (/^\s*:/.test(tail) && (before === '(' || before === ',')) || (/^\s*\)\s*=>/.test(tail) && before === '(');
}

/** The number of reads of the two fields in one file's text. */
function reads(text: string): number {
  const s = text.split('\n').map(l => (WHOLE_LINE_COMMENT.test(l) ? '' : l)).join('\n');
  let n = 0;
  for (const m of s.matchAll(FIELD)) {
    const i = m.index as number; const end = i + m[0].length;
    const prev = s.slice(0, i).replace(/\s+$/, ''); const after = s.slice(end, end + 40);
    const last = prev.slice(-1);
    if (last === "'" || last === '"' || last === '`') {
      if (!after.startsWith(last)) { n++; continue; }
      if (/\[\s*$/.test(prev.slice(0, -1))) { n++; continue; }   // x['field'] is a read
      continue;                                                   // a plain string, or a quoted key
    }
    // the last significant character, with trailing line comments removed (a key often follows a line that ends in one)
    const prevSig = s.slice(0, i).replace(/\/\/[^\n]*/g, '').replace(/\s+$/, '');
    const keyPosition = prevSig === '' || /[{,;(]$/.test(prevSig);
    if (keyPosition && /^\s*\??\s*:/.test(after) && !inPattern(s, i)) continue;   // a key or a type member (not a destructuring rename)
    n++;
  }
  return n;
}

const READERS: Record<string, string> = {
  'src/lib/sync/know-layer-sync.ts': 'counts a bond as mutual only from the stored flag',
  'src/lib/trust/affirm-wire-purge.ts': 'clears the values the removed affirm wire left behind',
  'src/lib/trust/peer-trust-chords.ts': 'draws a chord between two of your own contacts when both checks agree',
  'src/lib/trust/sample-circle.ts': 'the demo seed passes its own flag through',
  'src/lib/trust/trust-map-browse-layout.ts': 'lays out the browse view',
};

const files = [...sourceFiles(SRC), ...sourceFiles(APP)];
const rel = (f: string) => (f.startsWith(SRC) ? 'src/' + f.slice(SRC.length) : 'app/' + f.slice(APP.length));
const readers = files.filter(f => reads(readFileSync(f, 'utf8')) > 0).map(rel).sort();

test('the scanner counts every form of a read (control: each form alone) and ignores keys, types, strings and comments', () => {
  const read = [
    'const a = x.reciprocal;', 'const a = x?.reciprocal;', 'const a = x.mutual?.they_trust_me;', "const a = x['reciprocal'];", 'const { reciprocal } = m;',
    'function f({ they_trust_me }: M) {}', 'const a = reciprocal;', 'const a = ok ? reciprocal : 1;', 'const a = !!e.mutual?.reciprocal;',
    'const a = c.reciprocal ?? null;', "const a = x['they_trust_me'];", 'const { a, reciprocal: r } = m;', 'const { reciprocal: r } = m;', 'function f({ reciprocal: r }: M) {}', 'const g = ({ they_trust_me: t }) => t;',
  ];
  for (const code of read) assert.equal(reads(code) >= 1, true, `must count: ${code}`);
  const notRead = [
    'const o = { reciprocal: false };', '  reciprocal?: boolean;', '  they_trust_me: boolean | null;', "type T = 'pending' | 'reciprocal';",
    "if (k === 'reciprocal') {}", "const o = { 'reciprocal': false };", '// x.reciprocal is read here', ' * x.they_trust_me is read here', '/* x.reciprocal */',
    'mutual?: { they_trust_me?: boolean | null; last_sync?: string | null; reciprocal?: boolean };',
    'const a = ok ? { reciprocal: false } : x;', 'f({ reciprocal: false });', 'const o: T = { they_trust_me: null, reciprocal: false };',
  ];
  for (const code of notRead) assert.equal(reads(code), 0, `must not count: ${code}`);
});

test('the guard really scans the source tree (control: it sees the files it must see)', () => {
  assert.ok(files.filter(f => f.startsWith(SRC)).length > 200, 'expected many files under src');
  assert.ok(files.filter(f => f.startsWith(APP)).length >= 20, 'expected the files under app');
  assert.ok(readers.length >= 3, 'control: the known readers are found');
});

test('only the listed files read the stored mutual fields', () => {
  const unlisted = readers.filter(f => !(f in READERS));
  assert.deepEqual(unlisted, [], 'these files read they_trust_me or reciprocal: a screen must not paint a one-way state from them. Read the trust phase through livingEdgeStatus / trustPhaseVisual, or add the file to READERS with a reason');
  const stale = Object.keys(READERS).filter(f => !readers.includes(f));
  assert.deepEqual(stale, [], 'these listed files no longer read either field: remove them from READERS');
});
