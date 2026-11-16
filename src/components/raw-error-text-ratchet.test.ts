// src/components/raw-error-text-ratchet.test.ts
// A ratchet on the code-only copy rule: a screen sentence is chosen by a code, and an error's own text is never shown. This test counts the lines under
// src/components that read an error's `.message` (the pattern that puts a thrower's text into screen state), per file, and holds that count against a baseline.
//   - The count can only go down. A NEW such line, in an old file or a new one, fails. A removed line fails too until the baseline is lowered in the same change,
//     so the baseline is always exact and a stale number never leaves room for a new site to hide.
//   - The baseline holds COUNTS PER PATH and nothing else, never the text of a line.
//   - It counts MATCHES, not proven sinks: a line that only logs or branches on the text is counted too. Draining the baseline means moving each site to a
//     code-chosen sentence (see contact-io-errors.ts) or, for a log or a branch, to a typed code.
// Run: npx tsx --test src/components/raw-error-text-ratchet.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const BASELINE_FILE = join(HERE, 'raw-error-text-baseline.json');
const COMMON = ['err', 'e', 'error', 'ex', 'exception', 'cause'];

/** Source with comments blanked (line numbers kept). String contents are left alone: this is a line scanner, not a parser. */
export function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' ')).replace(/(^|[^:'"`\\])\/\/.*$/gm, '$1');
}

/** The 1-based lines that read an error's own text: `<caught variable>.message`, or `x instanceof Error ? x.message : ...`. A caught variable is a common name or any name bound by a catch clause or a .catch callback in the same file. */
export function rawErrorTextLines(source: string): number[] {
  const code = stripComments(source);
  const names = new Set(COMMON);
  for (const m of code.matchAll(/\bcatch\s*\(\s*([A-Za-z_$][\w$]*)/g)) names.add(m[1]);
  for (const m of code.matchAll(/\.catch\(\s*\(?\s*([A-Za-z_$][\w$]*)/g)) names.add(m[1]);
  const named = new RegExp(`(^|[^\\w$.])(${[...names].map((n) => n.replace(/\$/g, '\\$')).join('|')})\\.message\\b`);
  const tern = /\binstanceof Error \? [A-Za-z_$][\w$.]*\.message\b/;
  const out: number[] = [];
  code.split('\n').forEach((line, i) => { if (tern.test(line) || named.test(line)) out.push(i + 1); });
  return out;
}

function walk(dir: string, acc: string[] = []): string[] {
  for (const f of readdirSync(dir).sort()) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) walk(p, acc);
    else if (/\.tsx?$/.test(f) && !/\.test\.tsx?$/.test(f) && !/\.d\.ts$/.test(f)) acc.push(p);
  }
  return acc;
}

export function countsByPath(root: string = ROOT): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const p of walk(join(root, 'src', 'components'))) {
    const n = rawErrorTextLines(readFileSync(p, 'utf8')).length;
    if (n > 0) counts[relative(root, p).split(sep).join('/')] = n;
  }
  return counts;
}

test('RT1 the scanner flags the lines that show an error\'s own text, and only those (controls)', () => {
  const flagged = (s: string) => rawErrorTextLines(s).length;
  assert.equal(flagged("setError(err instanceof Error ? err.message : 'x');"), 1);
  assert.equal(flagged("setError(e instanceof Error ? e.message : 'x');"), 1);
  assert.equal(flagged("setNote(error.message);"), 1);
  assert.equal(flagged("setError(thing instanceof Error ? thing.message : 'x');"), 1, 'the instanceof form alone, for a name that is not a caught variable');
  assert.equal(flagged("const msg = ex.message;"), 1);
  assert.equal(flagged("try { f(); } catch (caught) {\n  setError(caught.message);\n}"), 1, 'a caught variable with an uncommon name');
  assert.equal(flagged("p.catch((reason) => setError(reason.message));"), 1, 'a .catch callback variable');
  assert.equal(flagged("if (err instanceof Foo) { setE(err.message); } else { setE(err.message); }"), 1, 'a line counts once');
  assert.equal(flagged("setError(view.message);"), 0, 'a typed sentence is not an error');
  assert.equal(flagged("setX(result.message);"), 0);
  assert.equal(flagged("const m = failure.message;"), 0, 'a name that is not a caught variable');
  assert.equal(flagged("// setError(err.message);"), 0, 'a line comment');
  assert.equal(flagged("/* setError(err.message); */ const a = 1;"), 0, 'a block comment');
  assert.equal(flagged("const s = 'prefix_err.message';"), 0, 'part of a longer name');
  assert.equal(flagged("setError(something.err.message);"), 0, 'a member of another object');
});

test('RT2 the baseline is shaped as counts per path and nothing else', () => {
  const b = JSON.parse(readFileSync(BASELINE_FILE, 'utf8')) as { rule: string; counts: Record<string, number> };
  assert.equal(typeof b.rule, 'string');
  assert.deepEqual(Object.keys(b).sort(), ['counts', 'rule']);
  const keys = Object.keys(b.counts);
  assert.deepEqual(keys, [...keys].sort(), 'paths are sorted');
  for (const [k, v] of Object.entries(b.counts)) {
    assert.ok(/^src\/components\/.+\.tsx?$/.test(k) && !/\.test\./.test(k), `a component path: ${k}`);
    assert.ok(Number.isInteger(v) && v > 0, `a positive count, not a zero or text: ${k}`);
  }
});

/** The ratchet itself: what grew past the baseline, and what shrank below it (a stale baseline). */
export function ratchet(now: Record<string, number>, allowed: Record<string, number>): { grew: string[]; shrank: string[] } {
  const grew: string[] = [], shrank: string[] = [];
  for (const p of [...new Set([...Object.keys(now), ...Object.keys(allowed)])].sort()) {
    const have = now[p] ?? 0, base = allowed[p] ?? 0;
    if (have > base) grew.push(`${p}: ${have} > baseline ${base}`);
    if (have < base) shrank.push(`${p}: ${have} < baseline ${base}`);
  }
  return { grew, shrank };
}

test('RT3 the ratchet logic (controls): growth, a new path, a stale baseline, and an exact match', () => {
  assert.deepEqual(ratchet({ a: 2 }, { a: 2 }), { grew: [], shrank: [] });
  assert.deepEqual(ratchet({ a: 3 }, { a: 2 }), { grew: ['a: 3 > baseline 2'], shrank: [] }, 'one more in an old file');
  assert.deepEqual(ratchet({ a: 2, b: 1 }, { a: 2 }), { grew: ['b: 1 > baseline 0'], shrank: [] }, 'a new file may not show any');
  assert.deepEqual(ratchet({ a: 1 }, { a: 2 }), { grew: [], shrank: ['a: 1 < baseline 2'] }, 'a removed line must lower the baseline');
  assert.deepEqual(ratchet({}, { a: 2 }), { grew: [], shrank: ['a: 0 < baseline 2'] }, 'a drained or deleted file must leave the baseline');
  assert.deepEqual(ratchet({ a: 3, b: 1 }, { a: 4 }), { grew: ['b: 1 > baseline 0'], shrank: ['a: 3 < baseline 4'] }, 'both at once');
});

test('RT5 the walk, the scan and the ratchet together, on a synthetic tree: .tsx and .ts, nested folders, tests ignored, a new file, a removed line', () => {
  const root = mkdtempSync(join(tmpdir(), 'rawerr-'));
  try {
    const put = (rel: string, body: string) => { const p = join(root, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, body); };
    put('src/components/A.tsx', "try {} catch (err) {\n  setError(err.message);\n  setNote(err instanceof Error ? err.message : 'x');\n}\n");
    put('src/components/sub/deeper/B.ts', "p.catch((reason) => log(reason.message));\n");
    put('src/components/C.test.ts', "setError(err.message);\n");
    put('src/components/D.d.ts', "declare const x: { message: string };\n");
    put('src/components/E.tsx', "setError(typedSentence);\n");
    put('src/lib/F.ts', "setError(err.message);\n");
    const base = { 'src/components/A.tsx': 2, 'src/components/sub/deeper/B.ts': 1 };
    assert.deepEqual(countsByPath(root), base, 'counts .tsx and nested .ts; ignores tests, .d.ts, clean files and anything outside src/components');
    assert.deepEqual(ratchet(countsByPath(root), base), { grew: [], shrank: [] });
    put('src/components/G.tsx', "catch (e) { setError(e.message); }\n");
    assert.deepEqual(ratchet(countsByPath(root), base).grew, ['src/components/G.tsx: 1 > baseline 0'], 'a new file with one line');
    put('src/components/A.tsx', "try {} catch (err) {\n  setError(err.message);\n}\n");
    assert.deepEqual(ratchet(countsByPath(root), { ...base, 'src/components/G.tsx': 1 }).shrank, ['src/components/A.tsx: 1 < baseline 2'], 'a removed line');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('RT4 THE RATCHET ON THE TREE: no file shows more of an error\'s own text than its baseline, and the baseline is exact', () => {
  const b = JSON.parse(readFileSync(BASELINE_FILE, 'utf8')) as { counts: Record<string, number> };
  const { grew, shrank } = ratchet(countsByPath(), b.counts);
  assert.deepEqual(grew, [], 'a NEW line shows an error\'s own text: choose the sentence by a typed code (see src/lib/contacts/contact-io-errors.ts); the baseline never goes up');
  assert.deepEqual(shrank, [], 'a line was removed: lower the baseline to the new count in the same change (delete the path when it reaches 0), so the ratchet only tightens');
});
