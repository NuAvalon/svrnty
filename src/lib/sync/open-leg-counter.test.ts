// src/lib/sync/open-leg-counter.test.ts
// Run: npx tsx --test src/lib/sync/open-leg-counter.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { counted, createOpenLegCounter } from './open-leg-counter';
import { dualReadOpener } from './hybrid-dual-read';

test('L1 take() returns the counts since the last take and resets', () => {
  const c = createOpenLegCounter();
  c.bump('hybrid'); c.bump('hybrid'); c.bump('classical');
  assert.deepEqual(c.take(), { hybrid: 2, classical: 1 });
  assert.deepEqual(c.take(), { hybrid: 0, classical: 0 });
});

test('L2 counted(): only NON-NULL results count; null counts nothing; a throw passes through and counts nothing; the value is untouched', async () => {
  const c = createOpenLegCounter();
  const open = counted<{ v: number }>(async (b) => (b === 'ok' ? { v: 7 } : b === 'boom' ? Promise.reject(new Error('x')) : null), 'classical', c);
  assert.deepEqual(await open('ok'), { v: 7 });
  assert.equal(await open('nope'), null);
  await assert.rejects(() => open('boom'), /x/);
  assert.deepEqual(c.take(), { hybrid: 0, classical: 1 });
});

test('L3 a counter that throws never changes what opens', async () => {
  const bad = { bump: () => { throw new Error('counter fault'); }, take: () => ({ hybrid: 0, classical: 0 }) };
  assert.deepEqual(await counted(async () => ({ v: 1 }), 'hybrid', bad)('b'), { v: 1 });
});

test('L4 without a counter the opener is returned as is (legacy callers unchanged)', () => {
  const f = async () => null;
  assert.equal(counted(f, 'hybrid', undefined), f);
});

test('L5 inside dualReadOpener: a hybrid open counts hybrid ONLY (the classical leg is not even tried); a hybrid miss that the classical leg opens counts classical ONLY', async () => {
  const c = createOpenLegCounter();
  let classicalCalls = 0;
  const hybrid = counted(async (b: string) => (b === 'h' ? { v: 'h' } : null), 'hybrid', c);
  const classical = counted(async (b: string) => { classicalCalls++; return b === 'c' ? { v: 'c' } : null; }, 'classical', c);
  const dual = dualReadOpener(hybrid, classical);
  assert.deepEqual(await dual('h'), { v: 'h' });
  assert.equal(classicalCalls, 0);
  assert.deepEqual(c.take(), { hybrid: 1, classical: 0 });
  assert.deepEqual(await dual('c'), { v: 'c' });
  assert.deepEqual(c.take(), { hybrid: 0, classical: 1 });
  assert.equal(await dual('neither'), null);
  assert.deepEqual(c.take(), { hybrid: 0, classical: 0 }, 'an unopenable blob counts as neither');
});

// Static guard: a NEW dualReadOpener call site (or a classical-only opener) that is not counted would silently hide a classical sender.
function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx)$/.test(n) && !/\.test\.|-fixture\./.test(n)) out.push(p);
  }
  return out;
}
test('L6 static: every dualReadOpener( call site in src passes counted legs, and each file that builds one imports counted', () => {
  const src = new URL('../..', import.meta.url).pathname; // .../src
  const offenders: string[] = [];
  for (const f of walk(src)) {
    if (f.endsWith('hybrid-dual-read.ts') || f.endsWith('open-leg-counter.ts')) continue;
    const text = readFileSync(f, 'utf8').replace(/\/\*[\s\S]*?\*\//g, (m) => ' '.repeat(m.length)).replace(/\/\/[^\n]*/g, (m) => ' '.repeat(m.length)); // same offsets, no comments
    const sites = [...text.matchAll(/dualReadOpener(?:<[^>]*>)?\(/g)];
    if (sites.length === 0) continue;
    for (const m of sites) {
      // The balanced argument list of THIS dualReadOpener( call: both legs must be wrapped, a hybrid-only wrapper would hide exactly
      // the classical senders this exists to find.
      let depth = 0;
      let end = m.index! + m[0].length - 1;
      for (let i = end; i < text.length; i++) {
        if (text[i] === '(') depth++;
        else if (text[i] === ')' && --depth === 0) { end = i; break; }
      }
      const call = text.slice(m.index!, end + 1);
      if (!/counted(?:<[^>]*>)?\([\s\S]*?'hybrid'/.test(call) || !/counted(?:<[^>]*>)?\([\s\S]*?'classical'/.test(call)) offenders.push(`${f}@${m.index}`);
    }
    if (!/\bcounted\b[^\n]*from '@\/lib\/sync\/open-leg-counter'|from '\.\/open-leg-counter'/.test(text)) offenders.push(`${f}: no counted import`);
  }
  assert.deepEqual(offenders, []);
});
