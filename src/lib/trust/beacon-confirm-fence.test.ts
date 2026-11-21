// src/lib/trust/beacon-confirm-fence.test.ts: SOURCE-SHAPE pins for the confirm session (not behaviour: the behaviour is in beacon-confirm-session.test.ts).
// The session nonce may reach the module in exactly two ways (a scanned QR, typed text) and may leave it once, at creation, as the text the screen draws; these pins keep a third way in, or a way out, from being added by accident.
// Run: npx tsx --test src/lib/trust/beacon-confirm-fence.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const FILE = 'src/lib/trust/beacon-confirm-session.ts';
const strip = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`\\])\/\/[^\n]*/g, '$1');
const RAW = readFileSync(FILE, 'utf8');
const SRC = strip(RAW);

function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (n === 'node_modules' || n === '.next' || n === '.git') continue;
    if (statSync(p).isDirectory()) walk(p, out); else if (/\.(ts|tsx)$/.test(n)) out.push(p);
  }
  return out;
}

test('CF1 the exports are exactly the three entry points, two constants and the named types: no raw-nonce entry, no getter, no re-export', () => {
  const values = [...SRC.matchAll(/^export (?:async )?(?:const|let|var|function|class) ([A-Za-z0-9_$]+)/gm)].map((m) => m[1]).sort();
  assert.deepEqual(values, ['MAX_ATTEMPTS', 'SESSION_MS', 'joinConfirmFromScan', 'joinConfirmFromTyped', 'startConfirmSession']);
  const types = [...SRC.matchAll(/^export (?:type|interface) ([A-Za-z0-9_$]+)/gm)].map((m) => m[1]).sort();
  assert.deepEqual(types, ['ConfirmSession', 'EnterResult', 'JoinRefusal', 'JoinResult', 'OwnCode', 'SessionStatus', 'StartRefusal', 'StartResult']);
  assert.doesNotMatch(SRC, /^export\s*\{|^export\s*\*|^export default|module\.exports|\bexports\./m, 'no re-export, no default export');
  assert.equal([...SRC.matchAll(/^export /gm)].length, values.length + types.length, 'every export line is one of the above');
});

test('CF2 it imports only the code module: no relay, send, message, clipboard, link, store or network module, in any form', () => {
  const froms = [...SRC.matchAll(/(?:from|import)\s*\(?\s*'([^']+)'/g)].map((m) => m[1]);
  assert.deepEqual(froms, ['./beacon-confirm-code']);
  assert.doesNotMatch(SRC, /\brequire\s*\(|\bimport\s*\(/, 'no require, no dynamic import');
});

test('CF3 it touches nothing that can carry the nonce off the screen or make it guessable: no console, storage, network, clipboard, window or Math.random', () => {
  assert.doesNotMatch(SRC, /\bconsole\b|localStorage|sessionStorage|indexedDB|\bfetch\s*\(|XMLHttpRequest|\bnavigator\b|\bdocument\b|\bwindow\b|\bglobalThis\.(?!crypto|performance)|postMessage|BroadcastChannel|WebSocket|sendBeacon|clipboard|\bBlob\b|createObjectURL|\beval\s*\(|new Function|\bprocess\b/);
  assert.doesNotMatch(SRC, /Math\.random/, 'the nonce comes from the secure random source only');
  assert.equal((SRC.match(/getRandomValues/g) ?? []).length, 1, 'one place draws the nonce');
  assert.equal((SRC.match(/Date\.now/g) ?? []).length, 1, 'the clock is injected; Date.now is only the default');
  assert.equal((SRC.match(/performance\.now/g) ?? []).length, 1, 'the second clock is injected too; performance.now is only the default');
});

test('CF4 the confirm form and the invite path do not know each other: neither imports the other, and the module is not imported by any app file yet', () => {
  const inviteDir = readdirSync('src/lib/invite').filter((n) => /\.(ts|tsx)$/.test(n) && !/\.test\./.test(n));
  for (const n of inviteDir) assert.doesNotMatch(readFileSync(join('src/lib/invite', n), 'utf8'), /beacon-confirm|svrnty-confirm/, `the invite module ${n} does not mention the confirm form`);
  const importers = walk('src').concat(walk('app')).filter((f) => !/\.test\.(ts|tsx)$/.test(f) && f !== FILE && /beacon-confirm-session/.test(readFileSync(f, 'utf8')));
  assert.deepEqual(importers, [], 'dark: nothing outside the tests imports the session module (the store glue adds one importer, on purpose, with its own review)');
});

test('CF5 the confirm QR form lives in one place, and no other module can build or read it', () => {
  assert.equal((RAW.match(/svrnty-confirm:1:/g) ?? []).length >= 1, true);
  const others = walk('src').concat(walk('app')).filter((f) => f !== FILE && !/beacon-confirm-session(\.test)?\.ts$|beacon-confirm-fence\.test\.ts$/.test(f) && /svrnty-confirm:/.test(readFileSync(f, 'utf8')));
  assert.deepEqual(others, [], 'no other file names the confirm QR form');
});
