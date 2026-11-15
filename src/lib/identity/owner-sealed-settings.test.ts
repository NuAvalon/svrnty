// src/lib/identity/owner-sealed-settings.test.ts
// Every owner-sealed settings record is named in ONE list (OWNER_SEALED_SETTINGS in client-store.ts), and the restore's passphrase check and snapshot walk that list.
// A sealed record that is written but not listed would sit beside a restore it cannot see: this test makes that red.
// Run: node --import tsx --test src/lib/identity/owner-sealed-settings.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('../../', import.meta.url).pathname; // src/
const store = readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8');

const listBody = (() => {
  const a = store.indexOf('export const OWNER_SEALED_SETTINGS');
  assert.ok(a >= 0, 'the list exists');
  const b = store.indexOf('\n];', a);
  assert.ok(b > a, 'the list ends');
  return store.slice(a, b);
})();
const listed = [...listBody.matchAll(/\{ name: '([a-z-]+)', recordId: ([A-Z_]+), settingKey: ([A-Za-z]+) \}/g)].map((m) => ({ name: m[1], recordId: m[2], settingKey: m[3] }));

const sources = (dir: string): string[] => readdirSync(dir).flatMap((f) => {
  const p = join(dir, f);
  if (statSync(p).isDirectory()) return f === 'node_modules' ? [] : sources(p);
  return /\.(ts|tsx)$/.test(f) && !/\.test\.(ts|tsx)$/.test(f) ? [p] : [];
});

test('S1 every encryptContactRecord(_sessionKey, <RESERVED_ID>, ...) call site in src/ uses an id that is in the list', () => {
  const ids = new Set(listed.map((l) => l.recordId));
  const used = new Set<string>();
  for (const file of sources(root)) {
    const text = readFileSync(file, 'utf8');
    for (const m of text.matchAll(/encryptContactRecord\(\s*_sessionKey\s*,\s*([A-Z][A-Z0-9_]*)\s*,/g)) used.add(m[1]);
  }
  assert.ok(used.size >= 6, `the reserved ids are found at their call sites (found ${used.size})`);
  for (const id of used) assert.ok(ids.has(id), `${id} seals a record but is not in OWNER_SEALED_SETTINGS`);
  for (const id of ids) assert.ok(used.has(id), `${id} is listed but no call site seals it (a stale entry)`);
});

test('S2 the list has no duplicate name, id or key, and its ids are the reserved ones (never a contact id)', () => {
  assert.equal(new Set(listed.map((l) => l.name)).size, listed.length, 'names are unique');
  assert.equal(new Set(listed.map((l) => l.recordId)).size, listed.length, 'record ids are unique');
  assert.equal(new Set(listed.map((l) => l.settingKey)).size, listed.length, 'setting keys are unique');
  assert.deepEqual(listed.map((l) => l.name), ['suppression', 'held-affirms', 'delivery-default', 'lens-book', 'beacon-seeds', 'beacon-key']);
  for (const l of listed) assert.match(store, new RegExp(`const ${l.recordId} = '[a-z0-9]+:[a-z-]+';`), `${l.recordId} is a reserved id constant`);
});

test('S3 the contact-row path is the only other sealed write, and it uses the row id, not a reserved one', () => {
  const m = [...store.matchAll(/encryptContactRecord\(\s*_sessionKey\s*,\s*([a-z][A-Za-z0-9_]*)\s*,/g)].map((x) => x[1]);
  assert.deepEqual(m, ['id'], 'one lowercase-id call site: the contact row');
});

test('S4 every encryptContactRecord( call in src/ is one S1 or S3 recognises (a call with another key variable, or a lowercase id, cannot slip past them)', () => {
  let all = 0, s1 = 0, s3 = 0;
  for (const file of sources(root)) {
    // code only: a comment that names the function is not a call
    const text = readFileSync(file, 'utf8').split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
    // every call, minus the function's own definition
    all += [...text.matchAll(/\bencryptContactRecord\(/g)].length - [...text.matchAll(/function\s+encryptContactRecord\(/g)].length;
    s1 += [...text.matchAll(/encryptContactRecord\(\s*_sessionKey\s*,\s*([A-Z][A-Z0-9_]*)\s*,/g)].length;
    s3 += [...text.matchAll(/encryptContactRecord\(\s*_sessionKey\s*,\s*([a-z][A-Za-z0-9_]*)\s*,/g)].length;
  }
  assert.ok(all >= 7, `the calls are found (found ${all})`);
  assert.equal(all, s1 + s3, `${all} encryptContactRecord( calls in src/ but S1 and S3 recognise ${s1 + s3}: a sealed record written another way is not covered by the list`);
});
