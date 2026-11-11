// src/lib/identity/owner-key-session.test.ts — the synchronous owner-key copy: three states, set only by the unlock path (Flint #7362).
// Run: npx tsx --test src/lib/identity/owner-key-session.test.ts
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js';
import { OwnerKeyError } from './owner-key';
import { ownerKey, isOwnerKeyLoaded, loadOwnerAliases, clearOwnerAliases } from './owner-key-session';

const hex64 = () => bytesToHex(randomBytes(32));
const hex40 = () => bytesToHex(randomBytes(20));
const reason = (f: () => unknown) => { try { f(); return 'no-throw'; } catch (e) { return e instanceof OwnerKeyError ? e.reason : 'other'; } };
afterEach(() => clearOwnerAliases());

test('SS1 NOT LOADED: every read throws not-loaded and never returns its argument (the notes-DB-name failure this prevents)', () => {
  assert.equal(isOwnerKeyLoaded(), false);
  for (const fp of [hex64(), hex40(), hex64().toUpperCase(), 'x']) assert.equal(reason(() => ownerKey(fp)), 'not-loaded');
});

test('SS2 LOADED with no aliases: the argument passes through unchanged, byte for byte (an owner who never rotated)', () => {
  loadOwnerAliases([]);
  assert.equal(isOwnerKeyLoaded(), true);
  for (const fp of [hex64(), hex40(), hex64().toUpperCase(), 'AbC', '  x ']) assert.equal(ownerKey(fp), fp);
});

test('SS3 LOADED with aliases: an operational fingerprint resolves to the durable id; the durable id and an unrelated fingerprint pass through', () => {
  const d = hex64(), f1 = hex64(), f2 = hex64(), other = hex64();
  loadOwnerAliases([[f1, d], [f2, d]]);
  assert.equal(ownerKey(f1), d);
  assert.equal(ownerKey(f2), d);
  assert.equal(ownerKey(d), d);
  assert.equal(ownerKey(other), other);
});

test('SS4 clearing the copy (tests, a failed refresh; NOT lock: ruling A) makes every read throw again', () => {
  const d = hex64(), f1 = hex64();
  loadOwnerAliases([[f1, d]]);
  assert.equal(ownerKey(f1), d);
  clearOwnerAliases();
  assert.equal(isOwnerKeyLoaded(), false);
  assert.equal(reason(() => ownerKey(f1)), 'not-loaded');
  assert.equal(reason(() => ownerKey(d)), 'not-loaded');
});

test('SS5 a malformed row is surfaced and leaves the state NOT LOADED, even when an older map was loaded: never repaired, never half-applied', () => {
  const d = hex64(), f1 = hex64();
  const bad: Array<[string, unknown]> = [
    ['an alias to a non-fingerprint', [[f1, 'zz']]],
    ['an upper-case durable id', [[f1, d.toUpperCase()]]],
    ['an UPPER-CASE alias key (Flint #7363: stored data can be edited)', [[f1.toUpperCase(), d]]],
    ['an alias key that is neither 40 nor 64 hex', [[f1.slice(0, 50), d]]],
    ['one good pair then one bad pair: the WHOLE map is refused, not the bad entry skipped', [[f1, d], [hex64().toUpperCase(), d]]],
    ['an alias of itself', [[d, d]]],
    ['a conflicting re-point', [[f1, d], [f1, hex64()]]],
    ['a chain', [[f1, d], [d, hex64()]]],
    ['a pair of three', [[f1, d, 'x']]],
    ['a pair that is an array-like object, not an array', [{ 0: f1, 1: d, length: 2 }]],
    ['not an array (a string)', 'nope'],
    ['not an array (a number)', 5],
    ['not an array (null)', null],
    ['not an array (undefined)', undefined],
    ['not an array (an object)', {}],
    ['a non-string member', [[5, d]]],
  ];
  for (const [label, entries] of bad) {
    loadOwnerAliases([[f1, d]]); // an OLDER, valid map is in place
    assert.equal(ownerKey(f1), d);
    const r = reason(() => loadOwnerAliases(entries as never));
    assert.ok(r === 'bad-alias' || r === 'alias-chain' || r === 'alias-conflict', label + ': the load throws an OwnerKeyError code, got ' + r);
    assert.equal(isOwnerKeyLoaded(), false, label + ': the state is NOT LOADED after a failed load');
    assert.equal(reason(() => ownerKey(f1)), 'not-loaded', label);
  }
  assert.equal(reason(() => loadOwnerAliases([[f1, 'zz']])), 'bad-alias');
  assert.equal(reason(() => loadOwnerAliases([[f1, d], [d, hex64()]])), 'alias-chain');
  assert.equal(reason(() => loadOwnerAliases([[f1, d], [f1, hex64()]])), 'alias-conflict');
});

test('SS6 a load replaces the copy atomically, and the caller\'s array is copied: changing it afterwards changes nothing', () => {
  const d = hex64(), f1 = hex64(), d2 = hex64(), f2 = hex64();
  const entries: Array<[string, string]> = [[f1, d]];
  loadOwnerAliases(entries);
  entries.push([f2, d2]);
  entries[0][1] = d2;
  assert.equal(ownerKey(f1), d);
  assert.equal(ownerKey(f2), f2, 'the pair added afterwards is not in the copy');
  loadOwnerAliases([[f2, d2]]);
  assert.equal(ownerKey(f1), f1, 'a new load replaces, it does not merge');
  assert.equal(ownerKey(f2), d2);
});

test('SS7 the module exposes no way to read the map or set one entry', async () => {
  const mod = await import('./owner-key-session');
  assert.deepEqual(Object.keys(mod).sort(), ['clearOwnerAliases', 'isOwnerKeyLoaded', 'loadOwnerAliases', 'ownerKey']);
});

// ---------- the load path is the unlock path only ----------
const ALLOWED_LOADERS: string[] = ['/src/lib/identity/client-store.ts']; // ruling A: client-store's DB-open path loads the copy; nothing else may
function walkSources(f: (p: string, text: string) => void) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      if (n === 'node_modules' || n === '.next' || n === '.git') continue;
      const p = join(d, n); const st = statSync(p);
      if (st.isDirectory()) { walk(p); continue; }
      if (!/\.(ts|tsx|mjs|js)$/.test(n) || /\.test\.|\.spec\./.test(n)) continue;
      f(p, readFileSync(p, 'utf8'));
    }
  };
  for (const d of ['src', 'app', 'scripts']) { try { walk(join(root, d)); } catch { /* absent */ } }
}

test('SS8 only client-store may import the session module (by exact path)', () => {
  const loaders: string[] = [], importers: string[] = [];
  walkSources((p, text) => {
    if (p.endsWith('/src/lib/identity/owner-key-session.ts')) return;
    if (/from ['"][^'"]*owner-key-session['"]/.test(text)) importers.push(p);
    if (/import\s*\{[^}]*\b(loadOwnerAliases|clearOwnerAliases)\b[^}]*\}\s*from\s*['"][^'"]*owner-key-session['"]/.test(text)) loaders.push(p);
  });
  assert.deepEqual(loaders.filter((p) => !ALLOWED_LOADERS.some((a) => p.endsWith(a))), [], 'a file that is not the unlock path imports the loader');
  assert.deepEqual(importers.filter((p) => !ALLOWED_LOADERS.some((a) => p.endsWith(a))), [], 'nothing but client-store imports the session module (the other readers are wired in later steps and named here by exact path)');
});

test('SS9 pure of effects: no I/O, clock, randomness or network in the session module', () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'owner-key-session.ts'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  assert.deepEqual([...src.matchAll(/from '([^']+)'/g)].map((m) => m[1]), ['./owner-key']);
  for (const bad of ['Date.now', 'new Date', 'Math.random', 'getRandomValues', 'randomBytes', 'fetch(', 'indexedDB', 'localStorage', 'sessionStorage', 'process.', 'setTimeout', 'require(', 'import(', 'export let']) assert.ok(!src.includes(bad), 'must not use ' + bad);
});
