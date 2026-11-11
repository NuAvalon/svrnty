// src/lib/identity/owner-key.test.ts — the owner's storage key (durable id), and what it protects.
// Run: npx tsx --test src/lib/identity/owner-key.test.ts
// The crypto is the REAL contact-crypto (AES-GCM with the owner string in the AAD) and the record ids are READ from client-store.ts, so a
// renamed or added reserved record id fails here. Nothing touches IndexedDB (fake-indexeddb is not installed in this tree).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js';
import { encryptContactRecord, decryptContactRecord } from './contact-crypto';
import { ownerStoreKey, withOwnerAlias, OwnerKeyError, type OwnerAliases } from './owner-key';

const hex64 = () => bytesToHex(randomBytes(32));
const hex40 = () => bytesToHex(randomBytes(20));
const reason = (f: () => unknown) => { try { f(); return 'no-throw'; } catch (e) { return e instanceof OwnerKeyError ? e.reason : 'other'; } };

// ---------- the rule: byte-identical when nothing rotated ----------
test('O1 no alias entry: the argument comes back UNCHANGED, whatever it looks like (nothing migrates for an owner who never rotated)', () => {
  const unrelated = new Map([[hex64(), hex64()]]);
  for (const fp of [hex64(), hex64().toUpperCase(), hex40(), hex40().toUpperCase(), 'AbCd' + hex64().slice(4), '  spaced  ', 'not-hex-at-all', 'x']) {
    assert.equal(ownerStoreKey(fp), fp, 'undefined map');
    assert.equal(ownerStoreKey(fp, new Map()), fp, 'empty map');
    assert.equal(ownerStoreKey(fp, unrelated), fp, 'an unrelated alias');
  }
});

test('O2 an operational fingerprint resolves to its durable id; the durable id resolves to itself', () => {
  const durable = hex64(), f1 = hex64(), f2 = hex64();
  const a = withOwnerAlias(withOwnerAlias(undefined, f1, durable), f2, durable);
  assert.equal(ownerStoreKey(f1, a), durable);
  assert.equal(ownerStoreKey(f2, a), durable, 'every operational fingerprint the owner ever had');
  assert.equal(ownerStoreKey(durable, a), durable);
});

// ---------- fail closed ----------
test('O3 malformed input and malformed maps are refused with a reason code, never guessed', () => {
  const d = hex64(), f1 = hex64();
  for (const bad of ['', undefined as unknown as string, null as unknown as string, 5 as unknown as string]) assert.equal(reason(() => ownerStoreKey(bad)), 'bad-fingerprint');
  assert.equal(reason(() => ownerStoreKey(f1, new Map([[f1, 'zz']]))), 'bad-alias', 'a value that is not a fingerprint');
  assert.equal(reason(() => ownerStoreKey(f1, new Map([[f1, f1]]))), 'bad-alias', 'an alias of itself');
  assert.equal(reason(() => ownerStoreKey(f1, new Map([[f1, d], [d, hex64()]]))), 'alias-chain', 'a durable id is terminal: never followed twice');
  assert.equal(reason(() => ownerStoreKey('__proto__', new Map())), 'no-throw', 'a prototype name is just a string');
  assert.equal(ownerStoreKey('__proto__', new Map()), '__proto__');
  // building a map
  assert.equal(reason(() => withOwnerAlias(undefined, f1, f1)), 'bad-alias');
  assert.equal(reason(() => withOwnerAlias(undefined, 'zz', d)), 'bad-alias');
  assert.equal(reason(() => withOwnerAlias(undefined, f1, 'zz')), 'bad-alias');
  const m = withOwnerAlias(undefined, f1, d);
  assert.equal(reason(() => withOwnerAlias(m, f1, hex64())), 'alias-conflict', 'an alias is never re-pointed');
  assert.equal(reason(() => withOwnerAlias(m, d, hex64())), 'alias-chain', 'a durable id cannot become an alias');
  assert.equal(reason(() => withOwnerAlias(m, hex64(), f1)), 'alias-chain', 'an operational fingerprint cannot be somebody\'s durable id');
});

test('O4 withOwnerAlias is pure: the input is untouched, the same pair is a no-op, the result is a new map', () => {
  const d = hex64(), f1 = hex64();
  const m0: OwnerAliases = new Map();
  const m1 = withOwnerAlias(m0, f1, d);
  assert.equal(m0.size, 0);
  assert.equal(m1.size, 1);
  const m2 = withOwnerAlias(m1, f1, d);
  assert.notEqual(m2, m1);
  assert.deepEqual([...m2], [...m1]);
  assert.equal(m1.size, 1);
});

// ---------- the point: records stay readable across a rotation ----------
function reservedIds(): Record<string, string> {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'client-store.ts'), 'utf8');
  const out: Record<string, string> = {};
  for (const name of ['SUPPRESSION_RECORD_ID', 'HELD_AFFIRMS_RECORD_ID', 'DELIVERY_RECORD_ID']) {
    const m = new RegExp('const ' + name + " = '([^']+)'").exec(src);
    assert.ok(m, name + ' is still declared in client-store.ts');
    out[name] = m![1];
  }
  return out;
}

test('O5 every encrypted record kind stays readable after the owner rotates, when the storage key is the durable id', async () => {
  const ids = reservedIds();
  assert.deepEqual(Object.values(ids).sort(), ['piece2:delivery-receipts', 'piece2:held-affirms', 'piece2:suppression'], 'the three reserved ids this test covers; a new one must be added here');
  const kinds: Record<string, string> = { contact: crypto.randomUUID(), ...Object.fromEntries(Object.entries(ids).map(([k, v]) => [k, v])) };
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const durable = hex64(), f1 = hex64();
  const payloads: Record<string, unknown> = {};
  // BEFORE the rotation: the active fingerprint IS the durable id, so the storage key is that string, unchanged
  for (const [kind, id] of Object.entries(kinds)) payloads[kind] = await encryptContactRecord(key, id, ownerStoreKey(durable), { kind, n: 1 });
  // the owner rotates: the active fingerprint is now f1, and the rotation's persist records the alias
  const aliases = withOwnerAlias(undefined, f1, durable);
  for (const [kind, id] of Object.entries(kinds)) {
    const back = await decryptContactRecord<{ kind: string; n: number }>(key, id, ownerStoreKey(f1, aliases), payloads[kind] as never);
    assert.deepEqual(back, { kind, n: 1 }, kind + ' written before the rotation is read after it');
    // and a record written AFTER the rotation reads back under the same storage key, and under the durable id itself
    const after = await encryptContactRecord(key, id, ownerStoreKey(f1, aliases), { kind, n: 2 });
    assert.deepEqual(await decryptContactRecord(key, id, durable, after as never), { kind, n: 2 }, kind + ' written after, read by the durable id');
  }
  // the failure the rule prevents: passing the OPERATIONAL fingerprint after the rotation, for EVERY kind
  for (const [kind, id] of Object.entries(kinds)) {
    await assert.rejects(decryptContactRecord(key, id, f1, payloads[kind] as never), `${kind}: the operational fingerprint as the owner string is refused`);
    await assert.rejects(decryptContactRecord(key, id, ownerStoreKey(f1, undefined), payloads[kind] as never), `${kind}: a rotated owner with NO alias recorded is refused (the rotation must persist the alias)`);
  }
});

test('O6 a different owner string is refused, and so is a different record id (the NEG that guards the whole rule)', async () => {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const owner = hex64(), other = hex64();
  const enc = await encryptContactRecord(key, 'piece2:suppression', owner, { a: 1 });
  assert.deepEqual(await decryptContactRecord(key, 'piece2:suppression', owner, enc), { a: 1 });
  await assert.rejects(decryptContactRecord(key, 'piece2:suppression', other, enc));
  await assert.rejects(decryptContactRecord(key, 'piece2:held-affirms', owner, enc));
});

// ---------- the module is pure and dark ----------
test('O7 pure: no imports, no clock, no randomness, no storage, no network', () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'owner-key.ts'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  assert.deepEqual([...src.matchAll(/from '([^']+)'/g)].map((m) => m[1]), []);
  for (const bad of ['Date.now', 'new Date', 'Math.random', 'getRandomValues', 'randomBytes', 'fetch(', 'indexedDB', 'localStorage', 'process.', 'setTimeout', 'require(', 'import(']) assert.ok(!src.includes(bad), 'must not use ' + bad);
});

test('O8 dark: nothing outside tests imports owner-key yet', () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
  const hits: string[] = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      if (n === 'node_modules' || n === '.next' || n === '.git') continue;
      const p = join(d, n); const st = statSync(p);
      if (st.isDirectory()) { walk(p); continue; }
      if (!/\.(ts|tsx|mjs|js)$/.test(n) || /\.test\.|\.spec\./.test(n) || p.endsWith('/src/lib/identity/owner-key.ts')) continue;
      if (/from ['"][^'"]*owner-key['"]/.test(readFileSync(p, 'utf8'))) hits.push(p);
    }
  };
  for (const d of ['src', 'app', 'scripts']) { try { walk(join(root, d)); } catch { /* absent */ } }
  assert.deepEqual(hits, []);
});
