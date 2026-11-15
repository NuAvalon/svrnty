// src/lib/identity/owner-sealed-settings.test.ts
// Every owner-sealed settings record is named in ONE list (OWNER_SEALED_SETTINGS in client-store.ts), and the restore's passphrase check and snapshot walk that list.
// A sealed record that is written but not listed would sit beside a restore it cannot see: this test makes that red.
// BOUND: these checks see DIRECT calls to encryptContactRecord( only. An alias (`const seal = encryptContactRecord; seal(...)`) or a re-export wrapper escapes them.
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
  assert.deepEqual(listed.map((l) => l.name), ['suppression', 'held-affirms', 'delivery-default', 'lens-book', 'beacon-seeds', 'beacon-key', 'beacon-confirmed']);
  for (const l of listed) assert.match(store, new RegExp(`const ${l.recordId} = '[a-z0-9]+:[a-z-]+';`), `${l.recordId} is a reserved id constant`);
});

test('S3 the sealed writes that are NOT a listed record are exactly two: the contact row (its own id) and the beacon ports\' sealer (a caller-chosen AAD for the pair and latch rows)', () => {
  const m = [...store.matchAll(/encryptContactRecord\(\s*_sessionKey\s*,\s*([a-z][A-Za-z0-9_]*)\s*,/g)].map((x) => x[1]);
  assert.deepEqual(m, ['id', 'aad'], 'the contact row, then the beacon sealer: a third lowercase-id site must be classified and covered by the restore check before it is added here');
  const a = store.indexOf('function beaconSessionSealer(');
  assert.ok(a >= 0, 'the sealer exists');
  assert.match(store.slice(a, store.indexOf('\n}\n', a)), /encryptContactRecord\(\s*_sessionKey\s*,\s*aad\s*,/, 'the aad site is the beacon sealer');
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

// ---- the restore's passphrase check also opens EVERY beacon pair and latch row (collections, not single records) ----
const codeOnlyText = (text: string) => text.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
const fnOf = (head: string) => {
  const a = store.indexOf(head);
  assert.ok(a >= 0, `${head} exists`);
  const ends = ['\nexport ', '\n/**'].map((m) => store.indexOf(m, a + 1)).filter((i) => i !== -1);
  return codeOnlyText(store.slice(a, Math.min(...ends)));
};
const heldSetBody = fnOf('async function readHeldSet(');
const openLoopBody = fnOf('async function openEveryHeldRecord(');

test('S5 the held set has EVERY row of both beacon collections, mapped with the ports\' own AAD; a row that cannot be mapped or parsed is malformed, and a malformed record refuses', () => {
  assert.match(heldSetBody, /for \(const prefix of beaconRowPrefixes\(fingerprint\)\) \{/, 'both collections are enumerated');
  assert.match(heldSetBody, /for \(const key of await txKeysWithPrefix\('settings', prefix\)\) \{/, 'EVERY key of the collection (no slice, no first-only)');
  assert.match(heldSetBody, /const aad = beaconRowAad\(fingerprint, key\);/, 'the AAD comes from the ports\' one definition');
  assert.match(heldSetBody, /const malformed = aad === null \|\| !payload \|\| typeof payload\.iv !== 'string' \|\| typeof payload\.ciphertext !== 'string';/, 'an unmappable or unparseable row is malformed');
  assert.match(heldSetBody, /kind: 'beacon', keySource: 'settings-salt', encrypted: true, malformed/, 'a beacon row is always encrypted: it is never skipped');
  assert.match(heldSetBody, /decryptContactRecord\(k, aad!, fingerprint,/, 'each row is opened with its own AAD');
  assert.match(openLoopBody, /if \(rec\.malformed\) return false;/, 'a malformed record refuses the restore');
  assert.match(openLoopBody, /if \(!\(await rec\.open\(await keyFor\(salt\)\)\)\) return false;/, 'EVERY member is opened (not one per collection)');
});

test('S6 the beacon row AAD has ONE definition, in beacon-ports.ts: client-store builds none of its own', () => {
  assert.doesNotMatch(codeOnlyText(store), /beacon-(pair|latch):/, 'no AAD template in client-store.ts');
  const ports = codeOnlyText(readFileSync(new URL('../trust/beacon-ports.ts', import.meta.url), 'utf8'));
  assert.equal(ports.split('`beacon-pair:${').length - 1, 1, 'one pair AAD builder');
  assert.equal(ports.split('`beacon-latch:${').length - 1, 1, 'one latch AAD builder');
  assert.match(ports, /const aadOf = \(pairId: string\) => pairAad\(owner, pairId\);/, 'the store uses the shared builder');
  assert.match(ports, /const aadOf = \(source: Source, pairId: string\) => latchAad\(owner, source, pairId\);/, 'the latch uses the shared builder');
});

// ---- ONE held set: holding, the passphrase check and the open session all read it ----
const fnBody = (head: string) => fnOf(head);

test('S7 deviceHoldsOwner is "the held set is non-empty", the held set counts every owner-sealed settings record and every beacon row, and NOT the contact manifest (stated in its definition)', () => {
  assert.match(fnBody('export async function deviceHoldsOwner'), /return \(await readHeldSet\(fingerprint\)\)\.length > 0;/, 'holding = the held set is non-empty');
  assert.match(heldSetBody, /for \(const sealed of OWNER_SEALED_SETTINGS\) \{\s*const row = await txGet<[^\n]*>\('settings', sealed\.settingKey\(fingerprint\)\);\s*if \(!row\) continue;/, 'every listed record');
  assert.match(heldSetBody, /for \(const prefix of beaconRowPrefixes\(fingerprint\)\)/, 'every beacon pair and latch row');
  assert.doesNotMatch(heldSetBody + fnBody('export async function deviceHoldsOwner'), /contactManifestSettingKey|contact_manifest/, 'the manifest holds nothing that can be opened: counting it would refuse every restore on such a device');
  assert.match(store, /NOT a member: the contact book manifest/, 'the exclusion is stated in the definition');
});

test('S9 the passphrase check and the open session iterate the SAME held set, so the three questions cannot disagree about what counts', () => {
  assert.match(fnBody('export async function passphraseOpensEveryHeldKeyRecord'), /return openEveryHeldRecord\(fingerprint, async \(salt\) => \{/, 'the passphrase check');
  assert.match(fnBody('export async function sessionOpensOwner'), /return openEveryHeldRecord\(fingerprint, async \(\) => sessionKey\);/, 'the open session');
  assert.match(openLoopBody, /const held = await readHeldSet\(fingerprint\);/, 'both read the one held set');
  const callers = [...store.matchAll(/await readHeldSet\(fingerprint\)/g)].length;
  assert.equal(callers, 2, 'readHeldSet is read by exactly two functions: deviceHoldsOwner and the opening loop');
});

test('S8 the snapshot has one entry per beacon collection: the count and the digest of the key-sorted key + value rows', () => {
  const b = fnBody('export async function snapshotOwnerRows');
  assert.match(b, /beaconRowPrefixes\(fingerprint\)/, 'the prefixes come from the ports\' one definition');
  assert.match(b, /\['beacon-pair-rows', pairPrefix\], \['beacon-latch-rows', latchPrefix\]/, 'one entry per collection');
  assert.match(b, /\(await txKeysWithPrefix\('settings', prefix\)\)\.slice\(\)\.sort\(\)/, 'every key, sorted (a digest that does not depend on the order IndexedDB returns them)');
  assert.match(b, /rows\.push\(\{ key, value: \(await txGet<\{ value\?: unknown \}>\('settings', key\)\)\?\.value \}\);\s*await put\(place, rows\);/, 'each row contributes its key and its value');
});
