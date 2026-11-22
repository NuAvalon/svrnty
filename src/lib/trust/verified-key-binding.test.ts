// "Verified" is bound to the key that was checked. The behaviour is tested in trust-recipe.test.ts; these are source-shape pins for the parts a behaviour
// test cannot see: who may write the stamp, that both store sinks make the SAME decision from the WHOLE record, that the demo seeds' stamps are real,
// and that nothing fills a fingerprint into a stamp it did not write. Every file under src and app that is not a test is read. A line that is entirely a
// comment is ignored; code on the same line as a comment marker is still read.
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
const rel = (f: string) => (f.startsWith(SRC) ? 'src/' + f.slice(SRC.length) : 'app/' + f.slice(APP.length));
const files = [...sourceFiles(SRC), ...sourceFiles(APP)].map((f) => ({
  path: rel(f),
  lines: readFileSync(f, 'utf8').split('\n').map((l) => (WHOLE_LINE_COMMENT.test(l) ? '' : l)),
}));
const code = (path: string): string => (files.find((f) => f.path === path) as { lines: string[] }).lines.join('\n');

/** Every "path:line text" in the tree where a line matches `re`, except in the listed files. */
function hits(re: RegExp, except: string[] = []): string[] {
  return files.filter((f) => !except.includes(f.path)).flatMap((f) => f.lines.flatMap((l, i) => (re.test(l) ? [`${f.path}:${i + 1} ${l.trim()}`] : [])));
}

test('the guard really scans the tree (control: it sees the files it must see)', () => {
  assert.ok(files.length > 200, `expected many files, saw ${files.length}`);
  assert.ok(hits(/owner_verified_at/).length >= 1, 'control: the stamp is found where it is written');
  assert.ok(files.some((f) => f.path === 'app/page.tsx'), 'control: app is scanned');
});

test('only the recipe WRITES a stamp: no other file builds an object with owner_verified_at', () => {
  // types.ts only declares the field's type (`owner_verified_at: string`). The (?=\S) stops the spaces from backtracking past the lookahead.
  const WRITES = /owner_verified_at\s*:\s*(?=\S)(?!string\b)/;
  assert.equal(WRITES.test("const o = { owner_verified_at: 'x' };"), true, 'control: a write is seen');
  assert.equal(WRITES.test('const o = { owner_verified_at: new Date().toISOString() };'), true, 'control: a computed write is seen');
  assert.equal(WRITES.test('  owner_verified_at: string;'), false, 'control: the type declaration is not a write');
  assert.deepEqual(hits(WRITES, ['src/lib/trust/trust-recipe.ts']), []);
});

test('nothing fills a fingerprint into a stamp it did not write: no other file sets a fingerprint on owner_verify', () => {
  assert.deepEqual(hits(/owner_verify[^\n]*\bfingerprint\s*[:=]/, ['src/lib/trust/trust-recipe.ts']), []);
  assert.deepEqual(hits(/\bowner_verify\s*\??\.\s*fingerprint\s*=(?!=)/), []);
});

test('no caller hands ownerHasVerified a made-up object: it always gets the record or the edge, which carry the current key', () => {
  assert.deepEqual(hits(/\bownerHasVerified\(\s*\{/), []);
  assert.deepEqual(hits(/\btrustGrantRefused\([^)]*\{\s*(?:metadata|owner_verify)\b/), []);
});

test('both store sinks make the ONE decision, from the WHOLE record, and neither calls the predicate itself', () => {
  const store = code('src/lib/identity/client-store.ts');
  assert.match(store, /trustGrantRefused\(false, addTrusted, record as /, 'create');
  assert.match(store, /trustGrantRefused\(wasTrusted, nowTrusted, next as /, 'promote');
  assert.equal((store.match(/\btrustGrantRefused\(/g) ?? []).length, 2, 'exactly the two sinks');
  assert.equal((store.match(/\bownerHasVerified\(/g) ?? []).length, 0, 'the store does not compare stamps itself');
});

test('a trusted demo contact carries a REAL stamp for its own fingerprint (the store refuses a trusted create without one)', () => {
  assert.match(code('src/lib/trust/sample-circle.ts'), /ownerVerifyPersistPatch\(\{\}, 'in_person', c\.fingerprint\)\.owner_verify/);
  assert.match(code('src/components/demo/seed-linked-demo.ts'), /ownerVerifyPersistPatch\(\{\}, 'in_person', peer\.fingerprint\)\.owner_verify/);
});

test('the Verify confirm takes the key from the held record inside the compare-and-swap, never from a screen', () => {
  const patches = code('src/lib/contacts/metadata-patches.ts');
  assert.match(patches, /ownerVerifyPersistPatch\(fresh\.metadata, method, currentFingerprintOf\(fresh\)\)/);
  for (const path of ['app/page.tsx', 'src/components/ContactManagement.tsx']) {
    assert.match(code(path), /ownerVerifyHeldPatch\(fresh, method\)/, `${path} calls the held-record patch from inside updateContact`);
  }
});
