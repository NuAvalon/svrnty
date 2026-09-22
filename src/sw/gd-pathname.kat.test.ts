// src/sw/gd-pathname.kat.test.ts
// SW-side proof for the path-canon KAT (path-canon.kat.json). Asserts the SW walker (manifestPath) produces the
// co-witness vector's expectedPath for every case, and that the divergence-prone pairs stay DISTINCT (no decode,
// case-sensitive, trailing-slash preserved, NFC != NFD). Apollo runs his signer walk + Flint an independent impl
// against the SAME vector; all three must agree byte-for-byte (#141748).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { manifestPath, manifestPathClass, type AssetClass } from './gd-pathname.js';

interface KatCase {
  name: string;
  class: AssetClass;
  requestUrl: string;
  expectedPath: string | null;
  distinctFrom?: string;
}
const HERE = dirname(fileURLToPath(import.meta.url));
const VEC = JSON.parse(readFileSync(join(HERE, 'path-canon.kat.json'), 'utf8')) as {
  origin: string;
  cases: KatCase[];
};

test('path-canon KAT: SW walker (manifestPath) === co-witness vector', () => {
  const got = new Map<string, string | null>();
  for (const c of VEC.cases) {
    const p = manifestPath(c.requestUrl, VEC.origin);
    assert.equal(p, c.expectedPath, `${c.name}: manifestPath(${JSON.stringify(c.requestUrl)})`);
    got.set(c.name, p);
  }
  // Divergence-prone pairs must NOT collapse (no-decode, case, trailing-slash, NFC != NFD).
  for (const c of VEC.cases) {
    if (c.distinctFrom) {
      assert.ok(got.has(c.distinctFrom), `${c.name}: distinctFrom "${c.distinctFrom}" not in vector`);
      assert.notEqual(got.get(c.name), got.get(c.distinctFrom), `${c.name} must differ from ${c.distinctFrom}`);
    }
  }
});

test('path-canon KAT: manifestPathClass matches the vector class for real static/shell entries', () => {
  for (const c of VEC.cases) {
    if (c.class === 'dynamic' || c.expectedPath === null) continue; // adversarial/non-entry paths: not classified
    assert.equal(manifestPathClass(c.expectedPath), c.class, `${c.name}: class of ${c.expectedPath}`);
  }
});
