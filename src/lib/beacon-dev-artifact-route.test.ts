// src/lib/beacon-dev-artifact-route.test.ts: #822 (a)-Z2. The dev-only proving-file route answers only the two named files, only in a dev build that opted in.
// Run: npx tsx --test src/lib/beacon-dev-artifact-route.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { serveBeaconDevArtifact, type ArtifactServeInput } from './beacon-dev-artifact-route';

const join = (d: string, n: string) => `${d}|${n}`; // a visible join, so a test can see exactly what path was built
function run(over: Partial<ArtifactServeInput>, bytes: Uint8Array | Error | 'notbytes' = new Uint8Array([1, 2, 3])) {
  const calls: string[] = [];
  const input: ArtifactServeInput = {
    flag: 'true', dir: '/mnt/dev', file: 'final.zkey', join,
    read: async (p) => { calls.push(p); if (bytes instanceof Error) throw bytes; if (bytes === 'notbytes') return 'x' as unknown as Uint8Array; return bytes; },
    ...over,
  };
  return serveBeaconDevArtifact(input).then((r) => ({ r, calls }));
}

test('R1 anything but the exact flag "true" answers 404 and never reads', async () => {
  for (const flag of [undefined, '', 'false', 'TRUE', 'True', ' true', 'true ', '1']) {
    const { r, calls } = await run({ flag });
    assert.deepEqual(r, { status: 404 }, String(flag));
    assert.equal(calls.length, 0, `${String(flag)} must not read`);
  }
});

test('R2 no dir configured answers 404 and never reads', async () => {
  for (const dir of [undefined, '']) {
    const { r, calls } = await run({ dir });
    assert.deepEqual(r, { status: 404 });
    assert.equal(calls.length, 0);
  }
});

test('R3 only the two exact names are ever read; every other name (traversal, case, slashes, prototype keys) is 404 with NO read', async () => {
  const bad = ['', '.', '..', '../final.zkey', '..%2Ffinal.zkey', '%2e%2e', 'final.zkey/', '/final.zkey', 'FINAL.ZKEY', 'Final.zkey', 'final.zkey ', 'final.zkey\u0000',
    'final.zkey.map', 'slotbind.wasm.bak', 'a/../final.zkey', 'final.zkey\\..', '__proto__', 'constructor', 'toString', 'hasOwnProperty', 'prototype', 'slotbind', 'zkey'];
  for (const file of bad) {
    const { r, calls } = await run({ file });
    assert.deepEqual(r, { status: 404 }, JSON.stringify(file));
    assert.equal(calls.length, 0, `${JSON.stringify(file)} must not reach the reader`);
  }
});

test('R4 the two names are served with their bytes, the right content type, an exact length and no-store; the path is dir + name and nothing else', async () => {
  for (const [file, type] of [['slotbind.wasm', 'application/wasm'], ['final.zkey', 'application/octet-stream']] as const) {
    const body = new Uint8Array([9, 8, 7, 6, 5]);
    const { r, calls } = await run({ file }, body);
    assert.equal(r.status, 200);
    if (r.status === 200) {
      assert.deepEqual(r.body, body);
      assert.deepEqual(r.headers, { 'content-type': type, 'content-length': '5', 'cache-control': 'no-store' });
    }
    assert.deepEqual(calls, [`/mnt/dev|${file}`]);
  }
});

test('R5 a failing or non-bytes read is a plain 404: no path, no error text', async () => {
  for (const bytes of [new Error('ENOENT: /mnt/dev/final.zkey'), 'notbytes' as const]) {
    const { r } = await run({}, bytes);
    assert.deepEqual(r, { status: 404 });
    assert.ok(!JSON.stringify(r).includes('/mnt'));
  }
});

test('R6 [static] the route adapter passes the static flag and the dir env, answers a bare 404 on anything not 200, is dynamic, and names no hash or dev URL', () => {
  const src = readFileSync(new URL('../../app/beacon-dev/[file]/route.ts', import.meta.url), 'utf8');
  const code = src.split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');
  assert.match(code, /flag: process\.env\.NEXT_PUBLIC_BEACON_DEV_ARTIFACTS,/);
  assert.match(code, /dir: process\.env\.BEACON_DEV_ARTIFACT_DIR,/);
  assert.match(code, /if \(r\.status !== 200\) return new Response\(null, \{ status: 404 \}\);/);
  assert.match(code, /export const dynamic = 'force-dynamic';/);
  assert.ok(!code.includes('b13ee702') && !code.includes('/beacon-dev/'), 'the route names neither the hash nor the dev URL prefix');
  assert.ok(!/NEXT_PUBLIC_BEACON_LIVE/.test(code), 'it must use the always-defined flag, not the unset-able variable');
});
