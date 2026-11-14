// src/lib/crypto/beacon-dev-artifacts.test.ts: #822 (a)-Z. The dev-only proving-file pin: given only to a dev build that opted in, named in exactly one place, never under public/.
// Run: npx tsx --test src/lib/crypto/beacon-dev-artifacts.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { devBeaconArtifacts } from './beacon-dev-artifacts';
import { PINS, loadProvingFiles, ArtifactRefused } from './beacon-artifacts';

const ZKEY = 'b13ee7020226548a0e13738db48075aae27048d09217d8ca4bd5b6458d9016f6'; // the rehearsal chain's final.zkey (4,164,155 bytes); a deliberate edit changes this
const WASM = '3f603c198ba712cb8fb3e34f59bbf75c445ddd8cf3596a305ea57c31000083be';
const ROOT = fileURLToPath(new URL('../../../', import.meta.url));

function withEnv<T>(env: Record<string, string | undefined>, fn: () => T): T {
  const keys = ['NEXT_PUBLIC_SVRNTY_DOMAIN', 'NEXT_PUBLIC_BEACON_LIVE', 'NEXT_PUBLIC_BEACON_DEV_ARTIFACTS'];
  const old = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  try {
    for (const k of keys) { if (env[k] === undefined) delete process.env[k]; else process.env[k] = env[k]; }
    return fn();
  } finally {
    for (const k of keys) { if (old[k] === undefined) delete process.env[k]; else process.env[k] = old[k]; }
  }
}
const DEV = { NEXT_PUBLIC_SVRNTY_DOMAIN: 'dev.svrnty.is', NEXT_PUBLIC_BEACON_LIVE: 'true', NEXT_PUBLIC_BEACON_DEV_ARTIFACTS: 'true' };

test('A1 a dev build that opted in gets the rehearsal pins and the two dev URLs; the wasm pin is the production one', () => {
  const c = withEnv(DEV, () => devBeaconArtifacts());
  assert.ok(c);
  assert.deepEqual(c!.pins, { wasmSha256: WASM, zkeySha256: ZKEY });
  assert.equal(c!.pins.wasmSha256, PINS.wasmSha256, 'the circuit is the same, so the wasm pin does not change');
  assert.deepEqual(c!.urls, { wasm: '/beacon-dev/slotbind.wasm', zkey: '/beacon-dev/final.zkey' });
});

test('A2 anything else gets NULL: no flag, an empty flag, a prod domain, no opt-in, or the flag alone with no dev domain (the run-time check is behind the static one)', () => {
  assert.equal(withEnv({}, () => devBeaconArtifacts()), null);
  assert.equal(withEnv({ ...DEV, NEXT_PUBLIC_BEACON_DEV_ARTIFACTS: '' }, () => devBeaconArtifacts()), null, 'flag empty, though dev + opt-in');
  assert.equal(withEnv({ ...DEV, NEXT_PUBLIC_BEACON_DEV_ARTIFACTS: undefined }, () => devBeaconArtifacts()), null, 'flag unset, though dev + opt-in');
  assert.equal(withEnv({ ...DEV, NEXT_PUBLIC_SVRNTY_DOMAIN: 'svrnty.is' }, () => devBeaconArtifacts()), null, 'flag true but a PROD domain: isBeaconWireLive refuses');
  assert.equal(withEnv({ ...DEV, NEXT_PUBLIC_BEACON_LIVE: undefined }, () => devBeaconArtifacts()), null, 'flag true but no opt-in: isBeaconWireLive refuses');
});

test('A3 PRODUCTION behaviour is unchanged: with no dev config the pins are PINS (zkey null) and loadProvingFiles refuses with zkey-unpinned, before any download', async () => {
  assert.equal(PINS.zkeySha256, null);
  let fetched = 0;
  const cfg = withEnv({}, () => devBeaconArtifacts());
  assert.equal(cfg, null);
  await assert.rejects(
    loadProvingFiles(async () => { fetched++; return new Uint8Array(1); }, { wasm: '/w', zkey: '/z' }),
    (e: unknown) => e instanceof ArtifactRefused && e.reason === 'zkey-unpinned',
  );
  assert.equal(fetched, 0);
});

test('A4 the dev pins refuse a file that is not the pinned one (the pin is checked, not trusted)', async () => {
  const c = withEnv(DEV, () => devBeaconArtifacts())!;
  await assert.rejects(
    loadProvingFiles(async () => new Uint8Array([1, 2, 3]), c.urls, c.pins),
    (e: unknown) => e instanceof ArtifactRefused && (e.reason === 'wasm-hash' || e.reason === 'zkey-hash'),
  );
});

function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    if (n === 'node_modules' || n === '.next' || n === '.git') continue;
    const p = join(dir, n);
    if (statSync(p).isDirectory()) walk(p, out); else out.push(p);
  }
  return out;
}

test('A5 [static] the rehearsal zkey hash and the dev URL prefix are named in exactly ONE non-test source file, and only inside the static branch', () => {
  const hits = [...walk(join(ROOT, 'src')), ...walk(join(ROOT, 'app')), join(ROOT, 'next.config.ts')]
    .filter((p) => /\.(ts|tsx|js|mjs)$/.test(p) && !/\.test\./.test(p))
    .filter((p) => {
      // CODE only: a comment that names a path (the route's own header does) carries no bytes and is stripped from a built bundle; a literal in code anywhere else still fails this
      const s = readFileSync(p, 'utf8').split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
      return s.includes(ZKEY) || s.includes('/beacon-dev/');
    })
    .map((p) => p.slice(ROOT.length));
  assert.deepEqual(hits, ['src/lib/crypto/beacon-dev-artifacts.ts']);
  const src = readFileSync(join(ROOT, 'src/lib/crypto/beacon-dev-artifacts.ts'), 'utf8');
  const code = src.split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');
  const open = code.indexOf("if (process.env.NEXT_PUBLIC_BEACON_DEV_ARTIFACTS === 'true') {");
  assert.ok(open >= 0, 'the static branch must test the always-defined flag');
  assert.ok(code.indexOf(ZKEY) > open && code.indexOf('/beacon-dev/slotbind.wasm') > open && code.indexOf('/beacon-dev/final.zkey') > open, 'the hash and both URLs sit inside the branch');
  assert.ok(code.indexOf('isBeaconWireLive()') > open && code.indexOf('isBeaconWireLive()') < code.indexOf(ZKEY), 'the run-time check guards the return');
  assert.ok(!/process\.env\.NEXT_PUBLIC_BEACON_LIVE === 'true'/.test(code), 'the branch must not test the unset-able variable (a build with it unset keeps the block: measured)');
});

test('A6 [static] no proving artifact is under public/ (a production build copies public/); the dev deploy serves them, not the repo', () => {
  const pub = join(ROOT, 'public');
  const files = existsSync(pub) ? walk(pub) : [];
  const bad = files.filter((p) => /(\.zkey|slotbind.*\.wasm|beacon-dev)/i.test(p));
  assert.deepEqual(bad.map((p) => p.slice(ROOT.length)), []);
  assert.ok(!existsSync(join(pub, 'beacon-dev')));
});
