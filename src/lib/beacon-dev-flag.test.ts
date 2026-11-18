// src/lib/beacon-dev-flag.test.ts: #822 (a)-Z. The build-time flag for the dev-only beacon proving files IS the isBeaconWireLive predicate, and next.config.ts inlines it.
// Run: npx tsx --test src/lib/beacon-dev-flag.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { beaconDevArtifactsFlag } from './beacon-dev-flag';
import { isBeaconWireLive } from './claim-gates';

const DOMAINS: Array<string | undefined> = [undefined, '', 'svrnty.is', 'dev.svrnty.is', 'DEV.svrnty.is', 'dev.', 'devx.svrnty.is', 'prod.dev.svrnty.is', 'staging.svrnty.is', 'relay.svrnty.is'];
const LIVES: Array<string | undefined> = [undefined, '', 'true', 'TRUE', 'True', '1', 'false', ' true'];

function withEnv<T>(domain: string | undefined, live: string | undefined, fn: () => T): T {
  const d = process.env.NEXT_PUBLIC_SVRNTY_DOMAIN, l = process.env.NEXT_PUBLIC_BEACON_LIVE;
  try {
    if (domain === undefined) delete process.env.NEXT_PUBLIC_SVRNTY_DOMAIN; else process.env.NEXT_PUBLIC_SVRNTY_DOMAIN = domain;
    if (live === undefined) delete process.env.NEXT_PUBLIC_BEACON_LIVE; else process.env.NEXT_PUBLIC_BEACON_LIVE = live;
    return fn();
  } finally {
    if (d === undefined) delete process.env.NEXT_PUBLIC_SVRNTY_DOMAIN; else process.env.NEXT_PUBLIC_SVRNTY_DOMAIN = d;
    if (l === undefined) delete process.env.NEXT_PUBLIC_BEACON_LIVE; else process.env.NEXT_PUBLIC_BEACON_LIVE = l;
  }
}

test('F1 the flag is EXACTLY isBeaconWireLive() on every (domain, opt-in) pair of the grid, and is only ever "true" or ""', () => {
  let trues = 0;
  for (const d of DOMAINS) for (const l of LIVES) {
    const live = withEnv(d, l, () => isBeaconWireLive());
    const flag = withEnv(d, l, () => beaconDevArtifactsFlag(process.env));
    assert.ok(flag === 'true' || flag === '', `${String(d)}/${String(l)}: ${flag}`);
    assert.equal(flag === 'true', live, `domain=${String(d)} live=${String(l)}`);
    if (flag === 'true') trues++;
  }
  // the three dev domains of the grid with the exact opt-in "true": dev.svrnty.is, DEV.svrnty.is (isDevBuild lower-cases) and the bare "dev." (it is a PREFIX test, so it
  // counts; that is the existing predicate's behaviour and the flag must match it, not tighten it)
  assert.equal(trues, 3);
});

test('F2 a production domain with the opt-in set by mistake, and a dev domain with no opt-in, both give an EMPTY flag', () => {
  assert.equal(beaconDevArtifactsFlag({ NEXT_PUBLIC_SVRNTY_DOMAIN: 'svrnty.is', NEXT_PUBLIC_BEACON_LIVE: 'true' }), '');
  assert.equal(beaconDevArtifactsFlag({ NEXT_PUBLIC_SVRNTY_DOMAIN: 'dev.svrnty.is' }), '');
  assert.equal(beaconDevArtifactsFlag({}), '');
});

test('F3 [static] next.config.ts inlines the flag through env, ALWAYS defined, computed by the same helper', () => {
  const src = readFileSync(new URL('../../next.config.ts', import.meta.url), 'utf8');
  assert.match(src, /import \{ beaconDevArtifactsFlag \} from '\.\/src\/lib\/beacon-dev-flag';/);
  assert.match(src, /env: \{\s*NEXT_PUBLIC_BEACON_DEV_ARTIFACTS: beaconDevArtifactsFlag\(process\.env\),\s*\},/);
});
