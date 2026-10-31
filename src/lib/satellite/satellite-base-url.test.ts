// src/lib/satellite/satellite-base-url.test.ts
// The /api/satellite env fence (Flint lane #2583, Archie #2588 (3)): a non-dev build never forwards to a dev satellite host.
// Run: npx tsx --test src/lib/satellite/satellite-base-url.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { NextRequest } from 'next/server';
import { DEFAULT_SATELLITE_URL, SatelliteEnvRefused, isDevBuild, satelliteBaseUrl } from './satellite-base-url';

test('G1 a dev build (domain dev.*) gets whatever SATELLITE_URL says, dev hosts included', () => {
  assert.equal(satelliteBaseUrl({ SATELLITE_URL: 'http://dev-satellite:8100', NEXT_PUBLIC_SVRNTY_DOMAIN: 'dev.svrnty.is' }), 'http://dev-satellite:8100');
  assert.equal(satelliteBaseUrl({ NEXT_PUBLIC_SVRNTY_DOMAIN: 'dev.svrnty.is' }), DEFAULT_SATELLITE_URL);
  assert.equal(isDevBuild('DEV.svrnty.is'), true);
});

test('G2 NEG: a prod build REFUSES a dev satellite host (the exact cross-env line Flint named)', () => {
  for (const url of ['http://dev-satellite:8100', 'http://dev-registration:8101', 'https://dev.svrnty.is', 'http://DEV-satellite:8100', 'http://dev:9']) {
    assert.throws(() => satelliteBaseUrl({ SATELLITE_URL: url, NEXT_PUBLIC_SVRNTY_DOMAIN: 'svrnty.is' }), SatelliteEnvRefused, url);
  }
});

test('G3 an unset or unknown domain counts as prod (fail closed)', () => {
  assert.throws(() => satelliteBaseUrl({ SATELLITE_URL: 'http://dev-satellite:8100' }), SatelliteEnvRefused);
  assert.throws(() => satelliteBaseUrl({ SATELLITE_URL: 'http://dev-satellite:8100', NEXT_PUBLIC_SVRNTY_DOMAIN: 'id.example.com' }), SatelliteEnvRefused);
  assert.throws(() => satelliteBaseUrl({ SATELLITE_URL: 'http://dev-satellite:8100', NEXT_PUBLIC_SVRNTY_DOMAIN: 'devsvrnty.is' }), SatelliteEnvRefused, '"dev." needs the dot');
  assert.equal(isDevBuild(undefined), false);
});

test('G4 a prod build keeps working with its own hosts, and refuses a URL it cannot parse', () => {
  assert.equal(satelliteBaseUrl({ NEXT_PUBLIC_SVRNTY_DOMAIN: 'svrnty.is' }), 'http://registration:8101');
  assert.equal(satelliteBaseUrl({ SATELLITE_URL: 'http://satellite:8100', NEXT_PUBLIC_SVRNTY_DOMAIN: 'svrnty.is' }), 'http://satellite:8100');
  assert.equal(satelliteBaseUrl({ SATELLITE_URL: 'http://devices.example:1', NEXT_PUBLIC_SVRNTY_DOMAIN: 'svrnty.is' }), 'http://devices.example:1', 'only a "dev" / "dev-" first label is refused');
  assert.throws(() => satelliteBaseUrl({ SATELLITE_URL: 'dev-satellite:8100', NEXT_PUBLIC_SVRNTY_DOMAIN: 'svrnty.is' }), SatelliteEnvRefused);
  assert.throws(() => satelliteBaseUrl({ SATELLITE_URL: 'not a url', NEXT_PUBLIC_SVRNTY_DOMAIN: 'svrnty.is' }), SatelliteEnvRefused);
});

test('G5 NEG end to end: the real /bind route in a prod build with a dev SATELLITE_URL makes ZERO fetch calls and answers 502', async () => {
  const saved = { url: process.env.SATELLITE_URL, dom: process.env.NEXT_PUBLIC_SVRNTY_DOMAIN };
  const calls: string[] = [];
  const orig = globalThis.fetch;
  globalThis.fetch = (async (u: unknown) => {
    calls.push(String(u));
    return new Response('{}', { status: 200 });
  }) as typeof fetch;
  process.env.SATELLITE_URL = 'http://dev-satellite:8100';
  process.env.NEXT_PUBLIC_SVRNTY_DOMAIN = 'svrnty.is';
  try {
    const { POST, GET } = await import('../../../app/api/satellite/bind/route');
    const body = JSON.stringify({ fingerprint: 'a'.repeat(64), sig_pubkey: 'b'.repeat(64), nonce: 'c'.repeat(32), epoch: 0, binding_sig: 'YmluZGluZ19zaWc=' });
    const post = await POST(new NextRequest('http://localhost/api/satellite/bind', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body }));
    assert.equal(post.status, 502);
    const get = await GET(new NextRequest(`http://localhost/api/satellite/bind?fingerprint=${'a'.repeat(64)}`));
    assert.equal(get.status, 502);
    assert.deepEqual(calls, [], 'nothing forwarded: no fingerprint or signing key leaves the prod server');
    // control: the same route in a DEV build forwards
    process.env.NEXT_PUBLIC_SVRNTY_DOMAIN = 'dev.svrnty.is';
    await POST(new NextRequest('http://localhost/api/satellite/bind', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body }));
    assert.equal(calls.length, 1);
    assert.ok(String(calls.at(0)).startsWith('http://dev-satellite:8100/bind'));
  } finally {
    globalThis.fetch = orig;
    if (saved.url === undefined) delete process.env.SATELLITE_URL; else process.env.SATELLITE_URL = saved.url;
    if (saved.dom === undefined) delete process.env.NEXT_PUBLIC_SVRNTY_DOMAIN; else process.env.NEXT_PUBLIC_SVRNTY_DOMAIN = saved.dom;
  }
});

test('G6 static: EVERY /api/satellite route takes its base URL from satelliteBaseUrl(), none reads SATELLITE_URL itself', () => {
  const root = new URL('../../../app/api/satellite/', import.meta.url).pathname;
  const files: string[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d)) {
      const p = join(d, e);
      if (statSync(p).isDirectory()) walk(p);
      else if (e === 'route.ts') files.push(p);
    }
  };
  walk(root);
  assert.ok(files.length >= 7, `found ${files.length} routes`);
  for (const f of files) {
    const src = readFileSync(f, 'utf8');
    assert.doesNotMatch(src, /process\.env\.SATELLITE_URL/, f);
    if (/fetch\(/.test(src)) assert.match(src, /\$\{satelliteBaseUrl\(\)\}/, f);
  }
});
