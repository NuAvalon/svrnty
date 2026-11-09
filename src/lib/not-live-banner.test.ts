import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { showNotLiveBanner } from './not-live-banner';

const src = (p: string) => readFileSync(p, 'utf8');

test('shown only on the home page, and only when set to exactly "on"', () => {
  assert.equal(showNotLiveBanner('/', 'on'), true);
  for (const setting of [undefined, '', 'off', 'ON', 'On', '1', 'true', 'on ', ' on']) {
    assert.equal(showNotLiveBanner('/', setting), false, `setting ${JSON.stringify(setting)}`);
  }
  for (const path of [null, '', '/u/alice', '/alice', '/c/abc', '//', '/?x=1']) {
    assert.equal(showNotLiveBanner(path, 'on'), false, `path ${JSON.stringify(path)}`);
  }
});

test('the setting is read on the server, per request, so toggling needs no rebuild', () => {
  const layout = src('app/layout.tsx');
  assert.match(layout, /showNotLiveBanner\(\(await headers\(\)\)\.get\('x-svrnty-path'\), process\.env\.SVRNTY_NOT_LIVE_BANNER\)/);
  assert.match(layout, /\{notLive && <NotLiveBanner \/>\}/);
  assert.match(layout, /export const dynamic = 'force-dynamic'/);
  assert.doesNotMatch(layout + src('src/lib/not-live-banner.ts'), /NEXT_PUBLIC_SVRNTY_NOT_LIVE/);
});

test('middleware overwrites the path header, so a client cannot supply it', () => {
  assert.match(src('middleware.ts'), /headers\.set\('x-svrnty-path', pathname\);/);
});

test('the page no longer renders its own banner', () => {
  assert.doesNotMatch(src('app/page.tsx'), /NotLiveBanner/);
});

test('self-hosters get it off by default, and the setting reaches the app container', () => {
  assert.match(src('docker-compose.yml'), /SVRNTY_NOT_LIVE_BANNER: \$\{SVRNTY_NOT_LIVE_BANNER:-off\}/);
  assert.match(src('.env.example'), /SVRNTY_NOT_LIVE_BANNER=/);
});
