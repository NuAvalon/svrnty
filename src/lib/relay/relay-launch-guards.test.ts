// src/lib/relay/relay-launch-guards.test.ts
// Launch plan v2 L4 (Archie #2202): #707 client-ip v1 (Flint #1329) + the disk watermark (429, Hypatia #2204).
//
// Run: npx tsx --test src/lib/relay/relay-launch-guards.test.ts

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CLIENT_IP_HEADER, UNKNOWN_CLIENT, getClientIP } from './client-ip';
import { checkMailboxRateLimit, getClientIP as rateLimitGetClientIP } from './mailbox-rate-limit';
import { relayDiskFull, resetDiskWatermarkCache, usedFraction } from './disk-watermark';

const req = (h: Record<string, string>) => new Request('http://r.test/x', { headers: h });

beforeEach(() => {
  resetDiskWatermarkCache();
  delete process.env.RELAY_DISK_WATERMARK_PCT;
  globalThis.__mailboxRateLimits = undefined;
});

// ---- #707 C3: only the Caddy-set header counts

test('C3: the client IP is the X-Svrnty-Client-IP value (v4 and v6), trimmed', () => {
  assert.equal(getClientIP(req({ [CLIENT_IP_HEADER]: ' 203.0.113.7 ' })), '203.0.113.7');
  assert.equal(getClientIP(req({ [CLIENT_IP_HEADER]: '2001:db8::1' })), '2001:db8::1');
});

test('C3 NEG: leftmost X-Forwarded-For, X-Real-IP and Cf-Connecting-IP are NEVER read (all forgeable by the client)', () => {
  const forged = { 'x-forwarded-for': '198.51.100.9, 172.70.1.1', 'x-real-ip': '198.51.100.9', 'cf-connecting-ip': '198.51.100.9' };
  assert.equal(getClientIP(req(forged)), UNKNOWN_CLIENT);
  assert.equal(getClientIP(req({ ...forged, [CLIENT_IP_HEADER]: '203.0.113.7' })), '203.0.113.7');
});

test('C3 NEG: a missing or malformed header is the one shared strict bucket', () => {
  // (a CR/LF value can't reach us: undici refuses it when the Request is built)
  for (const v of ['', 'not-an-ip', '1.2.3.4; drop', 'x'.repeat(60), '203.0.113.7, 198.51.100.9'])
    assert.equal(getClientIP(req(v ? { [CLIENT_IP_HEADER]: v } : {})), UNKNOWN_CLIENT, JSON.stringify(v));
});

test('C3: the rate limiter keys on the header: two real clients behind ONE Cloudflare edge get separate budgets', () => {
  assert.equal(rateLimitGetClientIP, getClientIP, 'one function, one rule');
  const now = 1_000_000;
  const edge = { 'x-forwarded-for': '172.70.1.1' }; // what the app saw before #707: the same CF edge for both
  for (let i = 0; i < 10; i++) assert.equal(checkMailboxRateLimit(getClientIP(req({ ...edge, [CLIENT_IP_HEADER]: '203.0.113.1' })), now), true);
  assert.equal(checkMailboxRateLimit(getClientIP(req({ ...edge, [CLIENT_IP_HEADER]: '203.0.113.1' })), now), false, 'A is over its own budget');
  assert.equal(checkMailboxRateLimit(getClientIP(req({ ...edge, [CLIENT_IP_HEADER]: '203.0.113.2' })), now), true, 'B is not throttled by A');
});

test('C3 NEG: varying a forged X-Forwarded-For does NOT buy a fresh budget', () => {
  const now = 2_000_000;
  for (let i = 0; i < 10; i++) checkMailboxRateLimit(getClientIP(req({ 'x-forwarded-for': `198.51.100.${i}` })), now);
  assert.equal(checkMailboxRateLimit(getClientIP(req({ 'x-forwarded-for': '198.51.100.99' })), now), false);
});

test('C5: client-ip.ts never logs (the value only keys the in-memory limiter)', () => {
  const src = readFileSync(join(__dirname, 'client-ip.ts'), 'utf8');
  assert.doesNotMatch(src, /console\./);
});

// ---- L4 disk watermark

const fs = (usedPct: number) => () => ({ blocks: 1000, bavail: 1000 - usedPct * 10, bsize: 4096 });

test('watermark: used fraction is 1 - bavail/blocks; at or above the % → full', () => {
  assert.equal(usedFraction('/data/relay/mailbox.sqlite', fs(25)), 0.25);
  assert.equal(relayDiskFull('/data/relay/mailbox.sqlite', 0, fs(79)), false);
  resetDiskWatermarkCache();
  assert.equal(relayDiskFull('/data/relay/mailbox.sqlite', 0, fs(80)), true, 'default 80%');
  resetDiskWatermarkCache();
  process.env.RELAY_DISK_WATERMARK_PCT = '90';
  assert.equal(relayDiskFull('/data/relay/mailbox.sqlite', 0, fs(85)), false, 'operator override');
});

test('watermark: statfs is re-read at most every 30 s, then the new state applies', () => {
  let calls = 0;
  let used = 50;
  const s = () => (calls++, { blocks: 1000, bavail: 1000 - used * 10, bsize: 4096 });
  assert.equal(relayDiskFull('/d/m.sqlite', 0, s), false);
  used = 95;
  assert.equal(relayDiskFull('/d/m.sqlite', 29_000, s), false, 'cached');
  assert.equal(calls, 1);
  assert.equal(relayDiskFull('/d/m.sqlite', 30_000, s), true);
});

test('watermark: an unreadable filesystem ALLOWS deposits (fail-open); :memory: is never full', () => {
  assert.equal(relayDiskFull('/d/m.sqlite', 0, () => { throw new Error('EIO'); }), false);
  resetDiskWatermarkCache();
  assert.equal(relayDiskFull('/d/m.sqlite', 0, () => ({ blocks: 0, bavail: 0, bsize: 4096 })), false);
  assert.equal(relayDiskFull(':memory:', 0, fs(100)), false);
});

test('route: the deposit route answers 429 while the data filesystem is above the watermark, and deposits again below it', async () => {
  process.env.RELAY_DB_PATH = join(mkdtempSync(join(tmpdir(), 'relay-l4-')), 'mailbox.sqlite');
  const { POST } = await import('../../../app/api/relay/envelope/route');
  const deposit = () =>
    POST(new Request('http://r.test/api/relay/envelope', {
      method: 'POST',
      headers: { 'content-type': 'application/json', [CLIENT_IP_HEADER]: '203.0.113.50' },
      body: JSON.stringify({ mailbox_id: 'mbx_' + 'a'.repeat(64), blob: 'x' }),
    }));
  process.env.RELAY_DISK_WATERMARK_PCT = '100'; // a real filesystem is never 100% used here
  assert.equal((await deposit()).status, 200);
  resetDiskWatermarkCache();
  process.env.RELAY_DISK_WATERMARK_PCT = '1'; // any real filesystem is at least 1% used
  const r = await deposit();
  assert.equal(r.status, 429, 'a definite 4xx, never 5xx/507 (Hypatia #2204)');
  assert.deepEqual(await r.json(), { error: 'Relay storage full.' });
});

test('polls and acks are never refused by the watermark (draining frees the disk)', () => {
  for (const f of ['queue', 'ack']) {
    const src = readFileSync(join(__dirname, '..', '..', '..', 'app', 'api', 'relay', f, 'route.ts'), 'utf8');
    assert.doesNotMatch(src, /disk-watermark|relayDiskFull/, f);
  }
});
