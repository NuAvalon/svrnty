// src/lib/relay/mailbox-rate-limit.test.ts
// #630 (Flint condition 2): pin the PRODUCTION deposit limiter so no e2e convenience can loosen it
// unnoticed. Default = 10 deposits per 60 s per IP; the 11th in a window is refused; the window
// resets; buckets are per-IP. Pure + deterministic (explicit `now`, env cleared, buckets reset).
// Run: PATH=~/.nvm/versions/node/v22.22.1/bin:$PATH npx tsx --test src/lib/relay/mailbox-rate-limit.test.ts

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { checkMailboxRateLimit } from './mailbox-rate-limit';
import { mailboxConfig } from './mailbox-config';

beforeEach(() => {
  delete process.env.RELAY_RATE_LIMIT_MAX;
  delete process.env.RELAY_RATE_LIMIT_WINDOW_MS;
  globalThis.__mailboxRateLimits = undefined;
});

test('production defaults: 10 deposits per 60 s per IP', () => {
  const cfg = mailboxConfig();
  assert.equal(cfg.rateLimitMax, 10);
  assert.equal(cfg.rateLimitWindowMs, 60_000);
});

test('limit + 1 in one window is refused (the 11th deposit gets the 429 path)', () => {
  const t0 = 1_000_000;
  for (let i = 1; i <= 10; i++) assert.equal(checkMailboxRateLimit('203.0.113.7', t0 + i), true, `deposit ${i} allowed`);
  assert.equal(checkMailboxRateLimit('203.0.113.7', t0 + 11), false, '11th deposit refused');
  assert.equal(checkMailboxRateLimit('203.0.113.7', t0 + 12), false, 'still refused inside the window');
});

test('the window resets: after 60 s the same IP is allowed again', () => {
  const t0 = 2_000_000;
  for (let i = 0; i < 10; i++) checkMailboxRateLimit('203.0.113.8', t0);
  assert.equal(checkMailboxRateLimit('203.0.113.8', t0 + 1), false);
  assert.equal(checkMailboxRateLimit('203.0.113.8', t0 + 60_001), true, 'new window opens after resetAt');
});

test('buckets are per IP: one IP exhausting its budget does not throttle another', () => {
  const t0 = 3_000_000;
  for (let i = 0; i < 10; i++) checkMailboxRateLimit('198.51.100.1', t0);
  assert.equal(checkMailboxRateLimit('198.51.100.1', t0 + 1), false);
  assert.equal(checkMailboxRateLimit('198.51.100.2', t0 + 1), true);
});
