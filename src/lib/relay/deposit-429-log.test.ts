// src/lib/relay/deposit-429-log.test.ts
// The deposit route says "429" for two different reasons (per-IP rate limit, mailbox at cap) and the response is the
// same either way. This pins what the OPERATOR sees: one log line per refusal naming the reason and a running count
// for that reason, so a rate-limit measurement can tell the two apart. The line carries NO IP, mailbox id or blob.
// Run: npx tsx --test src/lib/relay/deposit-429-log.test.ts

process.env.RELAY_DB_PATH = ':memory:'; // in-memory SQLite (the runner sets no NODE_ENV)
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { resetMailboxStore } from './mailbox-store';

const IP = '203.0.113.77'; // distinctive, so a leak is a plain substring match
const MBX = 'mbx_429_log_probe';
const BLOB = 'BLOB_429_LOG_PROBE';

let lines: string[] = [];
const real = { warn: console.warn, info: console.info, log: console.log, error: console.error };

beforeEach(async () => {
  delete process.env.RELAY_RATE_LIMIT_MAX;
  delete process.env.RELAY_MAILBOX_CAP;
  globalThis.__mailboxRateLimits = undefined;
  resetMailboxStore();
  const { resetDeposit429Counts } = await import('./deposit-429-log');
  resetDeposit429Counts();
  lines = [];
  const grab = (...a: unknown[]) => { lines.push(a.map(String).join(' ')); };
  console.warn = grab; console.info = grab; console.log = grab; console.error = grab;
});

afterEach(() => {
  Object.assign(console, real);
});

async function deposit(ip: string, mbx = MBX): Promise<number> {
  const { POST } = await import('../../../app/api/relay/envelope/route');
  const res = await POST(new Request('http://r.test/api/relay/envelope', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-forwarded-for': ip },
    body: JSON.stringify({ mailbox_id: mbx, blob: BLOB }),
  }));
  return res.status;
}

test('T1 a rate-limit refusal logs ONE line: reason=rate_limit, count=1', async () => {
  process.env.RELAY_RATE_LIMIT_MAX = '2';
  assert.equal(await deposit(IP), 200);
  assert.equal(await deposit(IP), 200);
  assert.deepEqual(lines, [], 'accepted deposits log nothing');
  assert.equal(await deposit(IP), 429);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /reason=rate_limit/);
  assert.match(lines[0], /count=1\b/);
});

test('T2 a mailbox-at-cap refusal logs reason=mailbox_cap, and the counts are per reason', async () => {
  process.env.RELAY_MAILBOX_CAP = '1';
  assert.equal(await deposit('198.51.100.1'), 200);
  assert.equal(await deposit('198.51.100.2'), 429);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /reason=mailbox_cap/);
  assert.match(lines[0], /count=1\b/);
  assert.doesNotMatch(lines[0], /rate_limit/);
});

test('T3 the count is a RUNNING count per reason', async () => {
  process.env.RELAY_MAILBOX_CAP = '1';
  await deposit('198.51.100.1');
  await deposit('198.51.100.2');
  await deposit('198.51.100.3');
  await deposit('198.51.100.4');
  assert.equal(lines.length, 3);
  assert.deepEqual(lines.map((l) => /count=(\d+)/.exec(l)?.[1]), ['1', '2', '3']);
});

test('T4 no line carries the IP, the mailbox id or the blob (either reason)', async () => {
  process.env.RELAY_RATE_LIMIT_MAX = '1';
  await deposit(IP);
  assert.equal(await deposit(IP), 429); // rate_limit
  process.env.RELAY_RATE_LIMIT_MAX = '100';
  process.env.RELAY_MAILBOX_CAP = '1';
  assert.equal(await deposit('198.51.100.9', 'mbx_other'), 200);
  assert.equal(await deposit('198.51.100.9', 'mbx_other'), 429); // mailbox_cap
  assert.ok(lines.length >= 2, 'both refusals logged (CONTROL: the capture saw output)');
  for (const l of lines) {
    for (const secret of [IP, '198.51.100.9', MBX, 'mbx_other', BLOB]) {
      assert.ok(!l.includes(secret), `log line leaks ${secret}`);
    }
  }
});

test('T5 non-429 refusals (400 bad field, 413 too large) log nothing', async () => {
  const { POST } = await import('../../../app/api/relay/envelope/route');
  const bad = await POST(new Request('http://r.test/api/relay/envelope', {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': IP }, body: JSON.stringify({ blob: BLOB }),
  }));
  assert.equal(bad.status, 400);
  const big = await POST(new Request('http://r.test/api/relay/envelope', {
    method: 'POST', headers: { 'content-type': 'application/json', 'content-length': String(10 * 1024 * 1024), 'x-forwarded-for': IP }, body: '{}',
  }));
  assert.equal(big.status, 413);
  assert.deepEqual(lines, []);
});

test('T6 the response is unchanged: same 429 body for both reasons (I-4 uniformity not widened)', async () => {
  process.env.RELAY_RATE_LIMIT_MAX = '1';
  const { POST } = await import('../../../app/api/relay/envelope/route');
  const mk = () => new Request('http://r.test/api/relay/envelope', {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': IP }, body: JSON.stringify({ mailbox_id: MBX, blob: BLOB }),
  });
  await POST(mk());
  const r = await POST(mk());
  assert.equal(r.status, 429);
  assert.deepEqual(await r.json(), { error: 'Rate limit exceeded.' });
});
