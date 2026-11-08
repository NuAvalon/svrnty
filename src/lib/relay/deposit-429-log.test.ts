// src/lib/relay/deposit-429-log.test.ts
// The deposit route says "429" for two different reasons (per-IP rate limit, mailbox at cap) and the response is the
// same either way. This pins what the OPERATOR sees: a log line naming the reason and a running count for that reason, so a
// rate-limit measurement can tell the two apart. The line carries NO IP, mailbox id or blob. Volume is bounded: the first
// refusal of a reason logs at once, then at most one line per reason per 60 s (T7, T8).
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
const realNow = Date.now;
let clock = 5_000_000;

beforeEach(async () => {
  delete process.env.RELAY_RATE_LIMIT_MAX;
  delete process.env.RELAY_MAILBOX_CAP;
  globalThis.__mailboxRateLimits = undefined;
  resetMailboxStore();
  const { resetDeposit429Counts } = await import('./deposit-429-log');
  resetDeposit429Counts();
  lines = [];
  clock = 5_000_000;
  Date.now = () => clock;
  const grab = (...a: unknown[]) => { lines.push(a.map(String).join(' ')); };
  console.warn = grab; console.info = grab; console.log = grab; console.error = grab;
});

afterEach(() => {
  Object.assign(console, real);
  Date.now = realNow;
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
  assert.match(lines[0], /since_last=1\b/);
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

test('T3 the count is a RUNNING total per reason: a later line carries the total and what it folded in', async () => {
  process.env.RELAY_MAILBOX_CAP = '1';
  await deposit('198.51.100.1');
  await deposit('198.51.100.2'); // refusal 1: logs
  await deposit('198.51.100.3'); // refusal 2: folded
  await deposit('198.51.100.4'); // refusal 3: folded
  assert.equal(lines.length, 1);
  clock += 60_000;
  await deposit('198.51.100.5'); // refusal 4: window passed, logs
  assert.equal(lines.length, 2);
  assert.match(lines[1], /count=4\b/);
  assert.match(lines[1], /since_last=3\b/);
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

test('T6 the 429 bodies are unchanged (each reason keeps its own existing body)', async () => {
  const { POST } = await import('../../../app/api/relay/envelope/route');
  const mk = (ip: string, mbx: string) => new Request('http://r.test/api/relay/envelope', {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': ip }, body: JSON.stringify({ mailbox_id: mbx, blob: BLOB }),
  });
  process.env.RELAY_RATE_LIMIT_MAX = '1';
  await POST(mk(IP, MBX));
  const rl = await POST(mk(IP, MBX));
  assert.equal(rl.status, 429);
  assert.deepEqual(await rl.json(), { error: 'Rate limit exceeded.' });
  process.env.RELAY_RATE_LIMIT_MAX = '100';
  process.env.RELAY_MAILBOX_CAP = '1';
  await POST(mk('198.51.100.20', 'mbx_cap_body'));
  const cap = await POST(mk('198.51.100.20', 'mbx_cap_body'));
  assert.equal(cap.status, 429);
  assert.deepEqual(await cap.json(), { error: 'Mailbox at capacity.' });
});

test('T7 a flood inside one window writes ONE line per reason, and the next window folds the flood into the total', async () => {
  process.env.RELAY_RATE_LIMIT_MAX = '1';
  await deposit(IP); // accepted
  for (let i = 0; i < 1000; i++) assert.equal(await deposit(IP), 429);
  assert.equal(lines.length, 1, '1,000 rate_limit refusals in one window = 1 line');
  process.env.RELAY_RATE_LIMIT_MAX = '100000';
  process.env.RELAY_MAILBOX_CAP = '1';
  await deposit('198.51.100.30', 'mbx_flood');
  for (let i = 0; i < 1000; i++) assert.equal(await deposit('198.51.100.30', 'mbx_flood'), 429);
  assert.equal(lines.length, 2, 'and 1,000 mailbox_cap refusals add exactly one more (each reason has its own window)');
  clock += 60_000;
  process.env.RELAY_RATE_LIMIT_MAX = '1';
  process.env.RELAY_MAILBOX_CAP = '1000';
  globalThis.__mailboxRateLimits = undefined;
  await deposit('203.0.113.99'); // fresh bucket: accepted
  assert.equal(await deposit('203.0.113.99'), 429);
  const last = lines[lines.length - 1];
  assert.match(last, /reason=rate_limit/);
  assert.match(last, /count=1001\b/);
  assert.match(last, /since_last=1000\b/);
});

test('T8 the window is 60 s exactly: 59.999 s later is still folded, 60 s later logs', async () => {
  process.env.RELAY_MAILBOX_CAP = '1';
  await deposit('198.51.100.1');
  await deposit('198.51.100.2'); // logs at clock
  clock += 59_999;
  await deposit('198.51.100.3');
  assert.equal(lines.length, 1);
  clock += 1;
  await deposit('198.51.100.4');
  assert.equal(lines.length, 2);
});
