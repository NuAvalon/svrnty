// src/lib/relay/deposit-limits.test.ts
// Hostile deposits against the real route handler. A deposit needs no account, so these limits are what bound one sender's cost to everyone else.
// Run: npx tsx --test src/lib/relay/deposit-limits.test.ts

process.env.RELAY_DB_PATH = ':memory:';
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CLIENT_IP_HEADER } from './client-ip';
import { resetMailboxStore, pollMailbox, ackDelete } from './mailbox-store';
import { deriveMailboxId } from './mailbox-auth';
import { deriveMailboxIdV2, generateMailboxAuthKeypair } from './mailbox-auth-v2';
import { checkMailboxRateLimit, mailboxLimiterSize } from './mailbox-rate-limit';

const ENV = ['RELAY_RATE_LIMIT_MAX', 'RELAY_RATE_LIMIT_IP_CAP', 'RELAY_MAILBOX_BYTES_CAP', 'RELAY_GLOBAL_DEPOSIT_BYTES_PER_WINDOW', 'RELAY_MAILBOX_CAP', 'RELAY_MAX_PAYLOAD_BYTES'] as const;
const realNow = Date.now;
let clock = 9_000_000;
const MB = deriveMailboxId('A'.repeat(64));
const MB2 = deriveMailboxId('B'.repeat(64));
const URL_ = 'http://r.test/api/relay/envelope';
let lines: string[] = [];
const realWarn = console.warn;

beforeEach(async () => {
  for (const k of ENV) delete process.env[k];
  process.env.RELAY_RATE_LIMIT_MAX = '1000000';
  globalThis.__mailboxRateLimits = undefined;
  resetMailboxStore();
  const budget = await import('./deposit-budget').catch(() => null);
  budget?.resetDepositBudget();
  (await import('./deposit-429-log')).resetDeposit429Counts();
  clock = 9_000_000;
  Date.now = () => clock;
  lines = [];
  console.warn = (...a: unknown[]) => { lines.push(a.map(String).join(' ')); };
});
afterEach(() => { Date.now = realNow; console.warn = realWarn; });

async function post(init: { body?: string; stream?: ReadableStream<Uint8Array>; ip?: string }) {
  const { POST } = await import('../../../app/api/relay/envelope/route');
  const req = new Request(URL_, {
    method: 'POST',
    headers: { 'content-type': 'application/json', [CLIENT_IP_HEADER]: init.ip ?? '203.0.113.5' },
    body: init.stream ?? init.body,
    ...(init.stream ? { duplex: 'half' } : {}),
  } as RequestInit);
  return POST(req);
}
const deposit = (mailbox_id: unknown, blob: unknown = 'sealed-blob', ip?: string) => post({ body: JSON.stringify({ mailbox_id, blob }), ip });
const stored = (id: string) => pollMailbox(id, Date.now()).length;

/** A body with no Content-Length that counts what the server actually pulled. */
function chunked(chunkBytes: number, total: number, head = '') {
  const enc = new TextEncoder();
  let sent = 0, first = true;
  const stats = { pulled: 0, cancelled: false };
  const stream = new ReadableStream<Uint8Array>({
    pull(c) {
      if (sent >= total) { c.close(); return; }
      const bytes = first && head ? enc.encode(head) : new Uint8Array(chunkBytes).fill(0x41);
      first = false;
      sent += bytes.byteLength; stats.pulled = sent;
      c.enqueue(bytes);
    },
    cancel() { stats.cancelled = true; },
  }, { highWaterMark: 0 });
  return { stream, stats };
}

test('P1 a chunked body over the cap is refused, and the server stops reading near the cap', async () => {
  const { stream, stats } = chunked(16 * 1024, 50 * 1024 * 1024);
  const res = await post({ stream });
  assert.equal(res.status, 413);
  assert.ok(stats.pulled <= 64 * 1024 + 2 * 16 * 1024, `pulled ${stats.pulled} bytes`);
  assert.equal(stats.cancelled, true, 'the body stream is cancelled, not left open');
});

test('P1 a chunked body under the cap is still accepted', async () => {
  const json = JSON.stringify({ mailbox_id: MB, blob: 'x'.repeat(1000) });
  const res = await post({ stream: chunked(1, json.length, json).stream });
  assert.equal(res.status, 200);
  assert.equal(stored(MB), 1);
});

test('P1 a body exactly at the cap is read in full', async () => {
  process.env.RELAY_MAX_PAYLOAD_BYTES = '2000';
  const shell = JSON.stringify({ mailbox_id: MB, blob: '' });
  const json = JSON.stringify({ mailbox_id: MB, blob: 'y'.repeat(2000 - shell.length) });
  assert.equal(json.length, 2000);
  assert.equal((await post({ stream: chunked(1, json.length, json).stream })).status, 200);
});

test('a deposit over its per-address limit is refused before any of the body is read', async () => {
  process.env.RELAY_RATE_LIMIT_MAX = '1';
  assert.equal((await deposit(MB)).status, 200);
  const { stream, stats } = chunked(1024, 1024 * 1024);
  assert.equal((await post({ stream })).status, 429);
  assert.equal(stats.pulled, 0);
});

for (const [name, id] of [
  ['far too long', 'mbx_' + 'a'.repeat(10 * 1024)],
  ['empty', ''],
  ['the wrong prefix', 'box_' + 'a'.repeat(64)],
  ['uppercase hex', 'mbx_' + 'A'.repeat(64)],
  ['63 hex', 'mbx_' + 'a'.repeat(63)],
  ['65 hex', 'mbx_' + 'a'.repeat(65)],
  ['a v2 prefix with v1 length wrong', 'mbx2_' + 'a'.repeat(63)],
  ['not a string', 7],
  ['an object', { a: 1 }],
] as const) {
  test(`P2 mailbox_id ${name}: 400, nothing stored`, async () => {
    const res = await deposit(id);
    assert.equal(res.status, 400);
    if (typeof id === 'string' && id) assert.equal(stored(id), 0);
  });
}

test('P2 a mailbox_id so long the body passes the cap is refused by the cap, and stores nothing', async () => {
  const id = 'mbx_' + 'a'.repeat(1024 * 1024);
  assert.equal((await deposit(id)).status, 413);
  assert.equal(stored(id), 0);
});

test('P2 a real v1 id and a real v2 id are both accepted', async () => {
  const v2 = deriveMailboxIdV2(generateMailboxAuthKeypair());
  assert.equal((await deposit(MB)).status, 200);
  assert.equal((await deposit(v2)).status, 200);
  assert.equal(stored(MB), 1);
  assert.equal(stored(v2), 1);
});

test('P3 IPv6: one /64 is one budget, another /64 is not affected, spelling does not matter', async () => {
  process.env.RELAY_RATE_LIMIT_MAX = '10';
  for (let i = 1; i <= 10; i++) assert.equal((await deposit(MB, 'b', `2001:db8:1:2::${i.toString(16)}`)).status, 200, `addr ${i}`);
  assert.equal((await deposit(MB, 'b', '2001:db8:1:2::ff')).status, 429);
  assert.equal((await deposit(MB, 'b', '2001:0db8:0001:0002:0000:0000:0000:00aa')).status, 429, 'the long spelling is the same /64');
  assert.equal((await deposit(MB, 'b', '2001:db8:1:3::1')).status, 200, 'the next /64 has its own budget');
});

test('P3 an IPv4-mapped address counts as that IPv4 address, not as one shared /64', async () => {
  process.env.RELAY_RATE_LIMIT_MAX = '1';
  assert.equal((await deposit(MB, 'b', '::ffff:198.51.100.7')).status, 200);
  assert.equal((await deposit(MB, 'b', '::ffff:198.51.100.7')).status, 429);
  assert.equal((await deposit(MB, 'b', '198.51.100.7')).status, 429, 'the same address, written the other way');
  assert.equal((await deposit(MB, 'b', '::ffff:198.51.100.8')).status, 200, 'a different mapped address has its own budget');
});

test('P3 IPv4 addresses stay separate', async () => {
  process.env.RELAY_RATE_LIMIT_MAX = '1';
  assert.equal((await deposit(MB, 'b', '198.51.100.1')).status, 200);
  assert.equal((await deposit(MB, 'b', '198.51.100.1')).status, 429);
  assert.equal((await deposit(MB, 'b', '198.51.100.2')).status, 200);
});

test('P4 the global budget caps accepted bytes per window, from any address to any mailbox, and recovers when the window turns', async () => {
  process.env.RELAY_GLOBAL_DEPOSIT_BYTES_PER_WINDOW = '3000';
  const blob = 'x'.repeat(1000);
  let accepted = 0, refused = 0;
  for (let i = 0; i < 12; i++) {
    const res = await deposit(deriveMailboxId(String(i).padStart(64, '0')), blob, `198.51.100.${i + 1}`);
    if (res.status === 200) accepted++; else { assert.equal(res.status, 429); refused++; }
  }
  assert.equal(accepted, 3);
  assert.equal(refused, 9);
  assert.ok(lines.some((l) => /reason=global_budget/.test(l)), 'the operator can tell this 429 from the others');
  clock += 60_001;
  assert.equal((await deposit(MB, blob, '198.51.100.200')).status, 200, 'an ordinary deposit is served after the flood stops');
  assert.equal(stored(MB), 1);
});

test('P4 a refused deposit spends none of the budget', async () => {
  process.env.RELAY_GLOBAL_DEPOSIT_BYTES_PER_WINDOW = '2000';
  process.env.RELAY_MAILBOX_CAP = '1';
  const blob = 'x'.repeat(1000);
  assert.equal((await deposit(MB, blob)).status, 200);
  for (let i = 0; i < 5; i++) assert.equal((await deposit(MB, blob)).status, 429, 'mailbox at cap');
  assert.equal((await deposit(MB2, blob)).status, 200, 'refusals did not use up the window');
});

test('P5 a mailbox past its byte cap refuses more, another mailbox is unaffected, and an ack frees room', async () => {
  process.env.RELAY_MAILBOX_BYTES_CAP = '2500';
  const blob = 'x'.repeat(1000);
  assert.equal((await deposit(MB, blob)).status, 200);
  assert.equal((await deposit(MB, blob)).status, 200);
  assert.equal((await deposit(MB, blob)).status, 429, 'a third would pass 2500 bytes');
  assert.ok(lines.some((l) => /reason=mailbox_cap/.test(l)));
  assert.equal((await deposit(MB2, blob)).status, 200);
  const held = pollMailbox(MB, Date.now());
  ackDelete(MB, [held[0].envelope_id], Date.now());
  assert.equal((await deposit(MB, blob)).status, 200, 'an ack freed room');
});

test('P5 a mailbox can be filled exactly to its byte cap', async () => {
  process.env.RELAY_MAILBOX_BYTES_CAP = '2000';
  const blob = 'x'.repeat(1000);
  assert.equal((await deposit(MB, blob)).status, 200);
  assert.equal((await deposit(MB, blob)).status, 200);
  assert.equal((await deposit(MB, 'y')).status, 429);
});

test('P5 the byte cap has a 16 MiB default and the count cap is unchanged', async () => {
  const { mailboxConfig } = await import('./mailbox-config');
  const cfg = mailboxConfig() as unknown as Record<string, number>;
  assert.equal(cfg.mailboxBytesCap, 16 * 1024 * 1024);
  assert.equal(cfg.cap, 1000);
  assert.equal(cfg.globalDepositBytesPerWindow, 0, '0 means derive it from this disk');
  assert.equal(cfg.rateLimitIpCap, 50_000);
});

const GiB = 1024 ** 3;
const disk = (totalBytes: number, availBytes: number) => () => ({ blocks: totalBytes / 4096, bavail: availBytes / 4096, bsize: 4096 });
const PATH = '/data/relay/mailbox.sqlite';
const DAY = 24 * 60 * 60 * 1000;

test('budget default: a big disk is held at the ceiling, at 7 days and at 30', async () => {
  const { depositBudgetBytes, resetDepositBudget, DERIVED_BUDGET_MAX } = await import('./deposit-budget');
  const prod = disk(2127283216384, 1565872836608);
  assert.equal(depositBudgetBytes(PATH, 1, prod), DERIVED_BUDGET_MAX);
  resetDepositBudget();
  process.env.RELAY_ENVELOPE_TTL_MS = String(30 * DAY);
  assert.equal(depositBudgetBytes(PATH, 1, prod), DERIVED_BUDGET_MAX);
  delete process.env.RELAY_ENVELOPE_TTL_MS;
});

test('budget default: a small VPS gets what its own disk can hold for one retention', async () => {
  const { depositBudgetBytes, resetDepositBudget } = await import('./deposit-budget');
  const vps = disk(20 * GiB, 10 * GiB); // 50% used, watermark 80% -> 6 GiB of room
  const sevenDays = depositBudgetBytes(PATH, 1, vps);
  assert.equal(sevenDays, Math.floor(6 * GiB / (7 * 24 * 60)));
  resetDepositBudget();
  process.env.RELAY_ENVELOPE_TTL_MS = String(30 * DAY);
  const thirtyDays = depositBudgetBytes(PATH, 1, vps);
  delete process.env.RELAY_ENVELOPE_TTL_MS;
  assert.ok(thirtyDays < sevenDays, 'a longer retention means a smaller budget');
  assert.ok(thirtyDays * 30 * 24 * 60 <= 6 * GiB, 'a flood lasting the whole retention stays under the watermark');
});

test('budget default: a disk at or past the watermark keeps the floor, so a little mail still goes', async () => {
  const { depositBudgetBytes, DERIVED_BUDGET_MIN } = await import('./deposit-budget');
  assert.equal(depositBudgetBytes(PATH, 1, disk(20 * GiB, 1 * GiB)), DERIVED_BUDGET_MIN);
});

test('budget default: an unreadable disk gets the ceiling, and an explicit setting always wins', async () => {
  const { depositBudgetBytes, resetDepositBudget, DERIVED_BUDGET_MAX } = await import('./deposit-budget');
  assert.equal(depositBudgetBytes(PATH, 1, () => { throw new Error('no statfs'); }), DERIVED_BUDGET_MAX);
  resetDepositBudget();
  process.env.RELAY_GLOBAL_DEPOSIT_BYTES_PER_WINDOW = '4242';
  assert.equal(depositBudgetBytes(PATH, 1, disk(20 * GiB, 10 * GiB)), 4242);
});

test('budget default: the disk is re-read at most every 30 s', async () => {
  const { depositBudgetBytes } = await import('./deposit-budget');
  let reads = 0;
  const counted = () => { reads++; return disk(20 * GiB, 10 * GiB)(); };
  depositBudgetBytes(PATH, 1_000, counted);
  depositBudgetBytes(PATH, 30_000, counted);
  assert.equal(reads, 1);
  depositBudgetBytes(PATH, 31_001, counted);
  assert.equal(reads, 2);
});

test('budget default: the computed value is logged once, not per deposit', async () => {
  const { depositBudgetBytes } = await import('./deposit-budget');
  const realInfo = console.info;
  const seen: string[] = [];
  console.info = (...a: unknown[]) => { seen.push(a.map(String).join(' ')); };
  try {
    for (let t = 1; t < 200_000; t += 40_000) depositBudgetBytes(PATH, t, disk(20 * GiB, 10 * GiB));
  } finally { console.info = realInfo; }
  assert.equal(seen.length, 1);
  assert.match(seen[0], /deposit budget: \d+ bytes per window/);
});

test('the relay routes are outside the middleware matcher, so Next does not read a body before the route can refuse it', () => {
  const src = readFileSync(join(process.cwd(), 'middleware.ts'), 'utf8');
  assert.match(src, /matcher: \['\/\(\(\?!_next\/static\|_next\/image\|favicon\.ico\|api\/relay\)\.\*\)'\]/);
});

test('P6 the limiter map never grows past its cap, an existing bucket keeps its count, new addresses share the overflow bucket', () => {
  process.env.RELAY_RATE_LIMIT_MAX = '5';
  process.env.RELAY_RATE_LIMIT_IP_CAP = '1000';
  const now = 1_000_000;
  checkMailboxRateLimit('198.51.100.9', now);
  let refusedNew = 0, peak = 0;
  for (let i = 0; i < 200_000; i++) {
    const ok = checkMailboxRateLimit(`10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`, now);
    if (!ok) refusedNew++;
    if (i % 1000 === 0) peak = Math.max(peak, mailboxLimiterSize());
  }
  peak = Math.max(peak, mailboxLimiterSize());
  assert.ok(peak <= 1001, `peak ${peak}`);
  assert.ok(refusedNew > 198_000, `new addresses share one bucket once full (refused ${refusedNew})`);
  for (let i = 0; i < 4; i++) assert.equal(checkMailboxRateLimit('198.51.100.9', now), true, 'an existing address keeps its own budget');
  assert.equal(checkMailboxRateLimit('198.51.100.9', now), false);
});

test('P6 expired addresses are swept when the map is full, so new addresses get their own buckets again', () => {
  process.env.RELAY_RATE_LIMIT_MAX = '5';
  process.env.RELAY_RATE_LIMIT_IP_CAP = '10';
  const now = 1_000_000;
  for (let i = 0; i < 10; i++) checkMailboxRateLimit(`10.0.0.${i}`, now);
  assert.equal(mailboxLimiterSize(), 10);
  const later = now + 60_001 + 1_000;
  assert.equal(checkMailboxRateLimit('10.0.1.1', later), true);
  assert.ok(mailboxLimiterSize() <= 2, `swept to ${mailboxLimiterSize()}`);
});
