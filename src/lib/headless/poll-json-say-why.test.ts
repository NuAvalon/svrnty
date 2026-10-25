// src/lib/headless/poll-json-say-why.test.ts
//
// Athena #593 / Archie #595 ("say why", the #659 class): `poll-json` used to discard consume's summary, so
// "journaled 0" could not tell "nothing was sent" from "the relay REFUSED our signed poll" (or from "it was
// sent but dropped as not-in-book / undecryptable"). These tests run the REAL scripts/devin-comm.ts against a
// local mock relay and pin: the refusal is named on stderr, the stdout JSON carries polled / rejected / dropped,
// the pre-existing keys are untouched (a wrapper that parses them keeps working), and the exit code stays 0.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { mintHeadlessAgent, serializeMintArtifact } from '../identity/headless-mint';

const REPO = resolve(__dirname, '../../..');
const CLI = join(REPO, 'scripts', 'devin-comm.ts');

type Req = { method: string; url: string };
/** A mock relay whose GET /queue answers `queue(...)`; every other request (acks) answers 200. */
async function withRelay<T>(
  queue: () => { status: number; body: string },
  fn: (relayBase: string, seen: Req[]) => Promise<T>,
): Promise<T> {
  const seen: Req[] = [];
  const server: Server = createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      seen.push({ method: req.method ?? '', url: req.url ?? '' });
      if (req.method === 'GET' && (req.url ?? '').includes('/queue')) {
        const q = queue();
        res.writeHead(q.status, { 'Content-Type': 'application/json' });
        res.end(q.body);
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as { port: number }).port;
  try { return await fn(`http://127.0.0.1:${port}/api/relay`, seen); }
  finally { await new Promise<void>((r) => server.close(() => r())); }
}

function runCli(args: string[], env: Record<string, string>): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((done, fail) => {
    const p = spawn(process.execPath, ['--import', 'tsx', CLI, ...args], { cwd: REPO, env: { ...process.env, ...env } });
    let out = '', err = '';
    p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d));
    const t = setTimeout(() => { p.kill('SIGKILL'); fail(new Error(`CLI timed out: ${args.join(' ')}\n${err}`)); }, 150_000);
    p.on('exit', (code) => { clearTimeout(t); done({ code, out, err }); });
  });
}

async function agentDir(): Promise<string> {
  const dir = mkdtempSync(join(tmpdir(), 'polljson-'));
  const me = await mintHeadlessAgent({ throwaway: true });
  writeFileSync(join(dir, 'mint.json'), JSON.stringify(serializeMintArtifact(me)), { mode: 0o600 });
  return dir;
}

/** poll-json prints exactly one JSON summary line on stdout. */
function summaryOf(out: string): Record<string, unknown> {
  const line = out.trim().split('\n').filter((l) => l.startsWith('{')).pop();
  assert.ok(line, `no JSON summary on stdout: ${JSON.stringify(out)}`);
  return JSON.parse(line!);
}

const OLD_KEYS = ['journaled', 'skipped', 'skipped_loom', 'loom_notices', 'decrypt_failed', 'dead', 'journal'];

test('poll-json: a poll the relay REFUSES (401) is named on stderr and in the JSON; exit stays 0', async () => {
  const dir = await agentDir();
  try {
    await withRelay(() => ({ status: 401, body: '{"error":"unauthorized"}' }), async (relay) => {
      const r = await runCli(['poll-json'], { SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: relay });
      assert.equal(r.code, 0, r.err);
      assert.match(r.err, /^POLL REFUSED by the relay: HTTP 401 \(a refused poll is not an empty mailbox\)$/m);
      const s = summaryOf(r.out);
      assert.equal(s.rejected, 401);
      assert.equal(s.polled, 0);
      assert.equal(s.journaled, 0);                      // the very case that used to look like "nothing sent"
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('poll-json: the status is named EXACTLY (a 429 is not reported as a 401)', async () => {
  const dir = await agentDir();
  try {
    await withRelay(() => ({ status: 429, body: '{"error":"Rate limit exceeded."}' }), async (relay) => {
      const r = await runCli(['poll-json'], { SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: relay });
      assert.match(r.err, /POLL REFUSED by the relay: HTTP 429/);
      assert.equal(summaryOf(r.out).rejected, 429);
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('poll-json: a CLEAN empty poll says rejected:null and prints no refusal; the old keys are all still there', async () => {
  const dir = await agentDir();
  try {
    await withRelay(() => ({ status: 200, body: '[]' }), async (relay) => {
      const r = await runCli(['poll-json'], { SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: relay });
      assert.equal(r.code, 0, r.err);
      assert.doesNotMatch(r.err, /POLL REFUSED/);
      const s = summaryOf(r.out);
      assert.equal(s.rejected, null);
      assert.equal(s.polled, 0);
      assert.equal(s.dropped, 0);
      for (const k of OLD_KEYS) assert.ok(k in s, `pre-existing key '${k}' must still be present`);
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('poll-json: an envelope that arrives but cannot be opened shows as polled:1 dropped:1, NOT as a silent "journaled 0"', async () => {
  const dir = await agentDir();
  try {
    const envelope = [{ envelope_id: 'env_garbage_1', blob: 'this-is-not-a-sealed-blob' }];
    await withRelay(() => ({ status: 200, body: JSON.stringify(envelope) }), async (relay) => {
      const r = await runCli(['poll-json'], { SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: relay });
      assert.equal(r.code, 0, r.err);
      assert.doesNotMatch(r.err, /POLL REFUSED/);          // the relay answered fine; the problem is the envelope
      const s = summaryOf(r.out);
      assert.equal(s.rejected, null);
      assert.equal(s.polled, 1);
      assert.equal(s.dropped, 1);
      assert.equal(s.journaled, 0);
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
