// src/lib/headless/peer-kem.test.ts
//
// #456 (Flint #180833): where a headless sender gets the recipient's ML-KEM key.
//   Tier 1: the resolver, in isolation (admitted record only, fingerprint-bound, named refusals).
//   Tier 2: the REAL scripts/devin-comm.ts CLI, spawned against a local mock relay, for `send` and
//           `send-tr`: a bound kem deposits (exit 0); an absent / swapped / incomplete kem prints
//           `NOT SENT to <8hex>: <reason>` on stderr, exits non-zero and deposits NOTHING; a kem offered
//           through argv or the environment is ignored; and a refused send-tr leaves
//           ratchet-sessions.json byte-identical (no chain index burned for a message that never left).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { createServer as createTcp } from 'node:net';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { mintHeadlessAgent, serializeMintArtifact } from '../identity/headless-mint';
import { HeadlessStore, type HeadlessContact } from './headless-store';
import { resolvePeerKemForSend, formatNotSent, errorLine, trackedFetch, sendThrowLine } from './peer-kem';

type Minted = Awaited<ReturnType<typeof mintHeadlessAgent>>;
const idOf = (a: Minted) => a.introduction.card.identity as unknown as {
  fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string;
};
function contactOf(a: Minted, over: Partial<HeadlessContact> = {}): HeadlessContact {
  const id = idOf(a);
  return {
    id: 'c_' + id.fingerprint.slice(0, 8), fingerprint: id.fingerprint, public_key: id.public_key,
    pq_kem_public_key: id.pq_kem_public_key, pq_sig_public_key: id.pq_sig_public_key, ...over,
  };
}

// ── Tier 1: the resolver ─────────────────────────────────────────────────────────────────────────

test('resolver: a contact whose kem+sig legs hash to its fingerprint yields exactly the kem on file', async () => {
  const peer = await mintHeadlessAgent({ throwaway: true });
  const r = await resolvePeerKemForSend(contactOf(peer));
  assert.deepEqual(r, { ok: true, kem: idOf(peer).pq_kem_public_key });
});

test('resolver: no contact, no kem, no sig leg → each a NAMED refusal (never ok)', async () => {
  const peer = await mintHeadlessAgent({ throwaway: true });
  const none = await resolvePeerKemForSend(null);
  assert.equal(none.ok, false);
  const noKem = await resolvePeerKemForSend(contactOf(peer, { pq_kem_public_key: undefined }));
  assert.equal(noKem.ok, false);
  assert.match((noKem as { reason: string }).reason, /no PQ key on file: ask them to re-share their card/);
  const noSig = await resolvePeerKemForSend(contactOf(peer, { pq_sig_public_key: undefined }));
  assert.equal(noSig.ok, false);
  assert.match((noSig as { reason: string }).reason, /no PQ signing key on file/);   // its OWN reason, not the mismatch one
});

test('resolver: a kem that is not the one the fingerprint commits to is REFUSED (swap beside a valid fp)', async () => {
  const peer = await mintHeadlessAgent({ throwaway: true });
  const other = await mintHeadlessAgent({ throwaway: true });
  // attacker/edit swaps in another identity's (perfectly well-formed) kem, keeping the victim's fp + keys
  const r = await resolvePeerKemForSend(contactOf(peer, { pq_kem_public_key: idOf(other).pq_kem_public_key }));
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /does not match their fingerprint/);
  // same for a swapped sig leg and a swapped classical key
  const sigSwap = await resolvePeerKemForSend(contactOf(peer, { pq_sig_public_key: idOf(other).pq_sig_public_key }));
  assert.equal(sigSwap.ok, false);
  const pubSwap = await resolvePeerKemForSend(contactOf(peer, { public_key: idOf(other).public_key }));
  assert.equal(pubSwap.ok, false);
});

test('resolver: the ONLY input is the stored record — a kem sitting in argv/env cannot rescue a kem-less contact', async () => {
  const peer = await mintHeadlessAgent({ throwaway: true });
  const kem = idOf(peer).pq_kem_public_key;
  const savedArgv = process.argv.slice();
  process.env.SVRNTY_PEER_KEM = kem; process.env.PEER_KEM = kem; process.env.PEER_PQ_KEM_PUBLIC_KEY = kem;
  process.argv.push('--kem', kem, kem);
  try {
    const r = await resolvePeerKemForSend(contactOf(peer, { pq_kem_public_key: undefined }));
    assert.equal(r.ok, false);
  } finally {
    process.argv.length = 0; process.argv.push(...savedArgv);
    delete process.env.SVRNTY_PEER_KEM; delete process.env.PEER_KEM; delete process.env.PEER_PQ_KEM_PUBLIC_KEY;
  }
});

test('formatNotSent: echoes only a hex prefix of the fingerprint (an operator-typed arg cannot inject text)', () => {
  assert.equal(formatNotSent('ABCDEF0123456789', 'because'), 'NOT SENT to abcdef01: because');
  assert.equal(formatNotSent('abc\nNOT SENT to forged: ok', 'r'), 'NOT SENT to abc: r');
  assert.equal(formatNotSent('zzzz', 'r'), 'NOT SENT to ?: r');
});

// ── Tier 2: the real CLI against a mock relay ─────────────────────────────────────────────────────

const REPO = resolve(__dirname, '../../..');
const CLI = join(REPO, 'scripts', 'devin-comm.ts');

type Deposit = { url: string; body: string };
async function withRelay<T>(fn: (relayBase: string, deposits: Deposit[]) => Promise<T>): Promise<T> {
  const deposits: Deposit[] = [];
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      deposits.push({ url: req.url ?? '', body: Buffer.concat(chunks).toString('utf8') });
      res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{"ok":true}');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as { port: number }).port;
  try { return await fn(`http://127.0.0.1:${port}/api/relay`, deposits); }
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

/** A sender agent dir (mint.json + store.json holding exactly the given contacts). */
async function senderDir(contacts: HeadlessContact[]): Promise<{ dir: string; fp: string }> {
  const dir = mkdtempSync(join(tmpdir(), 'peerkem-'));
  const sender = await mintHeadlessAgent({ throwaway: true });
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(join(dir, 'mint.json'), JSON.stringify(serializeMintArtifact(sender)), { mode: 0o600 });
  const store = new HeadlessStore({ path: join(dir, 'store.json'), lockDir: dir });
  for (const c of contacts) store.upsertContact(c);
  return { dir, fp: idOf(sender).fingerprint };
}

test('CLI send: a bound kem on the admitted record → hybrid deposit, exit 0, nothing on stderr', async () => {
  const peer = await mintHeadlessAgent({ throwaway: true });
  const { dir } = await senderDir([contactOf(peer)]);
  try {
    await withRelay(async (relay, deposits) => {
      const r = await runCli(['send', idOf(peer).fingerprint, 'hello'], { SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: relay });
      assert.equal(r.code, 0, r.err);
      assert.equal(JSON.parse(r.out.trim().split('\n').pop()!).deposited, true);
      assert.equal(deposits.length, 1);
      assert.match(deposits[0].url, /\/api\/relay\/envelope$/);
      assert.doesNotMatch(r.err, /NOT SENT/);
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('CLI send: kem absent → NOT SENT on stderr, non-zero exit, ZERO deposits; a kem in argv/env does not rescue it', async () => {
  const peer = await mintHeadlessAgent({ throwaway: true });
  const { dir } = await senderDir([contactOf(peer, { pq_kem_public_key: undefined })]);
  const kem = idOf(peer).pq_kem_public_key;
  try {
    await withRelay(async (relay, deposits) => {
      const r = await runCli(['send', idOf(peer).fingerprint, 'hello', kem], {
        SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: relay, SVRNTY_PEER_KEM: kem, PEER_KEM: kem,
      });
      assert.notEqual(r.code, 0);
      assert.match(r.err, new RegExp(`NOT SENT to ${idOf(peer).fingerprint.slice(0, 8)}: no PQ key on file: ask them to re-share their card`));
      assert.equal(deposits.length, 0);
      assert.doesNotMatch(r.out, /"deposited":\s*true/);
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('CLI send: a swapped kem (does not match the fingerprint) → refused loudly, ZERO deposits', async () => {
  const peer = await mintHeadlessAgent({ throwaway: true });
  const other = await mintHeadlessAgent({ throwaway: true });
  const { dir } = await senderDir([contactOf(peer, { pq_kem_public_key: idOf(other).pq_kem_public_key })]);
  try {
    await withRelay(async (relay, deposits) => {
      const r = await runCli(['send', idOf(peer).fingerprint, 'hello'], { SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: relay });
      assert.notEqual(r.code, 0);
      assert.match(r.err, /NOT SENT to [0-9a-f]{8}: the PQ key on file does not match their fingerprint/);
      assert.equal(deposits.length, 0);
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('CLI send: the relay rejecting the deposit is NOT silent — stderr line + non-zero exit', async () => {
  const peer = await mintHeadlessAgent({ throwaway: true });
  const { dir } = await senderDir([contactOf(peer)]);
  const server = createServer((_q, res) => { res.writeHead(503); res.end('no'); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as { port: number }).port;
  try {
    const r = await runCli(['send', idOf(peer).fingerprint, 'hello'], { SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: `http://127.0.0.1:${port}/api/relay` });
    assert.notEqual(r.code, 0);
    assert.match(r.err, /NOT SENT to [0-9a-f]{8}: the relay did not accept the deposit/);
    assert.match(r.out, /"deposited":\s*false/);
  } finally { await new Promise<void>((r) => server.close(() => r())); rmSync(dir, { recursive: true, force: true }); }
});

test('CLI send-tr: a bound kem → ratchet packet inside the hybrid outer, ONE deposit, session persisted', async () => {
  const peer = await mintHeadlessAgent({ throwaway: true });
  const { dir } = await senderDir([contactOf(peer)]);
  try {
    await withRelay(async (relay, deposits) => {
      const r = await runCli(['send-tr', idOf(peer).fingerprint, 'tr hello'], { SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: relay });
      assert.equal(r.code, 0, r.err);
      assert.equal(deposits.length, 1);
      assert.equal(existsSync(join(dir, 'ratchet-sessions.json')), true);
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('CLI send-tr: kem absent → refused BEFORE the chain moves: ratchet-sessions.json byte-identical, ZERO deposits', async () => {
  const peer = await mintHeadlessAgent({ throwaway: true });
  const { dir } = await senderDir([contactOf(peer, { pq_kem_public_key: undefined })]);
  const ratchetFile = join(dir, 'ratchet-sessions.json');
  const sentinel = '{"keep":"me"}';
  writeFileSync(ratchetFile, sentinel, { mode: 0o600 });
  try {
    await withRelay(async (relay, deposits) => {
      const r = await runCli(['send-tr', idOf(peer).fingerprint, 'tr hello'], { SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: relay });
      assert.notEqual(r.code, 0);
      assert.match(r.err, /NOT SENT to [0-9a-f]{8}: no PQ key on file: ask them to re-share their card/);
      assert.equal(deposits.length, 0);
      assert.equal(readFileSync(ratchetFile, 'utf8'), sentinel, 'a refused send-tr must not touch the ratchet state');
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('CLI send-tr: a swapped kem → refused, ratchet file byte-identical, ZERO deposits', async () => {
  const peer = await mintHeadlessAgent({ throwaway: true });
  const other = await mintHeadlessAgent({ throwaway: true });
  const { dir } = await senderDir([contactOf(peer, { pq_kem_public_key: idOf(other).pq_kem_public_key })]);
  const ratchetFile = join(dir, 'ratchet-sessions.json');
  writeFileSync(ratchetFile, '{}', { mode: 0o600 });
  try {
    await withRelay(async (relay, deposits) => {
      const r = await runCli(['send-tr', idOf(peer).fingerprint, 'x'], { SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: relay });
      assert.notEqual(r.code, 0);
      assert.match(r.err, /does not match their fingerprint/);
      assert.equal(deposits.length, 0);
      assert.equal(readFileSync(ratchetFile, 'utf8'), '{}');
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('errorLine: one bounded line (newlines collapsed, long messages cut, non-Errors stringified)', () => {
  assert.equal(errorLine(new Error('fetch\nfailed  twice')), 'fetch failed twice');
  assert.equal(errorLine(new Error('x'.repeat(500))).length, 120);
  assert.equal(errorLine('plain'), 'plain');
  // control bytes never survive (a relay-supplied message must not smuggle an escape sequence to a pane)
  const evil = errorLine(new Error('bad\x1b[31m red\x07 bell\x00 nul\x7f del\r\nnext'));
  assert.equal(evil, 'bad [31m red bell nul del next');
  assert.doesNotMatch(evil, /[\x00-\x1f\x7f]/);
  assert.doesNotMatch(sendThrowLine('abcdef01', new Error('x\x1b]0;pwned\x07y'), 'unreachable'), /[\x00-\x1f\x7f]/);
  assert.equal(errorLine(new Error('')), 'unknown error');
});

/** A port nothing listens on (bind, read the port, close) — connecting is refused, so fetch THROWS. */
async function deadRelay(): Promise<string> {
  const s = createTcp();
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', () => r()));
  const port = (s.address() as { port: number }).port;
  await new Promise<void>((r) => s.close(() => r()));
  return `http://127.0.0.1:${port}/api/relay`;
}

test('CLI send: relay UNREACHABLE (fetch throws, not deposited:false) → the same NOT SENT line, non-zero exit', async () => {
  const peer = await mintHeadlessAgent({ throwaway: true });
  const { dir } = await senderDir([contactOf(peer)]);
  try {
    const r = await runCli(['send', idOf(peer).fingerprint, 'hello'], { SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: await deadRelay() });
    assert.notEqual(r.code, 0);
    assert.match(r.err, new RegExp(`^NOT SENT to ${idOf(peer).fingerprint.slice(0, 8)}: the relay could not be reached \\(.+\\)$`, 'm'));
    assert.doesNotMatch(r.out, /"deposited":\s*true/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('CLI send-tr: relay UNREACHABLE → NOT SENT line that says the ratchet index is spent, non-zero exit', async () => {
  const peer = await mintHeadlessAgent({ throwaway: true });
  const { dir } = await senderDir([contactOf(peer)]);
  try {
    const r = await runCli(['send-tr', idOf(peer).fingerprint, 'tr hello'], { SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: await deadRelay() });
    assert.notEqual(r.code, 0);
    assert.match(r.err, /^NOT SENT to [0-9a-f]{8}: the relay could not be reached \(.+\); this ratchet index is spent$/m);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ── a THROW is worded by how far the send got (Hypatia #477): never a false NOT SENT ───────────────

test('trackedFetch: stage follows the request — before-post / unreachable / refused / deposited', async () => {
  const mk = (impl: () => Promise<{ ok: boolean }>) => trackedFetch((async () => impl()) as unknown as typeof fetch);
  const never = mk(async () => ({ ok: true }));
  assert.equal(never.stage(), 'before-post');                                   // no request made (sign/seal threw first)
  const down = mk(async () => { throw new Error('fetch failed'); });
  await assert.rejects(() => down.fetchImpl('http://x'));
  assert.equal(down.stage(), 'unreachable');
  const refused = mk(async () => ({ ok: false }));
  await refused.fetchImpl('http://x');
  assert.equal(refused.stage(), 'refused');
  const ok = mk(async () => ({ ok: true }));
  await ok.fetchImpl('http://x');
  assert.equal(ok.stage(), 'deposited');
});

test('sendThrowLine: only the stages where nothing was delivered say NOT SENT; a throw AFTER a 2xx says DEPOSITED', () => {
  const fp = 'abcdef0123456789', e = new Error('boom');
  assert.match(sendThrowLine(fp, e, 'before-post'), /^NOT SENT to abcdef01: the send failed before reaching the relay \(boom\)$/);
  assert.match(sendThrowLine(fp, e, 'unreachable'), /^NOT SENT to abcdef01: the relay could not be reached \(boom\)$/);
  assert.match(sendThrowLine(fp, e, 'refused'), /^NOT SENT to abcdef01: the relay did not accept the deposit, and saving the local copy failed \(boom\)$/);
  const dep = sendThrowLine(fp, e, 'deposited');
  assert.match(dep, /^DEPOSITED to abcdef01, but saving the local copy failed \(boom\); do NOT resend$/);
  assert.doesNotMatch(dep, /NOT SENT/);
  assert.match(sendThrowLine(fp, e, 'unreachable', true), /; this ratchet index is spent$/);
  assert.doesNotMatch(sendThrowLine(fp, e, 'unreachable', false), /spent/);
});

test('CLI send: a throw BEFORE the POST (signing fails) is NOT blamed on the network', async () => {
  const peer = await mintHeadlessAgent({ throwaway: true });
  const { dir } = await senderDir([contactOf(peer)]);
  const mintPath = join(dir, 'mint.json');
  const m = JSON.parse(readFileSync(mintPath, 'utf8'));
  m.private.classical_kpass = 'not-the-passphrase';           // the key no longer unlocks: signNoteWire throws before any request
  writeFileSync(mintPath, JSON.stringify(m), { mode: 0o600 });
  try {
    await withRelay(async (relay, deposits) => {
      const r = await runCli(['send', idOf(peer).fingerprint, 'hello'], { SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: relay });
      assert.notEqual(r.code, 0);
      assert.match(r.err, /NOT SENT to [0-9a-f]{8}: the send failed before reaching the relay \(.+\)/);
      assert.doesNotMatch(r.err, /could not be reached/);
      assert.equal(deposits.length, 0);
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('CLI send: the relay ACCEPTS the note but saving the local copy then fails → DEPOSITED, never NOT SENT', async () => {
  const peer = await mintHeadlessAgent({ throwaway: true });
  const { dir } = await senderDir([contactOf(peer)]);
  const storePath = join(dir, 'store.json');
  const deposits: string[] = [];
  // the relay swaps store.json for a DIRECTORY before it answers 200, so the CLI's later atomic save fails
  const server = createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      deposits.push(req.url ?? '');
      rmSync(storePath, { force: true }); mkdirSync(storePath);
      res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{"ok":true}');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as { port: number }).port;
  try {
    const r = await runCli(['send', idOf(peer).fingerprint, 'hello'], { SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: `http://127.0.0.1:${port}/api/relay` });
    assert.equal(deposits.length, 1, 'the relay did receive the note');
    assert.notEqual(r.code, 0);
    assert.match(r.err, /^DEPOSITED to [0-9a-f]{8}, but saving the local copy failed \(.+\); do NOT resend$/m);
    assert.doesNotMatch(r.err, /NOT SENT/);
  } finally { await new Promise<void>((r) => server.close(() => r())); rmSync(dir, { recursive: true, force: true }); }
});
