// src/lib/headless/giver-gate-hybrid-711.test.ts
// #711 (b): a CLI (headless) GIVER must see a joiner at its Gate. The joiner-response is sealed PQ-hybrid to the giver's KEM key (a CLI
// join passes giverPqKemPublicKey; the web app does the same). The giver's local joiner seam (scripts/devin-comm.ts buildLocalJoinerSeam)
// called verifyJoinerResponse WITHOUT a hybrid secrets source, so it could not open the response; it fell through the joiner seam and was
// consumed (acked) on a later path, and the Gate stayed empty. Live case 2026-10-31: Peter's web join to Athena's grow link never landed.
// REAL CLI end to end against an in-memory stub relay (no network). Fails on dev 00c0c17.
// Run: npx tsx --test src/lib/headless/giver-gate-hybrid-711.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

type Env = { envelope_id: string; mailbox_id: string; blob: string };
type Stub = { base: string; envelopes: Env[]; acked: string[]; close: () => Promise<void> };

async function startStubRelay(): Promise<Stub> {
  const held = new Map<string, string>();
  const envelopes: Env[] = [];
  const acked: string[] = [];
  let n = 0;
  const body = (req: IncomingMessage) => new Promise<string>((res) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => res(b)); });
  const send = (res: ServerResponse, code: number, obj: unknown) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
  const server = createServer(async (req, res) => {
    const url = req.url ?? '';
    if (req.method === 'POST' && url === '/api/relay') {
      const { encrypted } = JSON.parse(await body(req));
      const code = `STUB${String(++n).padStart(2, '0')}`;
      held.set(code, encrypted);
      return send(res, 200, { code, expiresAt: new Date(Date.now() + 7 * 864e5).toISOString() });
    }
    if (req.method === 'POST' && url === '/api/relay/envelope') {
      const { mailbox_id, blob } = JSON.parse(await body(req));
      envelopes.push({ envelope_id: `env${envelopes.length + 1}`, mailbox_id, blob });
      return send(res, 200, { ok: true });
    }
    if (req.method === 'GET' && url.startsWith('/api/relay/queue?')) {
      // Owner auth is not under test here; the stub returns the mailbox's envelopes.
      const mbx = new URL(url, 'http://x').searchParams.get('mailbox_id');
      return send(res, 200, envelopes.filter((e) => e.mailbox_id === mbx).map((e) => ({ envelope_id: e.envelope_id, blob: e.blob, expires_at: new Date(Date.now() + 864e5).toISOString() })));
    }
    if (req.method === 'POST' && url === '/api/relay/ack') {
      const { envelope_ids } = JSON.parse(await body(req)) as { envelope_ids: string[] };
      acked.push(...envelope_ids);
      for (const id of envelope_ids) { const i = envelopes.findIndex((e) => e.envelope_id === id); if (i >= 0) envelopes.splice(i, 1); }
      return send(res, 200, { deleted: envelope_ids.length });
    }
    const m = /^\/api\/relay\/([A-Za-z0-9_-]+)$/.exec(url);
    if (req.method === 'GET' && m && held.has(m[1])) return send(res, 200, { encrypted: held.get(m[1]) });
    return send(res, 404, { error: 'not found' });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as { port: number }).port;
  return { base: `http://127.0.0.1:${port}/api/relay`, envelopes, acked, close: () => new Promise((r) => server.close(() => r())) };
}

function cli(dir: string, base: string, args: string[]): Promise<{ status: number | null; out: string }> {
  return new Promise((resolve) => {
    const p = spawn('npx', ['--no-install', 'tsx', 'scripts/devin-comm.ts', ...args], {
      cwd: join(__dirname, '../../..'), env: { ...process.env, SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: base, NODE_OPTIONS: '--experimental-global-webcrypto' },
    });
    let out = ''; p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (out += d));
    const timer = setTimeout(() => p.kill('SIGKILL'), 120_000);
    p.on('close', (status) => { clearTimeout(timer); resolve({ status, out }); });
  });
}
const fpOf = (dir: string) => JSON.parse(readFileSync(join(dir, 'mint.json'), 'utf8')).public.card.identity.fingerprint as string;

test('#711 REAL CLI: giver mints a link, a CLI joiner joins (hybrid-sealed response), the giver\'s next poll puts the joiner AT THE GATE (not admitted)', async () => {
  const stub = await startStubRelay();
  const gdir = mkdtempSync(join(tmpdir(), 'g711-giver-'));
  const jdir = mkdtempSync(join(tmpdir(), 'g711-joiner-'));
  try {
    assert.equal((await cli(gdir, stub.base, ['mint'])).status, 0);
    const g = await cli(gdir, stub.base, ['grow', '1']);
    assert.equal(g.status, 0, g.out);
    const url = JSON.parse(g.out.trim().split('\n').pop()!).url as string;
    const giverFp = fpOf(gdir);
    assert.equal((await cli(jdir, stub.base, ['mint'])).status, 0);
    const joinerFp = fpOf(jdir);
    const j = await cli(jdir, stub.base, ['join', url, '--expect-fp', giverFp, '--name', 'giver']);
    assert.equal(j.status, 0, j.out);
    assert.equal(stub.envelopes.length, 1, 'the joiner-response was deposited');

    const p = await cli(gdir, stub.base, ['poll-json']);
    assert.equal(p.status, 0, p.out);
    const gate = await cli(gdir, stub.base, ['gate']);
    assert.equal(gate.status, 0, gate.out);
    assert.doesNotMatch(gate.out, /no one waiting at the Gate/, 'the joiner must be at the Gate: ' + gate.out.slice(-400));
    assert.match(gate.out, new RegExp(joinerFp.slice(0, 8), 'i'), 'the Gate line names the joiner');

    // At the Gate, NOT admitted: the giver's book does not contain the joiner until admit-gate.
    // A fresh giver may have no store.json yet (nothing admitted, nothing written): that is an empty book.
    const storePath = join(gdir, 'store.json');
    const store = (existsSync(storePath) ? JSON.parse(readFileSync(storePath, 'utf8')) : { contacts: [] }) as { contacts: Array<{ fingerprint: string }> };
    assert.equal(store.contacts.some((c) => c.fingerprint.toLowerCase() === joinerFp.toLowerCase()), false, 'Gate, never auto-admit');
    const codes = JSON.parse(readFileSync(join(gdir, 'issued-codes.json'), 'utf8'));
    const accepted = Object.values(codes[giverFp] as Record<string, { accepted: string[] }>).flatMap((e) => e.accepted);
    assert.ok(accepted.some((fp) => fp.toLowerCase() === joinerFp.toLowerCase()), 'the issued code records the joiner (once per joiner)');
  } finally {
    await stub.close();
    for (const d of [gdir, jdir]) rmSync(d, { recursive: true, force: true });
  }
});
