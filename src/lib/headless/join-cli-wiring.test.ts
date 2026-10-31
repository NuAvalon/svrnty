// Run: npx tsx --test src/lib/headless/join-cli-wiring.test.ts
// STATIC wiring contract (the CLI is not importable as a module): the `join` branch of scripts/devin-comm.ts must go through runJoin() and must not
// admit anyone itself. It FAILS on dev 374d31e, where the branch called store.upsertContact BEFORE the deposit and never passed the giver's KEM key.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, existsSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readdirSync, statSync, symlinkSync, chmodSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { spawn } from 'node:child_process';

const src = readFileSync(join(__dirname, '../../../scripts/devin-comm.ts'), 'utf8');
const a = src.indexOf("if (cmd === 'join') {");
const b = src.indexOf("if (cmd === 'gate') {");
const branch = src.slice(a, b);

test('the join branch exists and is bounded by the gate branch', () => {
  assert.ok(a > 0 && b > a);
});

test('join goes through runJoin(parseJoinFlags(rest), ...) and admits ONLY via the injected admit callback (after the deposit)', () => {
  assert.match(branch, /await runJoin\(parseJoinFlags\(rest\),/);
  assert.equal((branch.match(/store\.upsertContact\(/g) ?? []).length, 1, 'exactly one upsert, inside the admit callback');
  // #724: the callback writes through withAdmitLog (provenance line before the write), still the branch's only upsert.
  assert.match(branch, /admit: \(contact\) => withAdmitLog\(\s*DIR,\s*\{ source: 'join',[^\n]*\},\s*\(\) => store\.upsertContact\(contact\),\s*\),/);
});

test('a refusal prints a line and exits NON-ZERO, and says nothing was admitted', () => {
  assert.match(branch, /if \(!out\.ok\) \{[\s\S]*?process\.exitCode = 1;[\s\S]*?return;/);
  assert.match(branch, /Nothing was admitted/);
});

test('the derive check is the real fingerprintMatchesKey and the J5 backup goes through backupStoreBeforeJoin(STORE) (the dated 0600 copy lives in join-backup.ts, unit-tested there)', () => {
  assert.match(branch, /derives: \(fp, publicKey, pq\) => fingerprintMatchesKey\(fp, publicKey, pq\)/);
  assert.match(branch, /backup: \(\) => \{ backupStoreBeforeJoin\(STORE\); \}/);
  assert.doesNotMatch(branch, /copyFileSync/, 'the CLI must not carry its own copy of the backup logic');
  const mod = readFileSync(join(__dirname, 'join-backup.ts'), 'utf8');
  assert.match(mod, /copyFileSync\(storePath, path\);/);
  assert.match(mod, /chmodSync\(path, 0o600\);/);
});

test('the deposit target is passed through untouched (it carries giverPqKemPublicKey; runJoin builds it)', () => {
  assert.match(branch, /target,\s*\{ relayBase: RELAY \}/);
  assert.doesNotMatch(branch, /inviteNonce: code/, 'the old inline target (no KEM key) is gone');
});

test('LIVENESS (Flint #1304): admit-failed-after-deposit has its OWN branch, BEFORE the generic refusal, that is loud, non-zero, saves a 0600 card and prints a command that exists', () => {
  const i = branch.indexOf("out.refusal === 'admit-failed-after-deposit'");
  const j = branch.indexOf('if (!out.ok) {');
  assert.ok(i > 0 && j > i, 'the specific branch must come before the generic one');
  const spec = branch.slice(i, j);
  assert.match(spec, /joiner-response DEPOSITED, but admitting/);
  assert.doesNotMatch(spec, /Nothing was admitted/, 'false in this case: the response went out');
  assert.match(spec, /process\.exitCode = 1;[\s\S]*?return;/);
  assert.match(spec, /mode: 0o600/);
  assert.match(spec, /chmodSync\(pend, 0o600\)/);
  assert.match(spec, /devin-comm\.ts admit \$\{pend\}/, 'the printed command is the real `admit <card.json>`, which has no --name flag');
  assert.match(spec, /Do NOT re-run join/);
});

test('the saved pending card carries public material only (no private key, passphrase or seed)', () => {
  const i = branch.indexOf("out.refusal === 'admit-failed-after-deposit'");
  const spec = branch.slice(i, branch.indexOf('if (!out.ok) {'));
  assert.doesNotMatch(spec, /privateKey|passphrase|seed/i);
});

// BEHAVIOURAL (Archie #1310 "never exit 0 when nothing was written"): run the REAL `admit` against a throwaway agent dir. `admit` runs before the mint check, so no identity is needed.
function runAdmit(card: unknown): { status: number | null; out: string; contacts: unknown[] } {
  const dir = mkdtempSync(join(tmpdir(), 'devin-admit-'));
  try {
    const cardPath = join(dir, 'card.json');
    writeFileSync(cardPath, JSON.stringify(card));
    const r = spawnSync('npx', ['--no-install', 'tsx', 'scripts/devin-comm.ts', 'admit', cardPath], {
      cwd: join(__dirname, '../../..'), env: { ...process.env, SVRNTY_AGENT_DIR: dir }, encoding: 'utf8', timeout: 90_000,
    });
    const storePath = join(dir, 'store.json');
    const contacts = existsSync(storePath) ? (JSON.parse(readFileSync(storePath, 'utf8')).contacts ?? []) : [];
    return { status: r.status, out: `${r.stdout}${r.stderr}`, contacts };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
const FPX = 'ab'.repeat(32);

test('admit: a good card is written, read back, and exits 0', async () => {
  // #724: a "good" card is one whose keys hash to its fingerprint (Invariant-1), so this mints a real canonical identity.
  const { generateKey, readPrivateKey, decryptKey } = await import('openpgp');
  const { generatePQKeypairBundle, uint8ToBase64 } = await import('../crypto/pq');
  const { mintCanonicalFingerprint } = await import('../identity/fingerprint');
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime.
    curve: 'ed25519', userIDs: [{ name: 'topos', email: 'topos@x.test' }], passphrase: 'pw-topos', format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase: 'pw-topos' });
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  const r = runAdmit({ fingerprint, public_key: publicKey, pq_kem_public_key: uint8ToBase64(pq.kem.publicKey), pq_sig_public_key: uint8ToBase64(pq.signing.publicKey), name: 'topos' });
  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /admitted /);
  assert.equal(r.contacts.length, 1);
});

test('admit: a card whose keys do not hash to its fingerprint exits 1 and stores nothing (#724)', () => {
  const r = runAdmit({ fingerprint: FPX, public_key: '-----PUB-----', name: 'topos' });
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /keys do not hash to its fingerprint/);
  assert.equal(r.contacts.length, 0);
});

test('admit: a card with NO public_key exits 1, says nothing was written, and stores NOTHING (it used to print "admitted" and exit 0)', () => {
  const r = runAdmit({ fingerprint: FPX, name: 'topos' });
  assert.equal(r.status, 1, r.out);
  assert.match(r.out, /Nothing was written/);
  assert.doesNotMatch(r.out, /admitted /);
  assert.equal(r.contacts.length, 0);
});

test('admit: a card with NO fingerprint and NO durable_id exits 1 and stores nothing', () => {
  const r = runAdmit({ public_key: '-----PUB-----', name: 'x' });
  assert.equal(r.status, 1, r.out);
  assert.equal(r.contacts.length, 0);
});

// ── BEHAVIOURAL join through the REAL CLI against an in-memory stub relay (no network) ─────────────────────────────────────
// Found by the LIVE-RELAY run: a freshly minted agent has no store.json yet, and `join` used to refuse with backup-failed (ENOENT)
// because J5 tried to copy a file that does not exist. Flint #1444 conditions: skip the backup ONLY on lstat ENOENT; a symlink or any other
// error still refuses; the test goes all the way to exit 0 with a 200 deposit and a 0600 store.
type Stub = { base: string; envelopes: Array<{ mailbox_id: string; blob: string }>; close: () => Promise<void> };
async function startStubRelay(): Promise<Stub> {
  const held = new Map<string, string>();
  const envelopes: Stub['envelopes'] = [];
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
      envelopes.push(JSON.parse(await body(req)));
      return send(res, 200, { ok: true });
    }
    const m = /^\/api\/relay\/([A-Za-z0-9_-]+)$/.exec(url);
    if (req.method === 'GET' && m && held.has(m[1])) return send(res, 200, { encrypted: held.get(m[1]) });
    return send(res, 404, { error: 'not found' });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as { port: number }).port;
  return { base: `http://127.0.0.1:${port}/api/relay`, envelopes, close: () => new Promise((r) => server.close(() => r())) };
}
function runCliAsync(dir: string, base: string, args: string[]): Promise<{ status: number | null; out: string }> {
  return new Promise((resolve) => {
    const p = spawn('npx', ['--no-install', 'tsx', 'scripts/devin-comm.ts', ...args], {
      cwd: join(__dirname, '../../..'), env: { ...process.env, SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: base },
    });
    let out = ''; p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (out += d));
    const timer = setTimeout(() => p.kill('SIGKILL'), 120_000);
    p.on('close', (status) => { clearTimeout(timer); resolve({ status, out }); });
  });
}
async function mintedGiverLink(stub: Stub): Promise<{ url: string; fp: string; dirs: string[] }> {
  const gdir = mkdtempSync(join(tmpdir(), 'devin-giver-'));
  assert.equal((await runCliAsync(gdir, stub.base, ['mint'])).status, 0);
  const g = await runCliAsync(gdir, stub.base, ['grow', '1']);
  assert.equal(g.status, 0, g.out);
  const url = JSON.parse(g.out.trim().split('\n').pop()!).url as string;
  const fp = JSON.parse(readFileSync(join(gdir, 'mint.json'), 'utf8')).public.card.identity.fingerprint as string;
  return { url, fp, dirs: [gdir] };
}
const modeOf = (p: string) => (statSync(p).mode & 0o777).toString(8);

test('REAL CLI, FRESH agent (minted, no store.json): join goes all the way: exit 0, deposit 200, giver admitted as known, store created 0600, no backup of a store that was never there', async () => {
  const stub = await startStubRelay(); const made: string[] = [];
  try {
    const giver = await mintedGiverLink(stub); made.push(...giver.dirs);
    const jdir = mkdtempSync(join(tmpdir(), 'devin-join-fresh-')); made.push(jdir);
    assert.equal((await runCliAsync(jdir, stub.base, ['mint'])).status, 0);
    assert.equal(existsSync(join(jdir, 'store.json')), false, 'precondition: no store yet');
    const r = await runCliAsync(jdir, stub.base, ['join', giver.url, '--expect-fp', giver.fp, '--name', 'giver']);
    assert.equal(r.status, 0, r.out);
    const res = JSON.parse(r.out.trim().split('\n').pop()!);
    assert.equal(res.admitted, giver.fp);
    assert.equal(res.joinerResponse.status, 200);
    assert.equal(stub.envelopes.length, 1, 'exactly one deposit reached the relay');
    const store = JSON.parse(readFileSync(join(jdir, 'store.json'), 'utf8'));
    assert.equal(store.contacts.length, 1);
    assert.equal(store.contacts[0].trust_level, 'known');
    assert.equal(modeOf(join(jdir, 'store.json')), '600');
    assert.deepEqual(readdirSync(jdir).filter((f) => /^store\.json\.bak-/.test(f)), []);
  } finally { await stub.close(); for (const d of made) rmSync(d, { recursive: true, force: true }); }
});

test('REAL CLI, agent WITH a store: the J5 backup is still taken first (the fresh-agent skip must not weaken it)', async () => {
  const stub = await startStubRelay(); const made: string[] = [];
  try {
    const giver = await mintedGiverLink(stub); made.push(...giver.dirs);
    const jdir = mkdtempSync(join(tmpdir(), 'devin-join-store-')); made.push(jdir);
    assert.equal((await runCliAsync(jdir, stub.base, ['mint'])).status, 0);
    writeFileSync(join(jdir, 'store.json'), JSON.stringify({ contacts: [], notes: [], threads: [] }), { mode: 0o600 });
    const r = await runCliAsync(jdir, stub.base, ['join', giver.url, '--expect-fp', giver.fp, '--name', 'giver']);
    assert.equal(r.status, 0, r.out);
    // the J5 backup is the DATED one; the atomic writer also leaves a plain store.json.bak when it overwrites
    const baks = readdirSync(jdir).filter((f) => /^store\.json\.bak-\d{8}T\d{6}Z$/.test(f));
    assert.equal(baks.length, 1, `exactly one dated J5 backup expected, got ${readdirSync(jdir)}`);
    assert.equal(modeOf(join(jdir, baks[0])), '600');
  } finally { await stub.close(); for (const d of made) rmSync(d, { recursive: true, force: true }); }
});

test('REAL CLI: a store path that is a SYMLINK is refused (dangling or not), nothing is deposited, and nothing is written through the link', async () => {
  const stub = await startStubRelay(); const made: string[] = [];
  try {
    const giver = await mintedGiverLink(stub); made.push(...giver.dirs);
    for (const kind of ['dangling', 'to-a-real-file'] as const) {
      const jdir = mkdtempSync(join(tmpdir(), `devin-join-link-${kind}-`)); made.push(jdir);
      assert.equal((await runCliAsync(jdir, stub.base, ['mint'])).status, 0);
      const outside = join(jdir, 'elsewhere.json');
      if (kind === 'to-a-real-file') writeFileSync(outside, '{"contacts":[],"notes":[],"threads":[]}');
      symlinkSync(outside, join(jdir, 'store.json'));
      const before = stub.envelopes.length;
      const r = await runCliAsync(jdir, stub.base, ['join', giver.url, '--expect-fp', giver.fp, '--name', 'giver']);
      assert.equal(r.status, 1, `${kind}: ${r.out}`);
      assert.match(r.out, /backup-failed/, kind);
      assert.match(r.out, /symlink/, kind);
      assert.match(r.out, /Nothing was admitted/, kind);
      assert.equal(stub.envelopes.length, before, `${kind}: no deposit may be sent`);
      if (kind === 'dangling') assert.equal(existsSync(outside), false, 'nothing was written through the dangling link');
      else assert.equal(readFileSync(outside, 'utf8'), '{"contacts":[],"notes":[],"threads":[]}', 'the link target is untouched');
    }
  } finally { await stub.close(); for (const d of made) rmSync(d, { recursive: true, force: true }); }
});

test('REAL CLI: a store that EXISTS but cannot be read is refused (by the store load, earlier than J5; J5\'s own rule is unit-tested in join-backup.test.ts); nothing deposited', async (t) => {
  if (typeof process.getuid === 'function' && process.getuid() === 0) { t.skip('root can read mode-000 files'); return; }
  const stub = await startStubRelay(); const made: string[] = [];
  try {
    const giver = await mintedGiverLink(stub); made.push(...giver.dirs);
    const jdir = mkdtempSync(join(tmpdir(), 'devin-join-unreadable-')); made.push(jdir);
    assert.equal((await runCliAsync(jdir, stub.base, ['mint'])).status, 0);
    writeFileSync(join(jdir, 'store.json'), '{"contacts":[],"notes":[],"threads":[]}', { mode: 0o600 });
    chmodSync(join(jdir, 'store.json'), 0o000);
    const r = await runCliAsync(jdir, stub.base, ['join', giver.url, '--expect-fp', giver.fp, '--name', 'giver']);
    chmodSync(join(jdir, 'store.json'), 0o600);
    assert.equal(r.status, 1, r.out);
    assert.match(r.out, /EACCES|backup-failed/);
    assert.equal(stub.envelopes.length, 0, 'no deposit when the store cannot be read');
  } finally { await stub.close(); for (const d of made) rmSync(d, { recursive: true, force: true }); }
});
