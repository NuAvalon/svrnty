// src/lib/headless/intake-713-fallback.test.ts
// #713 over the local intake (Flint #189033): a LOSS terminal must NOT be reported as delivered. Intake has no envelope_id, so nothing
// records the loss; `intake` reports ok:false so the sender's router falls back to the relay, where the poll records it before acking.
// REAL CLI, offline (seal-note + intake touch no relay). Run: npx tsx --test src/lib/headless/intake-713-fallback.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function cli(dir: string, args: string[], stdin?: string): Promise<{ status: number | null; out: string; err: string }> {
  return new Promise((resolve) => {
    const p = spawn('npx', ['--no-install', 'tsx', 'scripts/devin-comm.ts', ...args], {
      cwd: join(__dirname, '../../..'),
      // A relay that can't be reached: these verbs must not need one.
      env: { ...process.env, SVRNTY_AGENT_DIR: dir, SVRNTY_RELAY: 'http://127.0.0.1:9/api/relay', NODE_OPTIONS: '--experimental-global-webcrypto' },
    });
    let out = ''; let err = '';
    p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d));
    if (stdin !== undefined) { p.stdin.write(stdin); }
    p.stdin.end();
    const timer = setTimeout(() => p.kill('SIGKILL'), 120_000);
    p.on('close', (status) => { clearTimeout(timer); resolve({ status, out, err }); });
  });
}
const lastJson = (s: string) => JSON.parse(s.trim().split('\n').filter((l) => l.startsWith('{')).pop()!);
function cardFile(dir: string, into: string): { path: string; fp: string } {
  const id = JSON.parse(readFileSync(join(dir, 'mint.json'), 'utf8')).public.card.identity;
  const path = join(into, `card-${id.fingerprint.slice(0, 8)}.json`);
  writeFileSync(path, JSON.stringify(id));
  return { path, fp: id.fingerprint };
}

test('#713 intake: a genuine note from a sender NOT in the book → ok:false + reason not-in-book (router falls back to the relay); admitted → ok:true', async () => {
  const work = mkdtempSync(join(tmpdir(), 'i713-'));
  const R = mkdtempSync(join(tmpdir(), 'i713-recv-'));
  const S = mkdtempSync(join(tmpdir(), 'i713-send-'));
  try {
    assert.equal((await cli(R, ['mint'])).status, 0);
    assert.equal((await cli(S, ['mint'])).status, 0);
    const rCard = cardFile(R, work);
    const sCard = cardFile(S, work);
    assert.equal((await cli(S, ['admit', rCard.path])).status, 0, 'the sender holds the receiver card');

    const sealed = await cli(S, ['seal-note', rCard.fp, 'hello over intake']);
    assert.equal(sealed.status, 0, sealed.err);
    const blob = lastJson(sealed.out).blob as string;
    assert.ok(blob && blob.length > 100);

    // R does NOT have S in its book → a loss terminal → must NOT be ok.
    const stranger = await cli(R, ['intake'], blob);
    assert.equal(stranger.status, 0, stranger.err);
    const v1 = lastJson(stranger.out);
    assert.deepEqual(v1, { ok: false, outcome: 'terminal', reason: 'not-in-book' });
    assert.equal(JSON.stringify(v1).includes(sCard.fp.slice(0, 8)), false, 'no fingerprint in the verdict');

    // Control: once R admits S, the same blob is a delivered note.
    assert.equal((await cli(R, ['admit', sCard.path])).status, 0);
    const admitted = await cli(R, ['intake'], blob);
    assert.deepEqual(lastJson(admitted.out), { ok: true, outcome: 'note' });
  } finally {
    for (const d of [work, R, S]) rmSync(d, { recursive: true, force: true });
  }
});

test('#713 intake NEG: garbage → ok:false (terminal, a loss reason), never ok:true', async () => {
  const R = mkdtempSync(join(tmpdir(), 'i713-g-'));
  try {
    assert.equal((await cli(R, ['mint'])).status, 0);
    const r = await cli(R, ['intake'], 'not a sealed blob at all');
    const v = lastJson(r.out);
    assert.equal(v.ok, false, JSON.stringify(v));
    assert.notEqual(v.outcome, 'note');
  } finally {
    rmSync(R, { recursive: true, force: true });
  }
});
