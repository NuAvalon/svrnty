// Run: npx tsx --test src/lib/headless/join-cli-wiring.test.ts
// STATIC wiring contract (the CLI is not importable as a module): the `join` branch of scripts/devin-comm.ts must go through runJoin() and must not
// admit anyone itself. It FAILS on dev 374d31e, where the branch called store.upsertContact BEFORE the deposit and never passed the giver's KEM key.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, existsSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

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
  assert.match(branch, /admit: \(contact\) => store\.upsertContact\(contact\)/);
});

test('a refusal prints a line and exits NON-ZERO, and says nothing was admitted', () => {
  assert.match(branch, /if \(!out\.ok\) \{[\s\S]*?process\.exitCode = 1;[\s\S]*?return;/);
  assert.match(branch, /Nothing was admitted/);
});

test('the derive check is the real fingerprintMatchesKey and the backup is a dated, 0600 copy of the store', () => {
  assert.match(branch, /derives: \(fp, publicKey, pq\) => fingerprintMatchesKey\(fp, publicKey, pq\)/);
  assert.match(branch, /copyFileSync\(STORE, bak\);/);
  assert.match(branch, /chmodSync\(bak, 0o600\);/);
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

test('admit: a good card is written, read back, and exits 0', () => {
  const r = runAdmit({ fingerprint: FPX, public_key: '-----PUB-----', name: 'topos' });
  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /admitted /);
  assert.equal(r.contacts.length, 1);
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
