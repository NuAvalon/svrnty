// Run: npx tsx --test src/lib/headless/join-cli-wiring.test.ts
// STATIC wiring contract (the CLI is not importable as a module): the `join` branch of scripts/devin-comm.ts must go through runJoin() and must not
// admit anyone itself. It FAILS on dev 374d31e, where the branch called store.upsertContact BEFORE the deposit and never passed the giver's KEM key.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
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
