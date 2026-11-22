/**
 * scripts/devin-know.ts is thin wiring around know-cli.ts. The rules are tested there; this pins what only the wiring can get
 * wrong, as a source check (the script runs main() on import):
 *   - the guards run BEFORE anything is read, written or sent, in order: argv, then the env-only directory, then the seat home;
 *   - no second way to name a seat directory, no shared-sandbox fallback, no path to the target-taking tick core;
 *   - minting is create-only into a NEW directory and always a throwaway;
 *   - the script deletes nothing local;
 *   - everything printed goes through one helper (8-hex prefixes and counts).
 * Run: npx tsx --test src/lib/headless/devin-know-wiring.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const code = (src: string) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
const SRC = code(readFileSync(join(process.cwd(), 'scripts/devin-know.ts'), 'utf8'));
const MAIN = SRC.slice(SRC.indexOf('async function main()'));
const MINT = SRC.slice(SRC.indexOf('async function mintThrowaway'), SRC.indexOf('async function main()'));
const at = (s: string, needle: string): number => s.indexOf(needle);

test('main: argv is checked, then the directory comes from the environment, then the seat home is verified, in that order', () => {
  const a = at(MAIN, 'refuseDirInArgv('), b = at(MAIN, 'agentHomeFromEnv('), c = at(MAIN, 'assertSeatHome(');
  assert.ok(a >= 0 && b > a && c > b, `order argv=${a} env=${b} home=${c}`);
});

test('main: nothing reads a store, signs, binds or sends before assertSeatHome has passed', () => {
  const guard = at(MAIN, 'assertSeatHome(');
  assert.ok(guard > 0);
  for (const act of ['new HeadlessStore(', 'knowOn(', 'runHeadlessKnowTick(', 'headlessPsiOptions(', 'buildKnowReport(', 'readFileSync(']) {
    const i = at(MAIN, act);
    if (act === 'readFileSync(') { assert.ok(i >= 0 && i < guard, 'the artifact is parsed, then verified'); continue; }
    assert.ok(i > guard, `${act} appears at ${i}, before the guard at ${guard}`);
  }
});

test('main: the mint-throwaway branch returns before the guarded commands (it has no seat to verify yet)', () => {
  assert.ok(at(MAIN, "cmd === 'mint-throwaway'") > 0 && at(MAIN, "cmd === 'mint-throwaway'") < at(MAIN, 'assertSeatHome('));
  assert.match(MAIN, /cmd === 'mint-throwaway'\)\s*return mintThrowaway\(dir\)/);
});

test('the seat directory has one source: no direct env read, no fallback path, one argv read', () => {
  assert.doesNotMatch(SRC, /process\.env\.SVRNTY_AGENT_DIR/);
  assert.doesNotMatch(SRC, /devin-sandbox|\.svrnty-agent|\$HOME|homedir\(/);
  assert.equal((SRC.match(/process\.argv/g) ?? []).length, 1, 'argv is read once, for the command and its arguments');
});

test('the target-taking tick core is not reachable from the script', () => {
  assert.doesNotMatch(SRC, /\btickCore\b/);
  assert.match(SRC, /\brunHeadlessKnowTick\b/);
});

test('minting refuses an existing directory BEFORE creating anything, is create-only, and is always a throwaway', () => {
  assert.ok(at(MINT, 'existsSync(dir)') >= 0 && at(MINT, 'existsSync(dir)') < at(MINT, 'mkdirSync('));
  assert.match(MINT, /flag:\s*'wx'/);
  assert.match(MINT, /throwaway:\s*true/);
  assert.doesNotMatch(SRC, /throwaway:\s*false/);
  assert.ok(at(MINT, 'assertSeatHome(') > at(MINT, 'writeFileSync('), 'the new seat is verified after it is written');
});

test('the script deletes nothing local', () => {
  assert.doesNotMatch(SRC, /\b(unlinkSync|rmSync|rmdirSync|unlink|rmdir)\b|fs\.rm\b/);
});

test('everything printed goes through the one out() helper', () => {
  assert.equal((SRC.match(/console\.log\(/g) ?? []).length, 1);
  assert.match(SRC, /const out = \(o: unknown\): void => console\.log\(JSON\.stringify\(o\)\)/);
});

test('know-tick publishes counts only (no values from the tick result)', () => {
  assert.match(SRC, /function countsOf[\s\S]*?Array\.isArray\(v\)\) o\[k\] = v\.length/);
  assert.match(MAIN, /tick:\s*countsOf\(await runHeadlessKnowTick\(/, 'the tick result is printed only through countsOf');
  assert.doesNotMatch(MAIN, /JSON\.stringify\((result|r)\b/);
});
