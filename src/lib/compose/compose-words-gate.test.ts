// Run: npx tsx --test src/lib/compose/compose-words-gate.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { composeWordsConfirmed } from './compose-words-gate';

const ROOT = join(__dirname, '../../..');

test('the check-words switch is OFF by default and ON only for the exact string "1" (nothing truthy-ish turns it on)', () => {
  assert.equal(composeWordsConfirmed({}), false);
  for (const v of [undefined, '', '0', 'true', 'TRUE', 'yes', ' 1', '1 ', '01', 'on']) assert.equal(composeWordsConfirmed({ NEXT_PUBLIC_COMPOSE_WORDS_CONFIRMED: v }), false, JSON.stringify(v));
  assert.equal(composeWordsConfirmed({ NEXT_PUBLIC_COMPOSE_WORDS_CONFIRMED: '1' }), true);
  assert.equal(composeWordsConfirmed({ COMPOSE_WORDS_CONFIRMED: '1' }), false, 'only the NEXT_PUBLIC_ name counts');
});

test('the BUILT-IN value (what a browser bundle reads): unset -> false, "1" -> true, "true" -> false. Run in a child so the module reads a real process.env at load', () => {
  const probe = `import('${join(__dirname, 'compose-words-gate').replace(/\\/g, '/')}').then((m) => console.log('RESULT=' + m.composeWordsConfirmed()));`;
  const run = (v: string | undefined) => {
    const env: NodeJS.ProcessEnv = { ...process.env };
    delete env.NEXT_PUBLIC_COMPOSE_WORDS_CONFIRMED;
    if (v !== undefined) env.NEXT_PUBLIC_COMPOSE_WORDS_CONFIRMED = v;
    const r = spawnSync('npx', ['--no-install', 'tsx', '-e', probe], { cwd: ROOT, env, encoding: 'utf8', timeout: 60_000 });
    return /RESULT=(true|false)/.exec(`${r.stdout}${r.stderr}`)?.[1];
  };
  assert.equal(run(undefined), 'false');
  assert.equal(run('1'), 'true');
  assert.equal(run('true'), 'false');
});

test('Next can inline it: the source holds the LITERAL `process.env.NEXT_PUBLIC_COMPOSE_WORDS_CONFIRMED` once, and no default-parameter `= process.env` read (Flint #1478)', () => {
  const src = readFileSync(join(__dirname, 'compose-words-gate.ts'), 'utf8').replace(/\/\/.*$/gm, '');
  assert.equal((src.match(/process\.env\.NEXT_PUBLIC_COMPOSE_WORDS_CONFIRMED/g) ?? []).length, 1);
  assert.doesNotMatch(src, /=\s*process\.env\b(?!\.)/, 'a process.env OBJECT read is empty in a browser bundle');
  assert.doesNotMatch(src, /\bprocess\.env\s*\[/);
});

test('GUARD (Flint #1478 (2)): no deploy file mentions COMPOSE_WORDS_CONFIRMED. The day it is flipped for real this test changes in the SAME PR, named and reviewed', () => {
  const files = [
    'Dockerfile', 'docker-compose.yml', 'infra/svrnty/Dockerfile', 'infra/svrnty/Dockerfile.registration', 'next.config.ts', '.env.example',
    'scripts/pre-deploy-audit.sh',
    ...readdirSync(join(ROOT, '.github/workflows')).map((f) => `.github/workflows/${f}`),
  ].filter((f) => existsSync(join(ROOT, f)));
  assert.ok(files.length >= 8, 'the guard must actually be reading the deploy files: ' + files.join(','));
  for (const f of files) assert.doesNotMatch(readFileSync(join(ROOT, f), 'utf8'), /COMPOSE_WORDS_CONFIRMED/, `${f} must not set or mention the check-words switch`);
  // the ONE place that may set it: the e2e server's own config
  assert.match(readFileSync(join(ROOT, 'playwright.config.ts'), 'utf8'), /NEXT_PUBLIC_COMPOSE_WORDS_CONFIRMED/);
  // control: the pattern is not dead
  assert.match('ENV NEXT_PUBLIC_COMPOSE_WORDS_CONFIRMED=1', /COMPOSE_WORDS_CONFIRMED/);
});
