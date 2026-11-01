// scripts/sensitive-paths.test.ts — pins the S42 sensitive-paths patterns (Flint lane:svrnty #217):
// every CODEOWNERS path is covered, the extras match real tracked files, an empty CODEOWNERS fails closed,
// and a non-sensitive file is not matched. Run: npx --no-install tsx --test scripts/sensitive-paths.test.ts
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SCRIPT = join(__dirname, 'sensitive-paths.sh');
const ROOT = join(__dirname, '..');
const run = (...args: string[]) => spawnSync('bash', [SCRIPT, ...args], { cwd: ROOT, encoding: 'utf8' });
const isSensitive = (p: string, owners = 'CODEOWNERS') => run('match', p, owners).status === 0;
const EXPECTED_EXTRAS = ['src/lib/headless/*', 'app/api/*', 'middleware.ts', 'package.json', 'package-lock.json'];

// The CODEOWNERS entries, parsed here independently of the script (leading "/" stripped, dirs get a synthetic file).
const ownerPaths = readFileSync(join(ROOT, 'CODEOWNERS'), 'utf8').split('\n')
  .map((l) => l.trim().split(/\s+/)[0] ?? '')
  .filter((p) => p && !p.startsWith('#'))
  .map((p) => p.replace(/^\//, ''));

describe('sensitive-paths patterns = CODEOWNERS + extras (Flint #217)', () => {
  it('every CODEOWNERS path is matched (a dir via a synthetic file under it)', () => {
    assert.ok(ownerPaths.length >= 10, `parsed ${ownerPaths.length} CODEOWNERS paths`);
    for (const p of ownerPaths) {
      const probe = p.endsWith('/') ? `${p}x.ts` : p;
      assert.ok(isSensitive(probe), `CODEOWNERS path not covered: ${p} (probe ${probe})`);
    }
    for (const nested of ['src/lib/relay/deep/inner.ts', 'scripts/anything.ts', '.github/workflows/qa.yml']) {
      assert.ok(isSensitive(nested), nested);
    }
  });

  it('the extras are exactly the agreed set and each matches a real tracked file', () => {
    assert.deepEqual(run('extras').stdout.trim().split('\n'), EXPECTED_EXTRAS);
    const tracked = execFileSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8' }).split('\n');
    for (const extra of EXPECTED_EXTRAS) {
      const rx = new RegExp(`^${extra.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`);
      assert.ok(tracked.some((f) => rx.test(f)), `extra ${extra} matches no tracked file (renamed? then it is dead)`);
    }
  });

  it('fails closed: a CODEOWNERS with no parsable path exits non-zero', () => {
    const dir = mkdtempSync(join(tmpdir(), 'codeowners-'));
    const empty = join(dir, 'CODEOWNERS');
    writeFileSync(empty, '# only comments\n\n   \n# @someone\n');
    assert.notEqual(run('patterns', empty).status, 0);
    assert.equal(isSensitive('package.json', empty), false, 'nothing is "matched" from an unparsable file');
  });

  it('a non-sensitive file is not matched', () => {
    for (const plain of ['src/components/notes/notes-status.ts', 'src/lib/contacts/other.ts', 'README.md']) {
      assert.equal(isSensitive(plain), false, plain);
    }
  });

  it('qa.yml builds its patterns from this script (one source of truth)', () => {
    const wf = readFileSync(join(ROOT, '.github/workflows/qa.yml'), 'utf8');
    assert.match(wf, /scripts\/sensitive-paths\.sh patterns CODEOWNERS/);
    assert.doesNotMatch(wf, /PATTERNS=\('scripts\/\*sign\*'/, 'the old hand-written list is gone');
  });
});

// The pull_request base = the merge ref's FIRST parent (the base tip the run is built on), never pull_request.base.sha, which
// stays at the base from when the PR opened (#337: dev's #326/#338 files were flagged on a notes-only PR). These tests run
// the EXACT lines CI runs: the `>>> merge-ref base` block cut out of qa.yml. Fixture = GitHub's shape: dev moves on with a
// sensitive change AFTER the PR branched off, and the merge ref is `merge --no-ff` of the PR head onto that newer dev tip.
describe('qa.yml merge-ref base: not a stale pull_request.base.sha, and not chosen by PR code', () => {
  const wf = readFileSync(join(ROOT, '.github/workflows/qa.yml'), 'utf8');
  const m = wf.match(/\n([ \t]*)# >>> merge-ref base[^\n]*\n([\s\S]*?)\n[ \t]*# <<< merge-ref base/);
  const block = m ? m[2].split('\n').map((l) => l.slice(m[1].length)).join('\n') : '';
  const env = { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t',
    GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' };
  const g = (cwd: string, ...a: string[]) => execFileSync('git', a, { cwd, encoding: 'utf8', env }).trim();
  const resolve = (cwd: string, prHead: string) =>
    spawnSync('bash', ['-c', `set -euo pipefail\n${block}\necho "$BASE"`], { cwd, encoding: 'utf8', env: { ...env, PR_HEAD_SHA: prHead } });
  const changed = (cwd: string, base: string) => g(cwd, 'diff', '--name-only', '--no-renames', base, 'HEAD').split('\n').filter(Boolean);
  const put = (repo: string, f: string, body: string) => { execFileSync('mkdir', ['-p', join(repo, f, '..')]); writeFileSync(join(repo, f), body); };
  const commit = (repo: string, msg: string) => { g(repo, 'add', '-A'); g(repo, 'commit', '-q', '-m', msg); return g(repo, 'rev-parse', 'HEAD'); };

  const repo = mkdtempSync(join(tmpdir(), 'mrbase-'));
  g(repo, 'init', '-q', '-b', 'dev');
  put(repo, 'README.md', 'a\n');
  put(repo, 'scripts/sensitive-paths.sh', '#!/bin/bash\necho real\n');
  const opened = commit(repo, 'base when the PR opened');           // = the stale pull_request.base.sha
  g(repo, 'checkout', '-q', '-b', 'pr');
  put(repo, 'src/components/notes/notes-copy.ts', 'x\n');
  const prHead = commit(repo, 'the PR: notes only');
  g(repo, 'checkout', '-q', 'dev');
  put(repo, 'src/lib/relay/mailbox-store.ts', 'y\n');
  const devTip = commit(repo, 'dev moves on: a sensitive change, reviewed in its own PR');
  g(repo, 'checkout', '-q', '-b', 'merge-ref');
  g(repo, 'merge', '-q', '--no-ff', '-m', 'merge ref', 'pr');

  it('the block exists in qa.yml and the step reads PR_HEAD_SHA, never pull_request.base.sha', () => {
    assert.ok(block.includes('git cat-file commit HEAD'), 'merge-ref base block not found in qa.yml');
    assert.doesNotMatch(block, /sensitive-paths\.sh/, 'no PR-modifiable script picks the base');
    assert.match(wf, /PR_HEAD_SHA: \$\{\{ github\.event\.pull_request\.head\.sha \}\}/);
    assert.doesNotMatch(wf, /\$\{\{\s*github\.event\.pull_request\.base\.sha\s*\}\}/, 'no step reads the stale base sha');
  });

  it('the bug it fixes: diffing the stale base flags the base branch\'s own sensitive change', () => {
    assert.ok(changed(repo, opened).includes('src/lib/relay/mailbox-store.ts'));
    assert.ok(isSensitive('src/lib/relay/mailbox-store.ts'), 'the fixture path is sensitive under the real CODEOWNERS');
  });

  it('BASE = the merge ref\'s first parent; its diff is only the PR\'s own file', () => {
    const r = resolve(repo, prHead);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.equal(r.stdout.trim(), devTip);
    assert.deepEqual(changed(repo, devTip), ['src/components/notes/notes-copy.ts']);
  });

  it('works in a depth-1 clone (CI\'s checkout), where rev-list --parents shows no parents', () => {
    const shallow = mkdtempSync(join(tmpdir(), 'mrbase-shallow-'));
    g(shallow, 'clone', '-q', '--depth=1', '--branch', 'merge-ref', `file://${repo}`, '.');
    assert.equal(g(shallow, 'rev-list', '--parents', '-n1', 'HEAD').split(' ').length, 1, 'the shallow boundary hides parents');
    const r = resolve(shallow, prHead);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.equal(r.stdout.trim(), devTip);
  });

  it('NEG (Flint #3013): a PR that rewrites sensitive-paths.sh to print HEAD as the base is still flagged', () => {
    const evil = mkdtempSync(join(tmpdir(), 'mrbase-evil-'));
    g(evil, 'clone', '-q', `file://${repo}`, '.');
    g(evil, 'checkout', '-q', '-b', 'pr2', opened);
    put(evil, 'scripts/sensitive-paths.sh', '#!/bin/bash\n[ "$1" = pr-base ] && git rev-parse HEAD && exit 0\nexit 0\n');
    put(evil, 'src/lib/relay/mailbox-store.ts', 'evil\n');
    const evilHead = commit(evil, 'a PR that tries to choose its own base');
    g(evil, 'checkout', '-q', '-B', 'mr2', `origin/dev`);
    g(evil, 'merge', '-q', '--no-ff', '-m', 'merge ref', 'pr2', '-X', 'theirs');
    const r = resolve(evil, evilHead);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.equal(r.stdout.trim(), devTip, 'BASE is the base tip, not whatever the PR\'s script says');
    const hits = changed(evil, r.stdout.trim());
    assert.ok(hits.includes('scripts/sensitive-paths.sh') && isSensitive('scripts/sensitive-paths.sh'), 'the script edit itself is flagged');
    assert.ok(hits.includes('src/lib/relay/mailbox-store.ts'), 'the sensitive change is flagged');
  });

  it('fails closed: wrong PR head, a non-merge HEAD, a "parent" line in a commit MESSAGE, malformed shas', () => {
    assert.notEqual(resolve(repo, devTip).status, 0, '2nd parent is not the PR head');
    const solo = mkdtempSync(join(tmpdir(), 'mrbase-solo-'));
    g(solo, 'clone', '-q', '--branch', 'pr', `file://${repo}`, '.');
    assert.notEqual(resolve(solo, prHead).status, 0, 'HEAD is not a merge commit');
    put(solo, 'README.md', 'b\n');
    g(solo, 'add', '-A');
    g(solo, 'commit', '-q', '-m', 'one parent', '-m', `parent ${prHead}`);
    assert.notEqual(resolve(solo, prHead).status, 0, 'a message line "parent <sha>" must not count as a parent');
    for (const bad of ['', 'abc', prHead.slice(0, 12), prHead.toUpperCase()]) assert.notEqual(resolve(repo, bad).status, 0, `malformed: "${bad}"`);
  });
});
