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
