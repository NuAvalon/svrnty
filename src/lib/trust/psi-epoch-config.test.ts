// Where the epoch switches are read from. Run: npx tsx --test src/lib/trust/psi-epoch-config.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { readPsiEpochFlags } from './psi-epoch-config';

test('everything unset is off', () => {
  assert.deepEqual(readPsiEpochFlags({}), { receive: false, send: false, use: false });
});

test('only the exact string "true" switches a flag on (not "1", "TRUE", " true", "yes", true-ish)', () => {
  for (const v of ['1', 'TRUE', 'True', ' true', 'true ', 'yes', 'on', '']) {
    assert.deepEqual(readPsiEpochFlags({ receive: v }), { receive: false, send: false, use: false }, JSON.stringify(v));
  }
  assert.deepEqual(readPsiEpochFlags({ receive: 'true' }), { receive: true, send: false, use: false });
});

test('the allowed orders come through: receive; receive + send; all three', () => {
  assert.deepEqual(readPsiEpochFlags({ receive: 'true', send: 'true' }), { receive: true, send: true, use: false });
  assert.deepEqual(readPsiEpochFlags({ receive: 'true', send: 'true', use: 'true' }), { receive: true, send: true, use: true });
});

test('out of order falls back to ALL OFF, not to a partial state: send without receive, use without send', () => {
  assert.deepEqual(readPsiEpochFlags({ send: 'true' }), { receive: false, send: false, use: false });
  assert.deepEqual(readPsiEpochFlags({ receive: 'true', use: 'true' }), { receive: false, send: false, use: false });
  assert.deepEqual(readPsiEpochFlags({ use: 'true' }), { receive: false, send: false, use: false });
});

test('the default reads the build variables by their FULL names (Next.js only replaces a name it sees whole)', () => {
  const src = readFileSync(new URL('./psi-epoch-config.ts', import.meta.url), 'utf8');
  for (const name of ['NEXT_PUBLIC_PSI_EPOCH_RECEIVE', 'NEXT_PUBLIC_PSI_EPOCH_SEND', 'NEXT_PUBLIC_PSI_EPOCH_USE']) {
    assert.match(src, new RegExp(`process\\.env\\.${name}\\b`));
  }
  assert.doesNotMatch(src.replace(/^\s*(\/\/|\*|\/\*).*$/gm, ''), /process\.env\[/, 'no computed lookup');
});

test('with no variables set in the test environment, the default is all off', () => {
  assert.deepEqual(readPsiEpochFlags(), { receive: false, send: false, use: false });
});
