// src/lib/messaging/reset-flag-720.test.ts
// #720 R4: the per-contact "this device reset <contact> and has received no frame since" flag. The pure row/key rules, the ORDER of the reset
// (session first, flag last, never on a failed step), and static guards that the store only touches the allowed rows. The IndexedDB reads and
// writes themselves are not run here (no Node harness); the real-browser proof runs them.
// Run: npx tsx --test src/lib/messaging/reset-flag-720.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { RESET_FLAG_PREFIX, normalizeResetFp, parseResetFlagRow, resetFlagKey } from './reset-flag';
import { isAllowedSettingsRowKey } from './settings-row-keys';
import { resetMessageSession, type SessionResetDeps } from './session-reset';

const FP = 'ab'.repeat(32);
const NOWISO = '2026-10-31T12:00:00.000Z';

test('F1 the key is the prefix plus the lowercase hex fingerprint, and only that; raw text never becomes a key', () => {
  assert.equal(resetFlagKey(FP.toUpperCase()), `${RESET_FLAG_PREFIX}${FP}`, 'case-folded');
  assert.equal(isAllowedSettingsRowKey(resetFlagKey(FP)), true, 'the allowlist accepts it');
  assert.equal(isAllowedSettingsRowKey(resetFlagKey('f'.repeat(128))), true, 'the longest accepted fingerprint still fits the row-key limit');
  for (const bad of ['', 'xyz', 'ab cd', 'ab/cd', 'ab:cd', '../x', 'é', 'f'.repeat(129), null, undefined, 7, {}]) {
    assert.equal(resetFlagKey(bad), null, JSON.stringify(bad));
    assert.equal(normalizeResetFp(bad), null);
  }
});

test('F2 the row is exactly {fp, reset_at}; anything else is absent, never repaired', () => {
  assert.deepEqual(parseResetFlagRow({ fp: FP, reset_at: NOWISO }), { fp: FP, reset_at: NOWISO });
  for (const bad of [null, undefined, 'x', [], {}, { fp: FP }, { reset_at: NOWISO }, { fp: FP, reset_at: NOWISO, extra: 1 },
    { fp: FP.toUpperCase(), reset_at: NOWISO }, { fp: 'zz', reset_at: NOWISO }, { fp: FP, reset_at: '5' }, { fp: FP, reset_at: '2026-10-31' },
    { fp: FP, reset_at: '2026-10-31T12:00:00' }, { fp: FP, reset_at: 5 }, { fp: 5, reset_at: NOWISO }]) {
    assert.equal(parseResetFlagRow(bad), null, JSON.stringify(bad));
  }
});

function deps(log: string[], o: { failAt?: 'reset' | 'mark' | 'flag'; hadSession?: boolean } = {}): SessionResetDeps {
  return {
    resetSession: async (owner, peer) => { log.push(`reset:${owner}:${peer}`); if (o.failAt === 'reset') throw new Error('x'); return o.hadSession ?? true; },
    markReleased: async (peer) => { log.push(`mark:${peer}`); if (o.failAt === 'mark') throw new Error('x'); return 3; },
    setFlag: async (peer, at) => { log.push(`flag:${peer}:${at}`); if (o.failAt === 'flag') throw new Error('x'); },
    now: () => new Date(NOWISO),
  };
}

test('F3 reset order: session, then marking, then the flag, with the contact as given and the time of the reset', async () => {
  const log: string[] = [];
  const r = await resetMessageSession('OWNER', FP.toUpperCase(), deps(log));
  assert.deepEqual(log, [`reset:OWNER:${FP.toUpperCase()}`, `mark:${FP}`, `flag:${FP.toUpperCase()}:${NOWISO}`]);
  assert.deepEqual(r, { hadSession: true, released: 3 });
});

test('F4 the flag is NEVER set for a reset that failed: a failed session delete or a failed marking leaves it unset', async () => {
  for (const failAt of ['reset', 'mark'] as const) {
    const log: string[] = [];
    await assert.rejects(resetMessageSession('OWNER', FP, deps(log, { failAt })));
    assert.ok(!log.some((l) => l.startsWith('flag:')), `${failAt} failed: no flag`);
  }
  const log: string[] = [];
  await assert.rejects(resetMessageSession('OWNER', FP, deps(log, { failAt: 'flag' })), 'a flag that cannot be set is reported, not swallowed (a repeated reset sets it)');
});

test('F5 a reset with no session row still sets the flag (our next message starts a fresh session either way)', async () => {
  const log: string[] = [];
  const r = await resetMessageSession('OWNER', FP, deps(log, { hadSession: false }));
  assert.equal(r.hadSession, false); assert.ok(log.some((l) => l.startsWith('flag:')));
});

const src = (p: string) => readFileSync(new URL(p, import.meta.url), 'utf8');
const code = (p: string) => src(p).split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');

test('F6 static: the store builds every key with resetFlagKey (no raw text), validates every row it reads, and clears with a read first', () => {
  const st = src('./reset-flag-store.ts');
  const builds = st.match(/RESET_FLAG_PREFIX\}\$\{[^}]*\}/g) ?? [];
  assert.deepEqual(builds, ['RESET_FLAG_PREFIX}${row.fp}'], 'the only inline key is the list() comparison against a validated row; every other key comes from resetFlagKey');
  assert.match(st, /parseResetFlagRow\(await getEncryptedSetting/, 'has() validates the row');
  assert.match(st, /const row = parseResetFlagRow\(value\);\s*if \(row && key === `\$\{RESET_FLAG_PREFIX\}\$\{row\.fp\}`\)/, 'list() skips a row whose key and fp disagree');
  const clear = st.slice(st.indexOf('export async function clearResetFlagIfSet'));
  assert.ok(clear.indexOf('getEncryptedSetting') > -1 && clear.indexOf('getEncryptedSetting') < clear.indexOf('deleteEncryptedSetting'), 'read before delete');
  assert.doesNotMatch(code('./reset-flag-store.ts'), /localStorage|sessionStorage/, 'never localStorage');
  assert.doesNotMatch(code('./reset-flag.ts'), /localStorage|sessionStorage/);
});

test('F7 static: the poll clears the flag from onFrameOpened, with the real store, and transport fires the hook only on a ratchet open, after the commit', () => {
  assert.match(src('../sync/live-book-poll.ts'), /onFrameOpened: async \(fp\) => \{\s*const \{ clearResetFlagIfSet \} = await import\('@\/lib\/messaging\/reset-flag-store'\);\s*await clearResetFlagIfSet\(fp\);/);
  const tr = src('./transport.ts');
  const fire = tr.indexOf('args.onFrameOpened?.(');
  assert.ok(fire > tr.indexOf('await staged.commit()'), 'after the commit');
  assert.match(tr.slice(tr.lastIndexOf('if (viaRatchet)', fire), fire), /if \(viaRatchet\) \{\s*try \{ await $/, 'only when a ratchet frame opened');
  assert.match(tr, /viaRatchet = true;[\s\S]{0,80}if \(typeof opened === 'string'\)/, 'set only after the failure branches returned');
});
