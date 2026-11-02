// #720 v5.2 E1 (hardening): a client-chosen envelope_id must pass safeEnvelopeId, the same rule the consume side applies.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rmSync } from 'node:fs';

const DB = join(tmpdir(), `svrnty-envelope-id-${process.pid}.sqlite`);
process.env.RELAY_DB_PATH = DB;
let store: typeof import('./mailbox-store');

before(async () => {
  store = await import('./mailbox-store');
});
after(() => {
  store.__closeDbForTests();
  for (const s of ['', '-wal', '-shm']) rmSync(DB + s, { force: true });
});

const ids = (mbx: string) => store.pollMailbox(mbx, Date.now()).map((e) => e.envelope_id);

test('an unsafe client envelope_id is refused with 400 and nothing is stored', () => {
  const now = Date.now();
  for (const [i, bad] of ['', 'has space', 'a/b', '../x', 'x'.repeat(101), 'nul\u0000', 'rlo\u202e'].entries()) {
    const mbx = `mbx_bad_${i}`;
    assert.deepEqual(store.depositEnvelope(mbx, 'blob', now, bad), { ok: false, status: 400 }, JSON.stringify(bad));
    assert.deepEqual(ids(mbx), [], JSON.stringify(bad));
  }
});

test('a safe client envelope_id is kept as given; an absent one gets the relay\'s own uuid', () => {
  const now = Date.now();
  assert.deepEqual(store.depositEnvelope('mbx_ok', 'blob', now, 'env-1.a:b_c'), { ok: true });
  assert.deepEqual(ids('mbx_ok'), ['env-1.a:b_c']);
  assert.deepEqual(store.depositEnvelope('mbx_auto', 'blob', now), { ok: true });
  assert.match(ids('mbx_auto')[0], /^[0-9a-f-]{36}$/);
});
