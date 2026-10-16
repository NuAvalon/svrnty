// src/lib/relay/mailbox-persistence.test.ts
// OPT-2 durability proof: mail survives a simulated process RESTART (file-backed SQLite). This is
// the whole point of OPT-2 — the in-memory globalThis.Map dropped pending mail on every restart.
// We deposit, drop the in-process connection (__closeDbForTests), then reopen from disk and assert
// the mail is still there. File-backed (RELAY_DB_PATH = a temp file), NOT :memory: (which is
// per-connection and could not prove cross-restart persistence).
//
// Run: npx tsx --test mailbox-persistence.test.ts

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rmSync } from 'node:fs';
import { depositEnvelope, pollMailbox, ackDelete, __closeDbForTests } from './mailbox-store';

const DB = join(tmpdir(), `svrnty-opt2-durability-${process.pid}.sqlite`);
process.env.RELAY_DB_PATH = DB;

function cleanup(): void {
  __closeDbForTests();
  for (const f of [DB, `${DB}-wal`, `${DB}-shm`]) {
    try { rmSync(f); } catch { /* not present — fine */ }
  }
}
before(cleanup);
after(cleanup);

const NOW = 2_000_000;

test('a deposited envelope survives a simulated process restart (close + reopen from disk)', () => {
  const dep = depositEnvelope('mbx-durable', 'SURVIVES-THE-FIRE', NOW);
  assert.deepEqual(dep, { ok: true });

  __closeDbForTests(); // simulate restart: drop the connection; next access reopens the file

  const list = pollMailbox('mbx-durable', NOW);
  assert.equal(list.length, 1, 'envelope survived the restart (in-memory Map would have dropped it)');
  assert.equal(list[0].blob, 'SURVIVES-THE-FIRE');
});

test('ack-delete persists across a restart (a drained mailbox stays drained)', () => {
  assert.deepEqual(depositEnvelope('mbx-ack', 'GONE-AFTER-ACK', NOW), { ok: true });
  const id = pollMailbox('mbx-ack', NOW)[0].envelope_id;
  assert.equal(ackDelete('mbx-ack', [id], NOW), 1);

  __closeDbForTests();

  assert.equal(pollMailbox('mbx-ack', NOW).length, 0, 'ack-delete was durable across the restart');
});

test('client-envelope_id dedup is idempotent across a restart (Apollo retry contract)', () => {
  const r1 = depositEnvelope('mbx-dedup', 'ONCE', NOW, 'client-stable-id-xyz');
  const r2 = depositEnvelope('mbx-dedup', 'ONCE', NOW, 'client-stable-id-xyz'); // retry, same id
  assert.deepEqual(r1, { ok: true });
  assert.deepEqual(r2, { ok: true }, 'retry is idempotent-OK, not an error');

  __closeDbForTests();

  const list = pollMailbox('mbx-dedup', NOW);
  assert.equal(list.length, 1, 'exactly one row despite the retry + restart (upsert-by-envelope_id)');
  assert.equal(list[0].envelope_id, 'client-stable-id-xyz');
});
