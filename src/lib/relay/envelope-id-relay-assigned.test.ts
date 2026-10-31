// src/lib/relay/envelope-id-relay-assigned.test.ts
// TRIPWIRE (Archie lane:svrnty #2315, after #2310-#2313): over HTTP the RELAY assigns every envelope id. A depositor cannot choose
// one: app/api/relay/envelope/route.ts calls depositEnvelope(mailboxId, blob, now) and never passes the store's optional
// clientEnvelopeId. #720 v5.2's malformed-id rule rests on that fact, and #318's held-frame schedule is keyed on the id.
// If a later change wires a client id through the route, these tests go RED on purpose: re-check v5.2 (and the schedule key)
// before turning them green.
//
// Run: npx tsx --test src/lib/relay/envelope-id-relay-assigned.test.ts

process.env.RELAY_DB_PATH = ':memory:'; // in-memory SQLite (the runner sets no NODE_ENV)
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { pollMailbox, resetMailboxStore } from './mailbox-store';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MBX = 'mbx_tripwire_envelope_id';

beforeEach(() => {
  resetMailboxStore();
});

async function deposit(body: Record<string, unknown>): Promise<{ status: number; json: unknown }> {
  const { POST } = await import('../../../app/api/relay/envelope/route');
  const res = await POST(new Request('http://r.test/api/relay/envelope', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }));
  return { status: res.status, json: await res.json() };
}

test('T1 a client-supplied envelope_id is ignored: the stored id is the relay\'s own random UUID', async () => {
  const r = await deposit({ mailbox_id: MBX, blob: 'B1', envelope_id: 'client-chosen-1' });
  assert.equal(r.status, 200);
  const [e, ...rest] = pollMailbox(MBX, Date.now());
  assert.equal(rest.length, 0);
  assert.equal(e.blob, 'B1');
  assert.notEqual(e.envelope_id, 'client-chosen-1');
  assert.match(e.envelope_id, UUID);
});

test('T2 the same client id twice with different blobs = two envelopes (no first-write-wins dedup over HTTP)', async () => {
  await deposit({ mailbox_id: MBX, blob: 'FIRST', envelope_id: 'same-id' });
  await deposit({ mailbox_id: MBX, blob: 'SECOND', envelope_id: 'same-id' });
  const list = pollMailbox(MBX, Date.now());
  assert.deepEqual(list.map((e) => e.blob), ['FIRST', 'SECOND']);
  assert.notEqual(list[0].envelope_id, list[1].envelope_id);
  assert.ok(list.every((e) => e.envelope_id !== 'same-id' && UUID.test(e.envelope_id)));
});

test('T3 the deposit ack names no id, and is the same with or without a client id', async () => {
  const a = await deposit({ mailbox_id: MBX, blob: 'X', envelope_id: 'client-chosen-2' });
  const b = await deposit({ mailbox_id: MBX, blob: 'Y' });
  assert.deepEqual(a, b);
  assert.deepEqual(a.json, { status: 'queued' });
});
