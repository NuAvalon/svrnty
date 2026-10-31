// src/lib/headless/headless-dead-letter.test.ts
// #713 for headless (Flint #189046 NEGs): a loss is RECORDED (a metadata row) before its envelope is acked, not only counted.
// Run: npx tsx --test src/lib/headless/headless-dead-letter.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { uint8ToBase64 } from '@/lib/crypto/pq';
import { signNoteWire } from '@/lib/messaging/note-auth';
import { sealNoteTo } from '@/lib/messaging/seal';
import type { NoteWireV0 } from '@/lib/messaging/types';
import { HeadlessStore, type HeadlessContact } from './headless-store';
import { type HeadlessOwner, pollHeadlessOnce, sendNoteFromHeadless } from './headless-client';
import { headlessDeadLetterSink, DEAD_LETTER_FILE } from './headless-dead-letter';

const RELAY = 'http://relay.test/api/relay';
const CANARY = 'CANARY-713-body-text-never-in-a-row';
type Id = { fp: string; pub: string; priv: string; kpass: string; kem: string; kemSec: string; sig: string };
async function mint(): Promise<Id> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return { fp: id.fingerprint, pub: id.public_key, priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass,
    kem: id.pq_kem_public_key, kemSec: uint8ToBase64(a.secret_material.mlkem1024Sec), sig: id.pq_sig_public_key };
}
const owner = (id: Id): HeadlessOwner => ({ fingerprint: id.fp, publicKeyArmored: id.pub, privateKeyArmored: id.priv, passphrase: id.kpass, kemPublicKey: id.kem, kemSecretKey: id.kemSec, sigPublicKey: id.sig });

function relay() {
  const box: Array<{ envelope_id: string; blob: string }> = [];
  const acked: string[] = [];
  let n = 0;
  const fetchImpl = (async (url: unknown, init?: RequestInit) => {
    const u = String(url);
    if (u.endsWith('/envelope')) { box.push({ envelope_id: `e${++n}`, blob: JSON.parse(String(init?.body)).blob }); return new Response('{}', { status: 200 }); }
    if (u.includes('/queue')) return new Response(JSON.stringify([...box]), { status: 200, headers: { 'content-type': 'application/json' } });
    if (u.includes('/ack')) { const { envelope_ids } = JSON.parse(String(init?.body)); acked.push(...envelope_ids); box.splice(0, box.length, ...box.filter((e) => !envelope_ids.includes(e.envelope_id))); return new Response('{"deleted":1}', { status: 200 }); }
    return new Response('', { status: 404 });
  }) as unknown as typeof fetch;
  return { box, acked, fetchImpl };
}
const rowsAt = (p: string) => JSON.parse(readFileSync(p, 'utf8')) as Record<string, { reason: string; fp?: string; blob_kind: string; first_seen: string; envelope_id: string }>;

test('D1 a stranger\'s genuine note via the relay → ONE row (reason not-in-book + the authenticated fp), recorded, THEN acked; file 0600; metadata only', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'hdl-'));
  try {
    const [A, B] = [await mint(), await mint()];
    const r = relay();
    await sendNoteFromHeadless({ owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem, body: CANARY, store: new HeadlessStore(), relayBase: RELAY, fetchImpl: r.fetchImpl });
    const path = join(dir, DEAD_LETTER_FILE);
    const s = await pollHeadlessOnce(owner(B), new HeadlessStore(), { relayBase: RELAY, fetchImpl: r.fetchImpl, deadLetterPath: path });
    assert.equal(s.deadLettered, 1);
    assert.equal(s.unrecorded, 0);
    assert.equal(s.lost['not-in-book'], 1);
    assert.deepEqual(r.acked, ['e1'], 'acked only after the row was written');
    const rows = rowsAt(path);
    assert.deepEqual(Object.keys(rows), ['e1']);
    assert.equal(rows.e1.reason, 'not-in-book');
    assert.equal(rows.e1.fp, A.fp.toLowerCase(), 'the AUTHENTICATED sender fp');
    assert.equal(rows.e1.blob_kind, 'hybrid-package');
    assert.equal((statSync(path).mode & 0o777).toString(8), '600');
    const text = readFileSync(path, 'utf8');
    assert.equal(text.includes(CANARY), false, 'no plaintext');
    assert.ok(text.length < 400, 'no blob: a row is a few fields, the blob is kilobytes');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('D2 NEG (F3) an UNVERIFIED note (signature does not match the body) → a row with NO fingerprint', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'hdl-'));
  try {
    const [A, B] = [await mint(), await mint()];
    const r = relay();
    const base = { type: 'svrnty-note-v0', note_id: 'n_forged', thread_id: 't1', from_fingerprint: A.fp, body: 'original', sent_at: '2026-10-31T20:00:00.000Z', participant_kind: 'human' } as unknown as NoteWireV0;
    const signed = await signNoteWire(base, A.pub, A.priv, A.kpass, A.kem, A.sig);
    const forged = { ...signed, body: 'tampered after signing' };
    r.box.push({ envelope_id: 'e-forged', blob: await sealNoteTo(forged, B.pub, B.kem) });
    const path = join(dir, DEAD_LETTER_FILE);
    const bStore = new HeadlessStore();
    bStore.upsertContact({ id: 'c_a', fingerprint: A.fp, public_key: A.pub, pq_sig_public_key: A.sig, pq_kem_public_key: A.kem, trust_level: 'known' } as HeadlessContact);
    const s = await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl: r.fetchImpl, deadLetterPath: path });
    assert.equal(s.deadLettered, 1);
    const row = rowsAt(path)['e-forged'];
    assert.equal(row.reason, 'verify-failed');
    assert.equal('fp' in row, false, 'an unauthenticated from_fingerprint is never recorded');
    assert.equal(bStore.listNotes().length, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('D3 NEG a FAILING sink (unparseable file) → nothing is acked, the envelope stays on the relay, unrecorded++', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'hdl-'));
  try {
    const [A, B] = [await mint(), await mint()];
    const r = relay();
    await sendNoteFromHeadless({ owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem, body: 'x', store: new HeadlessStore(), relayBase: RELAY, fetchImpl: r.fetchImpl });
    const path = join(dir, DEAD_LETTER_FILE);
    writeFileSync(path, '{torn', { mode: 0o600 });
    const s = await pollHeadlessOnce(owner(B), new HeadlessStore(), { relayBase: RELAY, fetchImpl: r.fetchImpl, deadLetterPath: path });
    assert.equal(s.unrecorded, 1);
    assert.equal(s.deadLettered, 0);
    assert.deepEqual(r.acked, [], 'never acked unrecorded');
    assert.equal(r.box.length, 1, 'still on the relay for a later poll');
    assert.equal(readFileSync(path, 'utf8'), '{torn', 'a torn file is never silently replaced');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('D4 control: an ADMITTED sender\'s note is stored and acked with NO row (and no file is created for nothing)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'hdl-'));
  try {
    const [A, B] = [await mint(), await mint()];
    const r = relay();
    await sendNoteFromHeadless({ owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem, body: 'hi', store: new HeadlessStore(), relayBase: RELAY, fetchImpl: r.fetchImpl });
    const path = join(dir, DEAD_LETTER_FILE);
    const bStore = new HeadlessStore();
    bStore.upsertContact({ id: 'c_a', fingerprint: A.fp, public_key: A.pub, pq_sig_public_key: A.sig, pq_kem_public_key: A.kem, trust_level: 'known' } as HeadlessContact);
    const s = await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl: r.fetchImpl, deadLetterPath: path });
    assert.equal(s.notes, 1);
    assert.equal(s.deadLettered, 0);
    assert.deepEqual(r.acked, ['e1']);
    assert.equal(existsSync(path), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('D5 sink unit: re-record keeps the EARLIEST first_seen; clear() removes the row (a later success replaces the flag); settle() prunes > 30 days', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'hdl-'));
  try {
    const path = join(dir, DEAD_LETTER_FILE);
    let nowMs = Date.parse('2026-10-31T20:00:00.000Z');
    const sink = headlessDeadLetterSink(path, () => nowMs);
    const row = (id: string, t: string) => ({ envelope_id: id, first_seen: t, reason: 'not-in-book' as const, blob_kind: 'hybrid-package' as const });
    await sink.record(row('a', '2026-10-30T10:00:00.000Z'));
    const again = await sink.record(row('a', '2026-10-31T19:00:00.000Z'));
    assert.equal(again.first_seen, '2026-10-30T10:00:00.000Z');
    await sink.record(row('b', '2026-10-31T19:00:00.000Z'));
    await sink.clear('b');
    assert.deepEqual(Object.keys(rowsAt(path)), ['a']);
    nowMs = Date.parse('2026-12-15T00:00:00.000Z');
    await sink.settle!();
    assert.deepEqual(Object.keys(rowsAt(path)), [], 'older than 30 days is pruned');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('D6 the CLI wires it: devin-comm\'s poll passes <agent dir>/dead-letters.json', () => {
  const src = readFileSync(join(__dirname, '../../../scripts/devin-comm.ts'), 'utf8');
  assert.match(src, /buildHeadlessConsumeDeps\(owner, store, \{ relayBase: RELAY, deadLetterPath: `\$\{DIR\}\/\$\{DEAD_LETTER_FILE\}` \}\)/);
});
