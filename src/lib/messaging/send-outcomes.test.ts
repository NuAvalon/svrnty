// src/lib/messaging/send-outcomes.test.ts
//
// B group 2, commit 4d-2 (Flint #823 T1/T3, Hypatia #837): a failed send says WHERE it failed, because the three cases need three different
// things from the user, and a wrong word either loses a message or duplicates one.
//   not-sent        threw before the POST, or the relay refused: nothing is held by the relay. Keep the draft.
//   unconfirmed     the POST threw or hung: the relay MAY have it. Never "not sent". No Retry (a resend can still duplicate, T2 not built).
//   sent-not-saved  the relay accepted (2xx), then the local save failed. It IS sent. Do not send again; keep the text visible.
// Real keys and signatures (mintHeadlessAgent); the only fakes are the relay (fetchImpl) and the storage (io), so "the POST happened" and
// "nothing was stored" are assertions about logs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq';
import type { RatchetIdentity, RatchetPeer } from '../crypto/message-ratchet';
import { mintHeadlessAgent } from '../identity/headless-mint';
import { NoteSendError, sendNoteToPeer, type SendNoteToPeerArgs } from './transport';
import { RatchetSessionBusyError } from './peer-session-lock';
import type { NoteRecord } from './types';
import { memIO } from './ratchet-test-io';
import { NOTES_COPY } from '../../components/notes/notes-copy';
import { sendNoteFromInbox } from '../../components/notes/notes-send';

function ratchetIdentity(): RatchetIdentity {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
}
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });

type Minted = Awaited<ReturnType<typeof mintHeadlessAgent>>;
const idOf = (a: Minted) => a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };

type Over = Partial<SendNoteToPeerArgs['io']> & { fetchImpl?: typeof fetch; postTimeoutMs?: number };

async function flow(over: Over = {}) {
  const [sender, peer] = [await mintHeadlessAgent({ throwaway: true }), await mintHeadlessAgent({ throwaway: true })];
  const stored: NoteRecord[] = [];
  const posts: string[] = [];
  const me = ratchetIdentity(), them = ratchetIdentity();
  const okFetch = (async (url: string) => { posts.push(String(url)); return new Response('{"ok":true}', { status: 200 }); }) as typeof fetch;
  const call = () => sendNoteToPeer({
    sender: { fingerprint: idOf(sender).fingerprint, participant_kind: 'human' },
    senderPublicKeyArmored: idOf(sender).public_key,
    senderPrivateKeyArmored: sender.secret_material.classicalPrivateKey,
    passphrase: sender.secret_material.classicalKpass,
    senderPqKemPublicKey: idOf(sender).pq_kem_public_key,
    senderPqSigPublicKey: idOf(sender).pq_sig_public_key,
    peerFingerprint: 'fp-them',
    peerPublicKeyArmored: idOf(peer).public_key,
    peerPqKemPublicKey: idOf(peer).pq_kem_public_key,
    body: 'hello there',
    ownerRatchet: me,
    peerRatchet: peerOf(them),
    postTimeoutMs: over.postTimeoutMs,
    fetchImpl: over.fetchImpl ? ((async (u: string, i: RequestInit) => { posts.push(String(u)); return over.fetchImpl!(u, i); }) as typeof fetch) : okFetch,
    io: {
      ratchet: over.ratchet ?? memIO().io,
      putNote: over.putNote ?? (async (n: NoteRecord) => { stored.push(n); }),
      listThreads: over.listThreads ?? (async () => []),
      putThread: over.putThread ?? (async () => {}),
    },
  });
  return { call, stored, posts };
}

async function failure(call: () => Promise<unknown>): Promise<NoteSendError> {
  try { await call(); } catch (e) { assert.ok(e instanceof NoteSendError, `expected a NoteSendError, got ${String(e)}`); return e; }
  assert.fail('expected the send to throw');
}

test('control: the happy path still resolves {deposited:true}, one POST, one local copy', async () => {
  const f = await flow();
  const r = await f.call();
  assert.equal(r.deposited, true);
  assert.equal(f.posts.length, 1);
  assert.equal(f.stored.length, 1);
});

// ── NOT SENT ─────────────────────────────────────────────────────────────────────────────────────────────────────────

test('not-sent: a throw BEFORE the POST (here the session lock is unavailable) => no POST at all, nothing stored', async () => {
  const busy = { ...memIO().io, acquireLock: async () => { throw new RatchetSessionBusyError(); } };
  const f = await flow({ ratchet: busy });
  const e = await failure(f.call);
  assert.equal(e.kind, 'not-sent');
  assert.deepEqual(f.posts, [], 'nothing left this device');
  assert.equal(f.stored.length, 0);
  assert.match(e.note_id, /^note_/, 'the ids are known even though nothing was sent');
});

test('not-sent: the relay REFUSES the deposit (429) => resolves deposited:false and keeps the local copy, as before', async () => {
  const f = await flow({ fetchImpl: (async () => new Response('{"error":"Mailbox at capacity."}', { status: 429 })) as typeof fetch });
  const r = await f.call();
  assert.equal(r.deposited, false);
  assert.equal(f.stored.length, 1);
});

test('refused: a 4xx (definite refusal) followed by a local-save failure is its OWN kind (the relay holds nothing, but it DID receive and answer)', async () => {
  for (const status of [400, 413, 429]) {
    const f = await flow({
      fetchImpl: (async () => new Response('x', { status })) as typeof fetch,
      putNote: async () => { throw new Error('IDB write failed'); },
    });
    const e = await failure(f.call);
    assert.equal(e.kind, 'refused', `HTTP ${status}`);
    assert.equal(f.posts.length, 1, 'the sealed message reached the relay, so "nothing left this device" would be false');
  }
});

test('unconfirmed: a 5xx (500, 502, 504) may have come back AFTER the relay stored it, so it is NOT "not sent" and nothing is saved as not-sent', async () => {
  for (const status of [500, 502, 503, 504]) {
    const f = await flow({ fetchImpl: (async () => new Response('gateway', { status })) as typeof fetch });
    const e = await failure(f.call);
    assert.equal(e.kind, 'unconfirmed', `HTTP ${status}`);
    assert.match(e.message, new RegExp(`answered ${status}`));
    assert.equal(f.posts.length, 1);
    assert.equal(f.stored.length, 0, 'no "not sent" local record that would invite a duplicate resend');
  }
});

// ── UNCONFIRMED ──────────────────────────────────────────────────────────────────────────────────────────────────────

test('unconfirmed: the POST throws (network drop) => the relay MAY have it, so NOT "not sent"; the attempt was made, nothing stored', async () => {
  const f = await flow({ fetchImpl: (async () => { throw new TypeError('fetch failed'); }) as typeof fetch });
  const e = await failure(f.call);
  assert.equal(e.kind, 'unconfirmed');
  assert.equal(f.posts.length, 1, 'the POST was attempted');
  assert.equal(f.stored.length, 0);
});

test('unconfirmed: a relay that never answers is cut off by the hard timeout, even if fetch ignores the abort signal', { timeout: 8000 }, async () => {
  const f = await flow({ postTimeoutMs: 25, fetchImpl: (() => new Promise(() => {})) as unknown as typeof fetch });
  const t0 = Date.now();
  const e = await failure(f.call);
  assert.equal(e.kind, 'unconfirmed');
  assert.match(e.message, /did not answer in time/);
  assert.ok(Date.now() - t0 < 2000, 'it did not hang');
});

// ── SENT, NOT SAVED ──────────────────────────────────────────────────────────────────────────────────────────────────

test('sent-not-saved: relay answered 200, then putNote throws => SENT (one POST), kind sent-not-saved, ids carried', async () => {
  const f = await flow({ putNote: async () => { throw new Error('IDB write failed'); } });
  const e = await failure(f.call);
  assert.equal(e.kind, 'sent-not-saved');
  assert.equal(f.posts.length, 1);
  assert.match(e.note_id, /^note_/);
  assert.match(e.thread_id, /^thr_/);
});

test('sent-not-saved: the same when listThreads or putThread is what fails after the deposit', async () => {
  for (const over of [
    { listThreads: async () => { throw new Error('read failed'); } },
    { putThread: async () => { throw new Error('write failed'); } },
  ]) {
    const f = await flow(over);
    assert.equal((await failure(f.call)).kind, 'sent-not-saved');
    assert.equal(f.posts.length, 1);
  }
});

// ── the layer the UI calls ───────────────────────────────────────────────────────────────────────────────────────────

const sendArgs = {
  sender: { fingerprint: 'fp-me', publicKeyArmored: 'x', privateKeyArmored: 'x', passphrase: 'x', canonical: true } as never,
  peerFingerprint: 'fp-them', peerPublicKeyArmored: 'x', body: 'b',
};

test('sendNoteFromInbox maps each kind to its ruled message and keeps the kind; an unknown throw before the POST is not-sent', async () => {
  const ids = { note_id: 'note_1', thread_id: 'thr_1' };
  const want = {
    'not-sent': NOTES_COPY.sendFailed,
    refused: NOTES_COPY.sendRefused,
    unconfirmed: NOTES_COPY.sendUnconfirmed,
    'sent-not-saved': NOTES_COPY.sentNotSaved,
  } as const;
  for (const kind of Object.keys(want) as Array<keyof typeof want>) {
    const r = await sendNoteFromInbox({ ...sendArgs, send: async () => { throw new NoteSendError(kind, new Error('boom'), ids); } });
    assert.deepEqual(r, { ok: false, kind, error: want[kind] });
  }
  const other = await sendNoteFromInbox({ ...sendArgs, send: async () => { throw new Error('key load failed'); } });
  assert.deepEqual(other, { ok: false, kind: 'not-sent', error: NOTES_COPY.sendFailed });
});

test('copy: the three messages are exactly the ruled wording, none claims delivery, and there is NO retry promise yet', () => {
  assert.equal(NOTES_COPY.sendFailed, 'Not sent. Nothing left this device. Your message is still in the box.');
  assert.equal(NOTES_COPY.sendUnconfirmed, "Couldn't confirm it was sent. The relay may already have it.");
  assert.equal(
    NOTES_COPY.sentNotSaved,
    "Sent to the relay, but this device couldn't save a copy. Don't send it again. Your text is below so you can copy it.",
  );
  assert.equal(NOTES_COPY.sendRefused, 'Not sent. The relay turned it down. Your message is still in the box.');
  // Hypatia #851: the refusal path must never say nothing left this device (the sealed message reached the relay).
  assert.doesNotMatch(NOTES_COPY.sendRefused, /left this device/i);
  assert.match(NOTES_COPY.sendFailed, /Nothing left this device/);
  for (const m of [NOTES_COPY.sendFailed, NOTES_COPY.sendRefused, NOTES_COPY.sendUnconfirmed, NOTES_COPY.sentNotSaved]) assert.doesNotMatch(m, /deliver|received/i);
  assert.doesNotMatch(JSON.stringify(NOTES_COPY), /second copy|Retrying won't/i, 'the relay ignores a client envelope id today, so a resend CAN duplicate');
});

test('NotesInbox: sent-not-saved moves the text to a read-only panel (compose cleared, dismiss clears it); the other two keep the draft; no Retry button', () => {
  const src = readFileSync(join(__dirname, '..', '..', 'components', 'notes', 'NotesInbox.tsx'), 'utf8');
  const block = /if \(result\.kind === 'sent-not-saved'\) \{([\s\S]*?)\n        \}/.exec(src);
  assert.ok(block, 'the sent-not-saved branch exists');
  assert.match(block![1], /setUnsaved\(body\)/);
  assert.match(block![1], /setDraft\(''\)/);
  assert.doesNotMatch(block![1], /setError/, 'it is not shown as an error that invites a resend');
  assert.match(src, /data-testid="notes-unsaved-text"[\s\S]{0,200}readOnly|readOnly[\s\S]{0,200}data-testid="notes-unsaved-text"/);
  assert.match(src, /onClick=\{\(\) => setUnsaved\(null\)\}/);
  assert.doesNotMatch(src, /Retry/, 'no Retry affordance until the relay honors an envelope id (T2)');
});
