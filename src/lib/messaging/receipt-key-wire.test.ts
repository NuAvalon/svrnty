// src/lib/messaging/receipt-key-wire.test.ts
// S62 slice 2 (contract v6, Flint A5-d C1/C2/C3): every note the PWA sends carries a fresh per-note `receipt_key` INSIDE the sealed, signed wire,
// and the sender keeps it on its own encrypted outbound record. The recipient later returns a MAC under it (slice 1, crypto/receipt-mac.ts).
// NEG-first: before this change the wire carried only the old receipt_nonce.
// Run: npx tsx --test src/lib/messaging/receipt-key-wire.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq';
import type { RatchetIdentity, RatchetPeer } from '../crypto/message-ratchet';
import { openLivingBookHybrid } from '../crypto/living-book-sleeve';
import { deriveMailboxFp } from '../crypto/mailbox-envelope';
import { mintHeadlessAgent } from '../identity/headless-mint';
import { noteSigningInput } from './canonical';
import { verifyNoteSender } from './note-auth';
import { sendNoteToPeer } from './transport';
import { memIO } from './ratchet-test-io';
import type { NoteRecord, NoteWireV0 } from './types';

const ROOT = join(__dirname, '..', '..', '..');
const HEX64 = /^[0-9a-f]{64}$/;

const ratchetIdentity = (): RatchetIdentity => {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
};
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });
type Minted = Awaited<ReturnType<typeof mintHeadlessAgent>>;
const idOf = (a: Minted) => a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };

/** Send one note for real (real keys, real seal); return what the relay was handed (opened with the recipient's keys) and what was stored locally. */
async function sendOne(sender: Minted, peer: Minted, body = 'hello there') {
  const stored: NoteRecord[] = [];
  let blob = '';
  const me = ratchetIdentity(), them = ratchetIdentity();
  const fetchImpl = (async (_u: string, init: RequestInit) => {
    blob = (JSON.parse(String(init.body)) as { blob: string }).blob;
    return new Response('{"ok":true}', { status: 200 });
  }) as typeof fetch;
  await sendNoteToPeer({
    sender: { fingerprint: idOf(sender).fingerprint, participant_kind: 'human' },
    senderPublicKeyArmored: idOf(sender).public_key,
    senderPrivateKeyArmored: sender.secret_material.classicalPrivateKey,
    passphrase: sender.secret_material.classicalKpass,
    senderPqKemPublicKey: idOf(sender).pq_kem_public_key,
    senderPqSigPublicKey: idOf(sender).pq_sig_public_key,
    peerFingerprint: 'fp-them',
    peerPublicKeyArmored: idOf(peer).public_key,
    peerPqKemPublicKey: idOf(peer).pq_kem_public_key,
    body,
    ownerRatchet: me,
    peerRatchet: peerOf(them),
    fetchImpl,
    io: { ratchet: memIO().io, putNote: async (n: NoteRecord) => { stored.push(n); }, listThreads: async () => [], putThread: async () => {} },
  });
  const m = peer.secret_material;
  const opened = await openLivingBookHybrid(blob, { x25519Sec: m.x25519Sec, mlkem1024Sec: m.mlkem1024Sec }, deriveMailboxFp(m.x25519Pub, m.mlkem1024Pub));
  assert.ok(opened, 'the recipient can open the sealed blob');
  return { wire: JSON.parse(new TextDecoder().decode(opened!)) as NoteWireV0, local: stored[0] };
}

test('W1 compat: a note WITHOUT receipt_key has a signing input byte-identical to today (golden string from the pre-change canonicalizer)', () => {
  const wire = { type: 'svrnty-note-v0', note_id: 'note_golden', thread_id: 'thr_golden', from_fingerprint: 'ab'.repeat(32), sent_at: '2026-10-30T12:00:00.000Z', body: 'golden body', participant_kind: 'human', receipt_nonce: 'nonce-golden' } as unknown as NoteWireV0;
  assert.equal(
    noteSigningInput(wire),
    '{"body":"golden body","from_fingerprint":"abababababababababababababababababababababababababababababababab","note_id":"note_golden","participant_kind":"human","receipt_nonce":"nonce-golden","sent_at":"2026-10-30T12:00:00.000Z","thread_id":"thr_golden","type":"svrnty-note-v0"}',
  );
  assert.match(noteSigningInput({ ...wire, receipt_key: 'cd'.repeat(32) }), /"receipt_key":"(cd){32}"/, 'and WITH it, the key is inside the signed bytes');
});

test('W2 C1: every sent note carries a fresh 64-hex receipt_key INSIDE the sealed wire, and no two notes share one', async () => {
  const [sender, peer] = [await mintHeadlessAgent({ throwaway: true }), await mintHeadlessAgent({ throwaway: true })];
  const keys = new Set<string>();
  for (let i = 0; i < 5; i++) {
    const { wire } = await sendOne(sender, peer, `note ${i}`);
    assert.match(String(wire.receipt_key), HEX64);
    keys.add(String(wire.receipt_key));
  }
  assert.equal(keys.size, 5);
});

test('W3 C3: the key is covered by the sender signature: the note verifies as sent; altering, removing, or adding the key afterwards fails', async () => {
  const [sender, peer] = [await mintHeadlessAgent({ throwaway: true }), await mintHeadlessAgent({ throwaway: true })];
  const { wire } = await sendOne(sender, peer);
  assert.equal(await verifyNoteSender(wire), true, 'control: as sent, it authenticates');
  const flipped = { ...wire, receipt_key: (wire.receipt_key as string).replace(/^./, (c) => (c === '0' ? '1' : '0')) };
  assert.equal(await verifyNoteSender(flipped), false, 'altered key');
  const without: Partial<NoteWireV0> = { ...wire };
  delete without.receipt_key;
  assert.equal(await verifyNoteSender(without as NoteWireV0), false, 'removed key');
  assert.equal(await verifyNoteSender({ ...wire, receipt_key: 'ab'.repeat(32) }), false, 'swapped key');
});

test('W4 the sender keeps the SAME key on its own outbound record (the source of truth for verifying the MAC), alongside the old nonce', async () => {
  const [sender, peer] = [await mintHeadlessAgent({ throwaway: true }), await mintHeadlessAgent({ throwaway: true })];
  const { wire, local } = await sendOne(sender, peer);
  assert.match(String(local.receipt_key), HEX64, 'a real key, not undefined');
  assert.equal(local.receipt_key, wire.receipt_key);
  assert.ok(local.receipt_nonce && local.receipt_nonce === wire.receipt_nonce, 'v1 nonce kept until the v1 verify path is removed (C8a, a later slice)');
  assert.equal(local.direction, 'outbound');
});

test('W5 C2 (structural): the key name appears only in the files that must handle it; no UI, script, journal or log writer mentions it', () => {
  const walk = (dir: string, out: string[] = []): string[] => {
    for (const name of readdirSync(dir)) {
      if (name === 'node_modules' || name === '.next' || name.startsWith('.')) continue;
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p, out);
      else if (/\.(ts|tsx|mjs|js)$/.test(name)) out.push(p);
    }
    return out;
  };
  const hits = [...walk(join(ROOT, 'src')), ...walk(join(ROOT, 'app')), ...walk(join(ROOT, 'scripts'))]
    .filter((f) => !/\.test\.tsx?$/.test(f))
    .filter((f) => /receipt_key/.test(readFileSync(f, 'utf8')))
    .map((f) => relative(ROOT, f))
    .sort();
  assert.deepEqual(hits, ['src/lib/crypto/receipt-mac.ts', 'src/lib/messaging/receipt-emit.ts', 'src/lib/messaging/transport.ts', 'src/lib/messaging/types.ts', 'src/lib/sync/live-book-poll.ts'], 'a new place that touches the key is a deliberate edit of this list (slice 3 added receipt-emit.ts: the recipient reads the key off an ACCEPTED note, only to compute the tag; slice 4 added live-book-poll.ts: the SENDER seam reads its own stored key to verify the tag and then drops it) (and of the C2 review)');
});

test('W6 C2 (line level): in the files that handle the key, no console/log/journal/JSON-dump line mentions it', () => {
  for (const f of ['src/lib/messaging/transport.ts', 'src/lib/messaging/types.ts', 'src/lib/crypto/receipt-mac.ts']) {
    const offenders = readFileSync(join(ROOT, f), 'utf8')
      .split('\n')
      .map((line, i) => ({ line, n: i + 1 }))
      .filter(({ line }) => !/^\s*(\/\/|\*|\/\*)/.test(line)) // comments may describe the rule
      .filter(({ line }) => /receipt_key|receiptKey|\brk\b/.test(line) && /console\.|\blog\w*\(|logger|JSON\.stringify|writeFile|appendFile|postMessage|localStorage|sessionStorage/.test(line));
    assert.deepEqual(offenders, [], `${f}: the receipt key must never reach a log, dump or storage call`);
  }
});
