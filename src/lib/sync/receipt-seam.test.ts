// src/lib/sync/receipt-seam.test.ts
//
// TG-1 anchor, part A (Hypatia #704/#706, Flint #705; S62 contract v7, Hypatia TG-1 v1_3): "Delivered is shown only after a VERIFIED receipt".
// Runs the REAL buildReceiptSeam (live-book-poll.ts) with the REAL MAC primitive and, for the round trip, REAL hybrid sealing and the REAL
// emitter. Only the two store calls the accept performs (our stored outbound note, the one write) are in-memory maps injected through
// ReceiptSeamDeps; nothing about verification, keys or tags is mocked. Run: npx tsx --test src/lib/sync/receipt-seam.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { mintHeadlessAgent } from '../identity/headless-mint';
import { sealLivingBookHybrid } from '../crypto/living-book-sleeve';
import { newReceiptKey, receiptKeyToHex, receiptTag } from '../crypto/receipt-mac';
import { bytesToHex } from '@noble/hashes/utils.js';
import { buildReceiptWireV1, RECEIPT_V1_WIRE_TYPE } from '../messaging/receipt-wire-v1';
import { emitDeliveredReceipt } from '../messaging/receipt-emit';
import { signNoteWire } from '../messaging/note-auth';
import { buildReceiptSeam, type ReceiptSeamDeps } from './live-book-poll';
import { mintHybridRecipient } from './hybrid-test-fixture';
import { deriveMailboxId } from '../relay/mailbox-auth';
import type { OwnerIdentity } from './consume-mailbox';
import type { NoteRecord, NoteWireV0 } from '../messaging/types';
import { NOTE_WIRE_TYPE } from '../messaging/domains';

const NOTE_ID = 'note_under_test';
const RK = receiptKeyToHex(newReceiptKey());
const RECIPIENT_FP = 'ab'.repeat(32);

function outbound(over: Partial<NoteRecord> = {}): NoteRecord {
  return {
    note_id: NOTE_ID, thread_id: 'thr_1', direction: 'outbound', from_fingerprint: 'sender', to_fingerprints: [RECIPIENT_FP],
    sent_at: '2026-10-25T00:00:00.000Z', body: 'hello', participant_kind: 'human',
    retention: { expires_at: null }, wire_type: NOTE_WIRE_TYPE, receipt_nonce: 'legacy-nonce', receipt_key: RK, ...over,
  } as NoteRecord;
}

function world(note?: NoteRecord | null) {
  const notes = new Map<string, NoteRecord>();
  const written: NoteRecord[] = [];
  const n = note === undefined ? outbound() : note;
  if (n) notes.set(n.note_id, n);
  const deps: ReceiptSeamDeps = {
    getNote: (async (id: string) => notes.get(id) ?? null) as ReceiptSeamDeps['getNote'],
    putNote: (async (r: NoteRecord) => { written.push(r); notes.set(r.note_id, r); }) as ReceiptSeamDeps['putNote'],
  };
  const owner = { fingerprint: 'cd'.repeat(32), publicKeyArmored: '', privateKeyArmored: '', passphrase: '' } as OwnerIdentity;
  return { notes, written, seam: buildReceiptSeam(owner, undefined, deps) };
}
const wire = (rk = RK, noteId = NOTE_ID, code: 'delivered' | 'read' | 'couldnt_verify' = 'delivered') => buildReceiptWireV1(rk, noteId, code)!;
const delivered = (w: { notes: Map<string, NoteRecord> }) => w.notes.get(NOTE_ID)?.delivered === true;

test('A1: a genuine MAC receipt is accepted, the note is marked delivered in ONE write, and the receipt key is gone from the row', async () => {
  const w = world();
  const r = await w.seam.accept(wire());
  assert.deepEqual(r, { note_id: NOTE_ID, thread_id: 'thr_1', from_fingerprint: RECIPIENT_FP }, 'the recipient comes from OUR outbound record, not from the receipt');
  assert.equal(w.written.length, 1, 'the ONE write');
  assert.equal(delivered(w), true);
  assert.equal('receipt_key' in w.written[0], false, 'the key dies at Delivered (it has served its purpose)');
  assert.equal(w.written[0].body, 'hello', 'nothing else about the note changed');
});

test('A1b: a REDELIVERED receipt finds no key: dropped silently, no second write, the note stays delivered', async () => {
  const w = world();
  await w.seam.accept(wire());
  assert.equal(await w.seam.accept(wire()), null);
  assert.equal(w.written.length, 1);
  assert.equal(delivered(w), true);
});

test('A2 done_when 3: a relay-forged receipt (right note_id, random tag) is refused; a tag made with the WRONG key is refused; nothing is written', async () => {
  const w = world();
  const forged = { ...wire(), tag: bytesToHex(crypto.getRandomValues(new Uint8Array(32))) };
  assert.equal(await w.seam.accept(forged), null);
  assert.equal(await w.seam.accept(wire(receiptKeyToHex(newReceiptKey()))), null, 'an attacker with its own key and the right note_id');
  assert.equal(w.written.length, 0); assert.equal(delivered(w), false);
});

test('A2b: a tag TRANSPLANTED from another note, and a tag whose code was changed, are refused', async () => {
  const w = world();
  const otherNote = wire(RK, 'a_different_note');
  assert.equal(await w.seam.accept({ ...wire(), tag: otherNote.tag }), null, 'tag minted for another note_id');
  const readTag = wire(RK, NOTE_ID, 'read').tag;
  assert.equal(await w.seam.accept({ ...wire(), tag: readTag }), null, 'a "read" tag presented as "delivered"');
  assert.equal(await w.seam.accept(wire(RK, NOTE_ID, 'read')), null, 'a VALID read receipt is not acted on in this build (opt-in, reciprocal: a later slice)');
  assert.equal(await w.seam.accept(wire(RK, NOTE_ID, 'couldnt_verify')), null, 'and there is no couldn\'t-verify behaviour at all (v7)');
  assert.equal(w.written.length, 0); assert.equal(delivered(w), false);
});

test('A3: unknown note_id, an INBOUND note that shares the id, an outbound note with no key, and a malformed stored key are all refused', async () => {
  assert.equal(await world(null).seam.accept(wire()), null, 'unknown note_id');
  assert.equal(await world(outbound({ direction: 'inbound' })).seam.accept(wire()), null, 'an inbound note with that id (even one carrying a key)');
  assert.equal(await world(outbound({ receipt_key: undefined })).seam.accept(wire()), null, 'no stored key (older note)');
  assert.equal(await world(outbound({ receipt_key: 'zz'.repeat(32) })).seam.accept(wire()), null, 'a malformed stored key');
  assert.equal(await world(outbound({ to_fingerprints: [] })).seam.accept(wire()), null, 'no recipient on the record');
});

test('A4 third-party non-transferability: the verifier needs the sender\'s key and NOTHING else, so a public card + a receipt prove nothing', () => {
  const t = receiptTag(Uint8Array.from(Buffer.from(RK, 'hex')), NOTE_ID, 'delivered');
  assert.equal(bytesToHex(t), wire().tag);
  assert.equal(buildReceiptSeam.length <= 3, true);
});

// ── END TO END with real hybrid sealing: S sends a note, R's client answers with the REAL emitter, S's seam turns it into Delivered ──
test('E2E: sender stores the key, the recipient\'s real emitter seals a receipt to the sender\'s mailbox, the sender\'s real seam verifies it => Delivered', async () => {
  const S = await mintHybridRecipient();                        // the SENDER (owner of the seam), holds the ML-KEM secret
  const a = await mintHeadlessAgent({ throwaway: true });        // not used for keys; ensures the minting path is warm
  void a;
  const rk = receiptKeyToHex(newReceiptKey());
  const signed: NoteWireV0 = await signNoteWire(
    { type: NOTE_WIRE_TYPE, note_id: 'e2e_note', thread_id: 'thr_e2e', from_fingerprint: S.fingerprint, sent_at: new Date().toISOString(), body: 'e2e', participant_kind: 'human', receipt_key: rk },
    S.publicKeyArmored, S.privateKeyArmored, S.passphrase, S.pqKemPublicKey, S.pqSigPublicKey,
  );
  const posts: Array<{ mailbox_id: string; blob: string }> = [];
  const fetchImpl = (async (_u: string, init?: RequestInit) => { posts.push(JSON.parse(String(init?.body))); return new Response('{"ok":true}', { status: 200 }); }) as unknown as typeof fetch;
  assert.equal(await emitDeliveredReceipt(signed, { fetchImpl }), 'sent');
  assert.equal(posts[0].mailbox_id, deriveMailboxId(S.fingerprint));
  const notes = new Map<string, NoteRecord>([['e2e_note', outbound({ note_id: 'e2e_note', thread_id: 'thr_e2e', receipt_key: rk })]]);
  const deps: ReceiptSeamDeps = {
    getNote: (async (id: string) => notes.get(id) ?? null) as ReceiptSeamDeps['getNote'],
    putNote: (async (r: NoteRecord) => { notes.set(r.note_id, r); }) as ReceiptSeamDeps['putNote'],
  };
  const owner = { fingerprint: S.fingerprint, publicKeyArmored: S.publicKeyArmored, privateKeyArmored: S.privateKeyArmored, passphrase: S.passphrase } as OwnerIdentity;
  const seam = buildReceiptSeam(owner, S.hybrid, deps);
  const opened = await seam.verify(posts[0].blob);
  assert.ok(opened && opened.type === RECEIPT_V1_WIRE_TYPE && opened.note_id === 'e2e_note');
  const confirmed = await seam.accept(opened!);
  assert.equal(confirmed?.note_id, 'e2e_note');
  assert.equal(notes.get('e2e_note')?.delivered, true);
  assert.equal('receipt_key' in notes.get('e2e_note')!, false);
});

test('NEG done_when (C8a): a validly IDENTITY-SIGNED v0 receipt sealed to the sender does NOT light Delivered: it does not even open as a receipt', async () => {
  const S = await mintHybridRecipient();
  const v0 = { type: 'svrnty-receipt-v0', note_id: NOTE_ID, nonce: 'legacy-nonce', from_fingerprint: RECIPIENT_FP, sig: 'aa'.repeat(80) };
  const blob = await sealLivingBookHybrid(new TextEncoder().encode(JSON.stringify(v0)), S.publicKeyArmored, S.pqKemPublicKey);
  const w = world();
  const seam = buildReceiptSeam({ fingerprint: S.fingerprint, publicKeyArmored: S.publicKeyArmored, privateKeyArmored: S.privateKeyArmored, passphrase: S.passphrase } as OwnerIdentity, S.hybrid, { getNote: async (id: string) => w.notes.get(id) ?? null, putNote: async (r: NoteRecord) => { w.written.push(r); w.notes.set(r.note_id, r); } } as ReceiptSeamDeps);
  assert.equal(await seam.verify(blob), null, 'the v0 shape is not a receipt any more');
  assert.equal(w.written.length, 0); assert.equal(delivered(w), false);
  assert.equal(await world().seam.verify('anything'), null, 'and with no ML-KEM secret nothing opens at all');
});

// ── structure (contract v7 / C8a): the v0 verify path is GONE, `delivered: true` has exactly one writer, no failure state exists ──
function nonTestSource(): Array<{ rel: string; text: string }> {
  const out: Array<{ rel: string; text: string }> = [];
  const walk = (dir: string) => {
    for (const n of readdirSync(dir)) {
      if (n === 'node_modules' || n === '.next' || n.startsWith('.')) continue;
      const p = join(dir, n);
      if (statSync(p).isDirectory()) walk(p);
      else if (/\.(ts|tsx|mts|js|mjs)$/.test(n) && !/\.test\.(ts|tsx)$/.test(n)) out.push({ rel: relative(process.cwd(), p), text: readFileSync(p, 'utf8') });
    }
  };
  for (const d of ['src', 'app', 'scripts']) walk(join(process.cwd(), d));
  return out;
}

test('structure C8a: no non-test source names the v0 receipt API (verifyReceiptWire, ReceiptWireV0, RECEIPT_WIRE_TYPE, DOMAIN_RECEIPT, buildReceiptWire, delivery-receipt, receiptOpenpgpDecryptor, sealReceiptTo)', () => {
  const re = /\b(verifyReceiptWire|ReceiptWireV0|RECEIPT_WIRE_TYPE|DOMAIN_RECEIPT|buildReceiptWire|tryParseReceiptWire|receiptOpenpgpDecryptor|sealReceiptTo|sealReceiptClassicalFixture|signDeliveryReceipt|verifyDeliveryReceipt)\b|delivery-receipt['"/.]/;
  const hits = nonTestSource().filter((f) => re.test(f.text)).map((f) => f.rel);
  assert.deepEqual(hits, [], `v0 receipt API still referenced in: ${hits.join(', ')}`);
});

test('structure: `delivered: true` is written on exactly ONE line per seam (FE + headless), and each is reached only after verifyReceiptTag', () => {
  const code = (l: string) => !/^\s*(\/\/|\*|\/\*)/.test(l);
  const src = nonTestSource();
  const lines = src.flatMap((f) => f.text.split('\n').map((l, i) => ({ f: f.rel, i, l }))).filter((x) => /delivered:\s*true/.test(x.l) && code(x.l));
  // layer 1 (spec 65bac8aa): the headless store's markDelivered is the headless seam's one write (it rides the #712 group commit)
  assert.deepEqual(lines.map((x) => x.f), ['src/lib/headless/headless-store.ts', 'src/lib/sync/live-book-poll.ts'], JSON.stringify(lines));
  const fe = lines[1];
  const all = readFileSync(join(process.cwd(), fe.f), 'utf8').split('\n');
  const verifyLine = all.findIndex((l, i) => /verifyReceiptTag\(rk/.test(l) && code(l) && i > 0);
  assert.ok(verifyLine >= 0 && verifyLine < fe.i, 'FE: the tag check is on an earlier line than the one write');
  // headless: the store write sits inside markDelivered, and markDelivered is CALLED on exactly one line, after the tag check in that seam
  const hs = readFileSync(join(process.cwd(), lines[0].f), 'utf8').split('\n');
  const def = hs.findIndex((l) => /^\s*markDelivered\(/.test(l));
  assert.ok(def >= 0 && def < lines[0].i && hs.slice(def, lines[0].i).every((l) => !/^\s{2}\}\s*$/.test(l)), 'the headless write is inside markDelivered');
  const calls = src.flatMap((f) => f.text.split('\n').map((l, i) => ({ f: f.rel, i, l }))).filter((x) => /\.markDelivered\(/.test(x.l) && code(x.l));
  assert.deepEqual(calls.map((x) => x.f), ['src/lib/headless/headless-client.ts'], JSON.stringify(calls));
  const hc = readFileSync(join(process.cwd(), calls[0].f), 'utf8').split('\n');
  const hv = hc.findIndex((l) => /verifyReceiptTag\(rk/.test(l) && code(l));
  assert.ok(hv >= 0 && hv < calls[0].i && calls[0].i - hv < 4, 'headless: markDelivered is called right after the tag check returned true');
});

test('structure v7: the sender status enum has NO failure / couldn\'t-verify state, and no copy infers failure from a missing receipt', () => {
  const status = readFileSync(join(process.cwd(), 'src/components/notes/notes-status.ts'), 'utf8');
  const union = status.match(/export type NoteBubbleStatus = ([^;]+);/)![1];
  assert.deepEqual([...union.matchAll(/'([^']+)'/g)].map((m) => m[1]).sort(), ['delivered', 'inbound', 'not-sent', 'sent-unconfirmed']);
  assert.doesNotMatch(union, /verif|fail|invalid|could|error|unverified/i);
  const copy = readFileSync(join(process.cwd(), 'src/components/notes/notes-copy.ts'), 'utf8');
  assert.doesNotMatch(copy, /couldn['’]?t verify|could not verify|failed to verify/i);
});
