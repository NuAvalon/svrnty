// src/lib/sync/receipt-seam.test.ts
//
// TG-1 anchor, part A (Hypatia #704/#706, Flint #705): "Delivered is shown only after a recipient-signed receipt verifies".
// This runs the REAL buildReceiptSeam accept (live-book-poll.ts) with REAL keys and REAL signatures: real minted
// identities, a real hybrid ed25519 + ML-DSA-87 receipt (buildReceiptWire), the real canonical-key derivation from the
// recipient's card, the real verifyReceiptWire. Only the three I/O calls the accept performs (our stored note, the
// recipient's card in our book, the one write) are in-memory maps, injected through ReceiptSeamDeps; nothing about
// verification, keys or nonces is mocked.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mintHeadlessAgent } from '../identity/headless-mint';
import { buildReceiptWire } from '../crypto/delivery-receipt';
import { buildReceiptSeam, type ReceiptSeamDeps } from './live-book-poll';
import type { OwnerIdentity } from './consume-mailbox';
import type { NoteRecord } from '../messaging/types';
import { NOTE_WIRE_TYPE } from '../messaging/domains';

type Minted = Awaited<ReturnType<typeof mintHeadlessAgent>>;
const idOf = (a: Minted) => a.introduction.card.identity as unknown as {
  fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
const cardOf = (a: Minted) => { const i = idOf(a); return { public_key: i.public_key, pq_kem_public_key: i.pq_kem_public_key, pq_sig_public_key: i.pq_sig_public_key }; };
/** A receipt signed with `signer`'s REAL keys, claiming to come from `claimFp`. */
const receiptFrom = (signer: Minted, claimFp: string, noteId: string, nonce: string) =>
  buildReceiptWire(noteId, nonce, claimFp, signer.secret_material.ed25519Seed, signer.secret_material.mldsa87Secret);

const NOTE_ID = 'note_under_test';
const NONCE = 'nonce-for-note_under_test';

function outbound(toFp: string, over: Partial<NoteRecord> = {}): NoteRecord {
  return {
    note_id: NOTE_ID, thread_id: 'thr_1', direction: 'outbound', from_fingerprint: 'sender', to_fingerprints: [toFp],
    sent_at: '2026-10-25T00:00:00.000Z', body: 'hello', participant_kind: 'human',
    retention: { expires_at: null }, wire_type: NOTE_WIRE_TYPE, receipt_nonce: NONCE, ...over,
  } as NoteRecord;
}

/** Fresh world: S (us, the sender) sent a note to R. S's book holds R's card (and optionally others). */
async function world(opts: { card?: 'R' | 'X' | 'none' | 'classical' | 'garbage'; note?: NoteRecord | 'none' | ((r: string) => NoteRecord) } = {}) {
  const [S, R, X, M] = [await mintHeadlessAgent({ throwaway: true }), await mintHeadlessAgent({ throwaway: true }),
    await mintHeadlessAgent({ throwaway: true }), await mintHeadlessAgent({ throwaway: true })];   // X = another contact, M = an attacker
  const notes = new Map<string, NoteRecord>();
  const written: NoteRecord[] = [];
  const rFp = idOf(R).fingerprint;
  const n = opts.note === 'none' ? null : typeof opts.note === 'function' ? opts.note(rFp) : (opts.note ?? outbound(rFp));
  if (n) notes.set(n.note_id, n);
  const book = new Map<string, Record<string, string>>();
  const which = opts.card ?? 'R';
  if (which === 'R') book.set(rFp, cardOf(R));
  else if (which === 'X') book.set(rFp, cardOf(X));                                                  // R's slot holds a DIFFERENT contact's keys
  else if (which === 'classical') book.set(rFp, { public_key: idOf(R).public_key });                // no PQ legs
  else if (which === 'garbage') book.set(rFp, { ...cardOf(R), pq_kem_public_key: 'AAAA', pq_sig_public_key: '!!notbase64!!' });
  book.set(idOf(X).fingerprint, cardOf(X));
  const deps: ReceiptSeamDeps = {
    getNote: (async (id: string) => notes.get(id) ?? null) as ReceiptSeamDeps['getNote'],
    putNote: (async (note: NoteRecord) => { written.push(note); notes.set(note.note_id, note); }) as ReceiptSeamDeps['putNote'],
    getContactByFingerprint: (async (_owner: string, fp: string) => book.get(fp) ?? null) as ReceiptSeamDeps['getContactByFingerprint'],
  };
  const owner = { fingerprint: idOf(S).fingerprint, publicKeyArmored: idOf(S).public_key, privateKeyArmored: '', passphrase: '' } as OwnerIdentity;
  const seam = buildReceiptSeam(owner, undefined, deps);
  return { S, R, X, M, rFp, notes, written, seam };
}
const delivered = (w: { notes: Map<string, NoteRecord> }) => w.notes.get(NOTE_ID)?.delivered === true;

test('A1: a receipt signed with the recipient\'s card keys → accepted, the note is marked delivered, and that is the ONE write', async () => {
  const w = await world();
  const r = await w.seam.accept(receiptFrom(w.R, w.rFp, NOTE_ID, NONCE));
  assert.deepEqual(r, { note_id: NOTE_ID, thread_id: 'thr_1', from_fingerprint: w.rFp });
  assert.equal(delivered(w), true);
  assert.equal(w.written.length, 1, 'exactly one write');
  assert.equal(w.written[0].delivered, true);
  // a redelivered receipt is harmless (idempotent on note_id)
  assert.ok(await w.seam.accept(receiptFrom(w.R, w.rFp, NOTE_ID, NONCE)));
  assert.equal(delivered(w), true);
});

test('A2: a receipt signed by an ATTACKER\'s keys but claiming to be the recipient → rejected, not delivered', async () => {
  const w = await world();
  assert.equal(await w.seam.accept(receiptFrom(w.M, w.rFp, NOTE_ID, NONCE)), null);
  assert.equal(delivered(w), false);
  assert.equal(w.written.length, 0);
});

test('A2b: a genuine receipt from R, but the card in OUR book under R\'s fingerprint holds a DIFFERENT contact\'s keys → rejected', async () => {
  const w = await world({ card: 'X' });
  assert.equal(await w.seam.accept(receiptFrom(w.R, w.rFp, NOTE_ID, NONCE)), null);
  assert.equal(delivered(w), false);
});

test('A3: wrong nonce, unknown note_id, an INBOUND note_id, or an outbound note with no nonce → rejected', async () => {
  const w = await world();
  assert.equal(await w.seam.accept(receiptFrom(w.R, w.rFp, NOTE_ID, 'a-different-nonce')), null, 'wrong nonce');
  assert.equal(await w.seam.accept(receiptFrom(w.R, w.rFp, 'note_does_not_exist', NONCE)), null, 'unknown note_id');
  assert.equal(delivered(w), false);

  const inbound = await world({ note: (r) => outbound(r, { direction: 'inbound' }) });
  assert.equal(await inbound.seam.accept(receiptFrom(inbound.R, inbound.rFp, NOTE_ID, NONCE)), null, 'inbound note');
  assert.equal(delivered(inbound), false);

  const noNonce = await world({ note: (r) => { const n = outbound(r); delete n.receipt_nonce; return n; } });
  assert.equal(await noNonce.seam.accept(receiptFrom(noNonce.R, noNonce.rFp, NOTE_ID, NONCE)), null, 'sender never opted in (no nonce stored)');
  assert.equal(delivered(noNonce), false);
});

test('A4: a validly-signed receipt whose from_fingerprint is NOT the note\'s recipient (wrong deliverer) → rejected', async () => {
  const w = await world();
  // R's REAL keys sign it (so the signature itself is valid for R's card), but it claims to be from X, not to_fingerprints[0].
  assert.equal(await w.seam.accept(receiptFrom(w.R, idOf(w.X).fingerprint, NOTE_ID, NONCE)), null);
  assert.equal(delivered(w), false);
});

test('A4b: a contact X in OUR book signs a receipt with X\'s own REAL keys and claims to be X, for a note we sent to R → rejected', async () => {
  // The sharp form of the wrong-deliverer case: this receipt VERIFIES perfectly against X's card. The only thing that stops it is
  // that the expected deliverer and the card lookup come from OUR note (to_fingerprints[0] = R), never from the receipt's own claim.
  const w = await world();
  assert.equal(await w.seam.accept(receiptFrom(w.X, idOf(w.X).fingerprint, NOTE_ID, NONCE)), null);
  assert.equal(delivered(w), false);
  assert.equal(w.written.length, 0);
});

test('A5: the recipient has been removed from our book → no card to verify against → rejected (floor holds)', async () => {
  const w = await world({ card: 'none' });
  assert.equal(await w.seam.accept(receiptFrom(w.R, w.rFp, NOTE_ID, NONCE)), null);
  assert.equal(delivered(w), false);
});

test('A6: a classical (no-PQ) contact, or a card with malformed PQ keys → rejected (no signing key to verify against)', async () => {
  const classical = await world({ card: 'classical' });
  assert.equal(await classical.seam.accept(receiptFrom(classical.R, classical.rFp, NOTE_ID, NONCE)), null, 'classical contact');
  assert.equal(delivered(classical), false);
  const garbage = await world({ card: 'garbage' });
  assert.equal(await garbage.seam.accept(receiptFrom(garbage.R, garbage.rFp, NOTE_ID, NONCE)), null, 'malformed card keys');
  assert.equal(delivered(garbage), false);
});

test('structure: `delivered: true` is written on exactly ONE line of non-test source, and only after verifyReceiptWire returned true', () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'live-book-poll.ts'), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');                   // code only
  assert.equal((src.match(/delivered: *true/g) ?? []).length, 1);
  const iVerify = src.indexOf('verifyReceiptWire(');
  const iGuard = src.indexOf('if (!ok) return null', iVerify);
  const iWrite = src.indexOf('delivered: true');
  assert.ok(iVerify > 0 && iGuard > iVerify && iWrite > iGuard, 'verify → reject-if-not-ok → the single write, in that order');
});
