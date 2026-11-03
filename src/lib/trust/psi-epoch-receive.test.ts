// The receive path for a sealed epoch package, with real note crypto and the real adoption rule over an in-memory store.
// Run: npx tsx --test src/lib/trust/psi-epoch-receive.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { buildEpochNote } from './psi-epoch-note';
import { buildEpochSealedPlaintext } from './psi-epoch-sealed';
import { maxEpochFor, restoreEpochRecord } from './psi-epoch-book';
import { receiveEpochNote, PSI_TICK_MINUTES, type EpochContact, type EpochReceiveDeps } from './psi-epoch-receive';
import { buildPsiEpochAdoption, type ContactRecord } from '../identity/client-store';

const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const OWNER = sha('owner');
const X = sha('friend-x');
const Y = sha('friend-y');
const secretOf = (seed: number) => Uint8Array.from({ length: 32 }, (_, i) => (seed + i) % 256);
const S_X = secretOf(11);
const S_Y = secretOf(77);
const NOW = 29_000_000;
const E = (m: number, seq = 0) => m * 2 ** 20 + seq;
const field = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (n + i) % 256);

function note(args: { from?: string; sPair?: Uint8Array; epoch?: number; know?: number; trust?: number; claim?: string }): Uint8Array {
  const from = args.from ?? X;
  const wire = buildEpochNote({
    sPair: args.sPair ?? S_X, fpSender: from, fpReceiver: OWNER, epoch: args.epoch ?? E(NOW, 1), know: field(args.know ?? 1), trust: field(args.trust ?? 2),
  });
  return buildEpochSealedPlaintext(wire, args.claim ?? from);
}

function world(opts: { blocked?: boolean; storeBlocked?: boolean; held?: string; adoptThrows?: boolean; findOverride?: EpochContact | null; secret?: Uint8Array | null; on?: boolean } = {}) {
  const calls: string[] = [];
  const records = new Map<string, ContactRecord>();
  records.set('cx', { id: 'cx', owner_fingerprint: OWNER, fingerprint: X, name: 'X', email: '', public_key: 'k', trust_level: 'unverified', added_at: 't',
    ...(opts.storeBlocked ? { blocked: true } : {}), ...(opts.held !== undefined ? { psi_epoch: opts.held } : {}) } as ContactRecord);
  const book = new Map<string, EpochContact>([[X, { id: 'cx', fingerprint: X, blocked: opts.blocked === true }], [Y, { id: 'cy', fingerprint: Y, blocked: false }]]);
  let clock = 0;
  const deps: EpochReceiveDeps = {
    receiveOn: opts.on !== false,
    ownerFp: OWNER,
    findContact: async (fp) => { calls.push('find'); return opts.findOverride !== undefined ? opts.findOverride : book.get(fp) ?? null; },
    pairSecretFor: async (id) => { calls.push('secret'); return opts.secret !== undefined ? opts.secret : id === 'cx' ? S_X : id === 'cy' ? S_Y : null; },
    nowMinutes: () => { clock++; calls.push('now'); return NOW; },
    adopt: async (id, decide) => {
      calls.push('adopt');
      if (opts.adoptThrows) throw new Error('conflict');
      const rec = records.get(id) as ContactRecord;
      const next = buildPsiEpochAdoption(rec, decide);
      if (next === null) return { applied: false };
      records.set(id, next);
      return { applied: true };
    },
  };
  return { deps, calls, records, clockReads: () => clock, held: () => (records.get('cx') as ContactRecord).psi_epoch as string | undefined };
}

test('not an epoch package: not-epoch, and nothing is called', async () => {
  const w = world();
  assert.deepEqual(await receiveEpochNote(new Uint8Array(138), w.deps), { kind: 'not-epoch' });
  assert.deepEqual(await receiveEpochNote(new Uint8Array(10), w.deps), { kind: 'not-epoch' });
  assert.deepEqual(w.calls, []);
});

test('F1 off: benign ack for an epoch note AND for a malformed one; the book, the secret, the clock and the store are never touched', async () => {
  const w = world({ on: false });
  assert.deepEqual(await receiveEpochNote(note({}), w.deps), { kind: 'benign-ack' });
  const malformed = note({}).slice(0, 120);
  assert.deepEqual(await receiveEpochNote(malformed, w.deps), { kind: 'benign-ack' });
  assert.deepEqual(w.calls, []);
});

test('F1 on, malformed (the header with another length): unverified, nothing is called', async () => {
  const w = world();
  assert.deepEqual(await receiveEpochNote(note({}).slice(0, 137), w.deps), { kind: 'unverified' });
  assert.deepEqual(w.calls, []);
});

test('a claimed sender not in the book: UNVERIFIED, the pairwise secret is never derived, nothing is written', async () => {
  const w = world();
  const stranger = sha('stranger');
  assert.deepEqual(await receiveEpochNote(note({ from: stranger, claim: stranger }), w.deps), { kind: 'unverified' });
  assert.deepEqual(w.calls, ['find']);
});

test('EXACT lookup: a store that answers with a contact whose fingerprint is only a prefix or a respelling of the claim does not make a sender', async () => {
  for (const loose of [{ id: 'cx', fingerprint: X.slice(0, 40), blocked: false }, { id: 'cx', fingerprint: X.toUpperCase(), blocked: false }, { id: 'cx', fingerprint: X + '0', blocked: false }]) {
    const w = world({ findOverride: loose });
    assert.deepEqual(await receiveEpochNote(note({}), w.deps), { kind: 'unverified' }, loose.fingerprint.length + '/' + loose.fingerprint.slice(0, 3));
    assert.deepEqual(w.calls, ['find']);
  }
});

test('a blocked contact is dropped BEFORE any secret is derived or MAC checked, and nothing is written', async () => {
  const w = world({ blocked: true });
  assert.deepEqual(await receiveEpochNote(note({}), w.deps), { kind: 'blocked-drop' });
  assert.deepEqual(w.calls, ['find']);
  assert.equal(w.held(), undefined);
});

test('a good note is adopted and stored; the same note again is already-held; an older epoch is already-held; the same epoch with other bytes is a conflict', async () => {
  const w = world();
  assert.deepEqual(await receiveEpochNote(note({ epoch: E(NOW, 5), know: 1, trust: 2 }), w.deps), { kind: 'adopted' });
  const rec = restoreEpochRecord(w.held());
  assert.equal(rec?.cur.e, E(NOW, 5));
  assert.equal(rec?.prev, null);
  assert.deepEqual(await receiveEpochNote(note({ epoch: E(NOW, 5), know: 1, trust: 2 }), w.deps), { kind: 'already-held' });
  assert.deepEqual(await receiveEpochNote(note({ epoch: E(NOW, 4), know: 3, trust: 4 }), w.deps), { kind: 'already-held' });
  assert.deepEqual(await receiveEpochNote(note({ epoch: E(NOW, 5), know: 9, trust: 10 }), w.deps), { kind: 'conflict' });
  assert.equal(restoreEpochRecord(w.held())?.cur.e, E(NOW, 5), 'neither the older nor the conflicting one replaced it');
  assert.deepEqual(await receiveEpochNote(note({ epoch: E(NOW, 6), know: 5, trust: 6 }), w.deps), { kind: 'adopted' });
  const next = restoreEpochRecord(w.held());
  assert.equal(next?.cur.e, E(NOW, 6));
  assert.equal(next?.prev?.e, E(NOW, 5), 'the earlier epoch is kept as prev');
});

test('a bad MAC (a flipped tag byte, or a wrong pairwise secret) is bad-mac, and nothing is written', async () => {
  const tampered = note({});
  tampered[105] ^= 1;
  const w = world();
  assert.deepEqual(await receiveEpochNote(tampered, w.deps), { kind: 'bad-mac' });
  assert.equal(w.held(), undefined);
  const w2 = world({ secret: secretOf(200) });
  assert.deepEqual(await receiveEpochNote(note({}), w2.deps), { kind: 'bad-mac' });
});

test('REPLAY: X\'s valid note re-sealed claiming to be Y is bad-mac, whether or not the two pairwise secrets differ (the tag binds both fingerprints)', async () => {
  const fromX = note({});
  const claimingY = buildEpochSealedPlaintext(fromX.slice(0, 106), Y);
  const w = world();
  assert.deepEqual(await receiveEpochNote(claimingY, w.deps), { kind: 'bad-mac' });
  // even if Y's pairwise secret were the same as X's, the tag was made for sender X, so it does not verify for sender Y
  const sameSecret = world({ secret: S_X });
  assert.deepEqual(await receiveEpochNote(claimingY, sameSecret.deps), { kind: 'bad-mac' });
  assert.equal(sameSecret.held(), undefined);
});

test('no way to derive the pairwise secret, or an own fingerprint that cannot form the context: UNVERIFIED (never a bad-MAC record), nothing written', async () => {
  const w = world({ secret: null });
  assert.deepEqual(await receiveEpochNote(note({}), w.deps), { kind: 'unverified' });
  const w2 = world();
  assert.deepEqual(await receiveEpochNote(note({}), { ...w2.deps, ownerFp: 'not-a-fingerprint' }), { kind: 'unverified' });
  assert.equal(w.held(), undefined);
});

test('an epoch above what this clock allows is out-of-range and writes nothing; exactly at the bound is adopted', async () => {
  const bound = maxEpochFor(NOW);
  const w = world();
  assert.deepEqual(await receiveEpochNote(note({ epoch: bound + 1 }), w.deps), { kind: 'out-of-range' });
  assert.equal(w.held(), undefined);
  assert.deepEqual(await receiveEpochNote(note({ epoch: bound }), w.deps), { kind: 'adopted' });
});

test('the clock is read once per accepted note, and the tick is its 5-minute unit', async () => {
  assert.equal(PSI_TICK_MINUTES, 5);
  const w = world();
  await receiveEpochNote(note({}), w.deps);
  assert.equal(w.clockReads(), 1);
  const rec = restoreEpochRecord(w.held());
  assert.equal(rec?.adoptedTick, Math.floor(NOW / 5));
});

test('a block that lands between the lookup and the write: the store refuses (the decision is never asked) and the result is blocked-drop', async () => {
  const w = world({ storeBlocked: true });
  assert.deepEqual(await receiveEpochNote(note({}), w.deps), { kind: 'blocked-drop' });
  assert.equal(w.held(), undefined);
});

test('a store that cannot take the write now (a conflict, a lock timeout) is retry', async () => {
  const w = world({ adoptThrows: true });
  assert.deepEqual(await receiveEpochNote(note({}), w.deps), { kind: 'retry' });
});

test('a decision that said "adopted" but a write that did not happen is retry, never adopted', async () => {
  const w = world();
  const noWrite: EpochReceiveDeps = {
    ...w.deps,
    adopt: async (_id, decide) => {
      decide(null, { id: 'cx' } as ContactRecord); // the decision runs and says "adopt", then the store reports that it wrote nothing
      return { applied: false };
    },
  };
  assert.deepEqual(await receiveEpochNote(note({}), noWrite), { kind: 'retry' });
  assert.equal(w.held(), undefined);
});

test('a stored form that no longer restores counts as no record: the note is adopted over it', async () => {
  const w = world({ held: 'not-json' });
  assert.deepEqual(await receiveEpochNote(note({}), w.deps), { kind: 'adopted' });
  assert.notEqual(restoreEpochRecord(w.held()), null);
});

test('GUARD: the receive path never names the epoch field', () => {
  const src = readFileSync(new URL('./psi-epoch-receive.ts', import.meta.url), 'utf8').replace(/^\s*(\/\/|\*|\/\*).*$/gm, '');
  assert.doesNotMatch(src, /psi_epoch|PSI_EPOCH_FIELD/);
});
