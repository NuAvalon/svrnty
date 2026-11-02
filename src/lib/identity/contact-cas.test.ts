// Compare-and-swap for a contact write, over an in-memory store whose commit uses the real compare rule (sameStoredRow). The interleavings are
// forced with a hook that runs another writer between a write's reads and its commit. Real IndexedDB behaviour is NOT covered here: see the
// browser run (e2e/contact-cas.spec.ts) and commitIfUnchanged's own test.
//
// Run: npx tsx --test src/lib/identity/contact-cas.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  casUpdateWith, sameStoredRow, ContactConflictError, CAS_MAX_ATTEMPTS,
} from './contact-cas';
import { readFileSync } from 'node:fs';
import { World, rec, addTag, world } from './contact-cas-testkit';

// ── the happy path and the null decision ────────────────────────────────────────────────────────────────────

test('an uncontended update applies on the first attempt and keeps the manifest consistent', async () => {
  const w = world('a', 'b');
  const r = await casUpdateWith(w.io(), 'a', (e) => ({ ...e, n: e.n + 1, version: 1 }));
  assert.deepEqual(r, { applied: true, attempts: 1 });
  assert.equal(w.get('a').n, 1);
  assert.equal(w.manifestConsistent(), true);
});

test('a missing contact is "Contact not found" and nothing is written', async () => {
  const w = world('a');
  await assert.rejects(() => casUpdateWith(w.io(), 'zzz', (e) => e), /Contact not found/);
  assert.equal(w.commits, 0);
});

test('a null decision writes nothing, is not a conflict, and does not call finalize', async () => {
  const w = world('a');
  const before = JSON.stringify([...w.contacts.entries()]);
  const r = await casUpdateWith(w.io(), 'a', () => null);
  assert.deepEqual(r, { applied: false, attempts: 1 });
  assert.equal(JSON.stringify([...w.contacts.entries()]), before);
  assert.equal(w.finalizeCalls.length, 0);
  assert.equal(w.commits, 0);
});

// ── the lost update ─────────────────────────────────────────────────────────────────────────────────────────

test('two writers to the SAME contact: both effects survive, the loser decided again on the newer record', async () => {
  const w = world('a');
  const b = w.io();
  let aRuns = 0;
  // A reads, then B completes its whole update, then A tries to commit.
  const aIo = w.io([async () => { await casUpdateWith(b, 'a', addTag('from-b')); }]);
  const a = await casUpdateWith(aIo, 'a', (e) => { aRuns++; return addTag('from-a')(e); });
  assert.deepEqual(w.get('a').tags.sort(), ['from-a', 'from-b']);
  assert.equal(a.attempts, 2);
  assert.equal(aRuns, 2, 'the update function ran once per attempt, and the second run saw B\'s change');
  assert.equal(w.manifestConsistent(), true);
});

test('the update function sees the NEWER record on the retry', async () => {
  const w = world('a');
  const b = w.io();
  const seen: number[] = [];
  const aIo = w.io([async () => { await casUpdateWith(b, 'a', (e) => ({ ...e, n: 41 })); }]);
  await casUpdateWith(aIo, 'a', (e) => { seen.push(e.n); return { ...e, n: e.n + 1 }; });
  assert.deepEqual(seen, [0, 41]);
  assert.equal(w.get('a').n, 42);
});

// ── the manifest ────────────────────────────────────────────────────────────────────────────────────────────

test('a version bump of ANOTHER contact between the reads and the commit changes the manifest: the write retries and the manifest ends consistent', async () => {
  const w = world('a', 'b');
  const other = w.io();
  const io = w.io([async () => { await casUpdateWith(other, 'b', (e) => ({ ...e, version: 7 })); }]);
  const r = await casUpdateWith(io, 'a', (e) => ({ ...e, version: 1 }));
  assert.equal(r.attempts, 2);
  assert.equal(w.get('a').version, 1);
  assert.equal(w.get('b').version, 7);
  assert.equal(w.manifestConsistent(), true, 'the manifest covers both new versions');
});

test('a contact ADDED between the reads and the commit also forces a retry (the manifest changed)', async () => {
  const w = world('a');
  const io = w.io([async () => { w.put(rec('c')); }]);
  const r = await casUpdateWith(io, 'a', (e) => ({ ...e, n: 1 }));
  assert.equal(r.attempts, 2);
  assert.equal(w.manifestConsistent(), true);
});

test('an edit of another contact that does not change its version leaves the manifest alone: no conflict', async () => {
  const w = world('a', 'b');
  const other = w.io();
  const io = w.io([async () => { await casUpdateWith(other, 'b', (e) => ({ ...e, n: 99 })); }]); // same version
  const r = await casUpdateWith(io, 'a', (e) => ({ ...e, n: 1 }));
  assert.equal(r.attempts, 1);
  assert.equal(w.get('b').n, 99);
  assert.equal(w.manifestConsistent(), true);
});

test('a first manifest created between the reads and the commit forces a retry (absent -> present)', async () => {
  const w = new World();
  w.contacts.set('a', w.seal(rec('a')));             // a contact with NO manifest yet
  const io = w.io([async () => { w.settings.set('contact_manifest:o', w.manifestOf(w.all())); }]);
  const r = await casUpdateWith(io, 'a', (e) => ({ ...e, n: 1 }));
  assert.equal(r.attempts, 2);
});

// ── bounded retry ───────────────────────────────────────────────────────────────────────────────────────────

test('a writer that wins every comparison makes the write throw ContactConflictError after the cap, with nothing written', async () => {
  const w = world('a');
  const rival = w.io();
  const hooks = Array.from({ length: CAS_MAX_ATTEMPTS }, () => async () => { await casUpdateWith(rival, 'a', (e) => ({ ...e, n: e.n + 1 })); });
  const io = w.io(hooks);
  let runs = 0;
  const commitsBefore = w.commits;
  await assert.rejects(
    () => casUpdateWith(io, 'a', (e) => { runs++; return { ...e, tags: [...e.tags, 'mine'] }; }),
    (e: unknown) => e instanceof ContactConflictError && e.attempts === CAS_MAX_ATTEMPTS && e.contactId === 'a',
  );
  assert.equal(runs, CAS_MAX_ATTEMPTS);
  assert.equal(w.get('a').tags.includes('mine'), false, 'the losing write left no trace');
  assert.equal(w.commits - commitsBefore, CAS_MAX_ATTEMPTS, 'only the competing writer committed');
  assert.equal(w.manifestConsistent(), true);
});

test('losing fewer than the cap times still lands', async () => {
  const w = world('a');
  const rival = w.io();
  const hooks = Array.from({ length: CAS_MAX_ATTEMPTS - 1 }, () => async () => { await casUpdateWith(rival, 'a', (e) => ({ ...e, n: e.n + 1 })); });
  const r = await casUpdateWith(w.io(hooks), 'a', addTag('mine'));
  assert.equal(r.attempts, CAS_MAX_ATTEMPTS);
  assert.equal(w.get('a').tags.includes('mine'), true);
  assert.equal(w.get('a').n, CAS_MAX_ATTEMPTS - 1);
});

test('the cap is configurable and 1 means a single attempt', async () => {
  const w = world('a');
  const rival = w.io();
  const io = w.io([async () => { await casUpdateWith(rival, 'a', (e) => ({ ...e, n: 5 })); }]);
  await assert.rejects(() => casUpdateWith(io, 'a', (e) => ({ ...e, n: 6 }), 1), ContactConflictError);
});

test('a null decision on a retry is not a conflict and ends the call without error', async () => {
  const w = world('a');
  const rival = w.io();
  const io = w.io([async () => { await casUpdateWith(rival, 'a', (e) => ({ ...e, n: 1 })); }]);
  // first attempt wants to write; after the competitor, the newer record no longer calls for it
  const r = await casUpdateWith(io, 'a', (e) => (e.n >= 1 ? null : { ...e, n: 1 }));
  assert.deepEqual(r, { applied: false, attempts: 2 });
  assert.equal(w.get('a').n, 1);
});

test('the cap is the ruled value: five attempts', () => {
  assert.equal(CAS_MAX_ATTEMPTS, 5);
});

test('each attempt reads the contact exactly ONCE, at its start: the compare is against that read, not a later one', async () => {
  const w = world('a');
  let reads = 0;
  const counting = (hooks: Array<() => Promise<void>> = []) => {
    const io = w.io(hooks);
    const orig = io.readRaw;
    io.readRaw = async (id) => { reads++; return orig(id); };
    return io;
  };
  await casUpdateWith(counting(), 'a', (e) => ({ ...e, n: 1 }));
  assert.equal(reads, 1, 'an uncontended write reads once');
  reads = 0;
  const rival = w.io();
  const r = await casUpdateWith(counting([async () => { await casUpdateWith(rival, 'a', (e) => ({ ...e, n: 50 })); }]), 'a', (e) => ({ ...e, n: e.n + 1 }));
  assert.equal(r.attempts, 2);
  assert.equal(reads, 2, 'one conflict means exactly two attempts, one read each');
});

// ── the gates ───────────────────────────────────────────────────────────────────────────────────────────────

test('finalize (the gates) runs on every attempt against the record that attempt decided from', async () => {
  const w = world('a');
  const rival = w.io();
  const io = w.io([async () => { w.finalizeCalls = []; await casUpdateWith(rival, 'a', (e) => ({ ...e, n: 10 })); }]);
  const seenByA: Array<{ existingN: number; nextN: number }> = [];
  const inner = io.finalize;
  io.finalize = async (existing, next) => { seenByA.push({ existingN: existing.n, nextN: next.n }); return inner(existing, next); };
  await casUpdateWith(io, 'a', (e) => ({ ...e, n: e.n + 1 }));
  assert.deepEqual(seenByA, [{ existingN: 0, nextN: 1 }, { existingN: 10, nextN: 11 }]);
});

test('a gate that refuses throws and nothing is written', async () => {
  const w = world('a');
  w.finalizeError = new Error('verify-before-trust: refused');
  const commitsBefore = w.commits;
  await assert.rejects(() => casUpdateWith(w.io(), 'a', (e) => ({ ...e, trust: 'trusted' })), /verify-before-trust/);
  assert.equal(w.commits, commitsBefore);
  assert.equal(w.get('a').trust, undefined);
});

test('a non-conflict error from the update function propagates at once, without retrying', async () => {
  const w = world('a');
  let runs = 0;
  await assert.rejects(() => casUpdateWith(w.io(), 'a', () => { runs++; throw new Error('bad patch'); }), /bad patch/);
  assert.equal(runs, 1);
});

// ── the purity contract ─────────────────────────────────────────────────────────────────────────────────────

test('CONTRACT: an update function runs once per attempt, so a side effect inside it happens more than once under contention', async () => {
  const w = world('a');
  const rival = w.io();
  const io = w.io([async () => { await casUpdateWith(rival, 'a', (e) => ({ ...e, n: 1 })); }]);
  const outer: string[] = [];
  await casUpdateWith(io, 'a', (e) => { outer.push('ran'); return { ...e, tags: [...e.tags, 'x'] }; });
  assert.deepEqual(outer, ['ran', 'ran'], 'a push into an outer array is repeated: such an update function is forbidden');
});

// ── sameStoredRow ───────────────────────────────────────────────────────────────────────────────────────────

test('sameStoredRow: absent equals absent, absent never equals a row', () => {
  assert.equal(sameStoredRow(null, null), true);
  assert.equal(sameStoredRow(null, { id: 'a' }), false);
  assert.equal(sameStoredRow({ id: 'a' }, null), false);
});

test('sameStoredRow: an encrypted envelope is the same only if iv AND ciphertext are the same', () => {
  const e = { id: 'a', enc_version: 1, iv: 'i1', ciphertext: 'c1' };
  assert.equal(sameStoredRow(e, { ...e }), true);
  assert.equal(sameStoredRow(e, { ...e, iv: 'i2' }), false);
  assert.equal(sameStoredRow(e, { ...e, ciphertext: 'c2' }), false);
  assert.equal(sameStoredRow(e, { id: 'a', iv: 'i1', ciphertext: 'c1' }), false, 'an unencrypted row never equals an envelope');
});

test('sameStoredRow: other rows (the manifest, a legacy contact) compare by content', () => {
  assert.equal(sameStoredRow({ key: 'k', value: 'mac1' }, { key: 'k', value: 'mac1' }), true);
  assert.equal(sameStoredRow({ key: 'k', value: 'mac1' }, { key: 'k', value: 'mac2' }), false);
});

test('ContactConflictError carries the contact and the attempts and is an Error', () => {
  const e = new ContactConflictError('c1', 5);
  assert.ok(e instanceof Error);
  assert.equal(e.name, 'ContactConflictError');
  assert.equal(e.contactId, 'c1');
  assert.equal(e.attempts, 5);
});

// ── the store's two entry points (static: they sit behind IndexedDB, exercised in the Chromium run) ────────

test('GUARD: updateContact and updateContactIf both go through casUpdateWith, decide through the pure merge, and report applied from the CAS result', () => {
  const store = readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8').replace(/^\s*\/\/.*$/gm, '');
  assert.match(store, /await casUpdateWith\(contactCasIO, id, \(existing\) => mergeContactUpdate\(existing, updates\)\);/);
  assert.match(store, /const r = await casUpdateWith\(contactCasIO, id, \(existing\) => \{\s*const patch = decide\(existing\);\s*return patch === null \? null : mergeContactUpdate\(existing, patch\);\s*\}\);\s*return \{ applied: r\.applied \};/);
  assert.match(store, /assertUnlockedForContactWrite\('updateContact'\)/);
  assert.match(store, /assertUnlockedForContactWrite\('updateContactIf'\)/);
});
