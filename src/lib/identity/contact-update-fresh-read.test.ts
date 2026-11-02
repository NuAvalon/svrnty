// A write that builds a value from a nested field (metadata, tags, a history list) must build it from the record the store holds when the write
// runs, not from a copy captured earlier (a dialog opened minutes ago, a list loaded before a loop, a second tab).
//
// updateContact therefore accepts a SYNCHRONOUS function of the record it just read. These tests cover the pure merge it uses, the three-way
// merge of share settings, and (as static guards, the style of verify-before-trust.test.ts, since the repo has no IndexedDB harness) that the
// converted write sites do not go back to spreading a captured `metadata`.
//
// Run: npx tsx --test src/lib/identity/contact-update-fresh-read.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mergeContactUpdate, clearOpenVisibilityIfUntrusted, type ContactRecord } from './client-store';
import { applyShareSettingsChange, defaultShareSettings, SHARE_SETTING_KEYS, type ContactShareSettings } from '@/lib/contacts/contact-lane';

const rec = (o: Record<string, unknown> = {}): ContactRecord =>
  ({ id: 'c1', owner_fingerprint: 'o', fingerprint: 'f', name: 'n', email: 'e', public_key: 'k', added_at: 'a', ...o }) as unknown as ContactRecord;
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

// ── mergeContactUpdate ──────────────────────────────────────────────────────────────────────────────────────

test('an object patch merges over the held record and cannot change the id', () => {
  const out = mergeContactUpdate(rec({ name: 'old' }), { name: 'new', id: 'other' } as Partial<ContactRecord>);
  assert.equal(out.name, 'new');
  assert.equal(out.id, 'c1', 'the id is the held record\'s');
  assert.equal(out.email, 'e');
});

test('a function updater is called ONCE with the held record, and its patch is merged over it', () => {
  const held = rec({ metadata: { tags: ['a'] } });
  const seen: ContactRecord[] = [];
  const out = mergeContactUpdate(held, (existing) => {
    seen.push(existing);
    return { name: 'renamed' };
  });
  assert.equal(seen.length, 1);
  assert.equal(seen[0], held, 'the exact held object is passed, not a copy captured earlier');
  assert.equal(out.name, 'renamed');
  assert.deepEqual(out.metadata, { tags: ['a'] });
});

test('a metadata change built from the HELD record keeps what changed since a stale copy was taken', () => {
  const stale = rec({ metadata: { tags: ['a'], share_settings: { open_visibility: true } } });
  const held = rec({ metadata: { tags: ['a'], share_settings: { open_visibility: false }, owner_verified_at: 't' } }); // changed elsewhere since
  // the old shape: spread the captured copy
  const old = mergeContactUpdate(held, { metadata: { ...stale.metadata, tags: ['a', 'b'] } });
  assert.equal(old.metadata.share_settings.open_visibility, true, 'the captured copy WRITES BACK the old value (the bug)');
  assert.equal(old.metadata.owner_verified_at, undefined, 'and drops a key added since');
  // the function shape: build from the held record
  const fresh = mergeContactUpdate(held, (f) => ({ metadata: { ...f.metadata, tags: ['a', 'b'] } }));
  assert.equal(fresh.metadata.share_settings.open_visibility, false, 'the setting changed since survives');
  assert.equal(fresh.metadata.owner_verified_at, 't');
  assert.deepEqual(fresh.metadata.tags, ['a', 'b']);
});

test('an updater that is async, or returns anything but a plain object, is refused', () => {
  const held = rec();
  const asyncUpdater = (async () => ({ name: 'x' })) as unknown as (e: ContactRecord) => Partial<ContactRecord>;
  assert.throws(() => mergeContactUpdate(held, asyncUpdater), /synchronously return a plain patch object/);
  for (const bad of [undefined, null, 'x', 5, [], Promise.resolve({})]) {
    assert.throws(() => mergeContactUpdate(held, (() => bad) as unknown as (e: ContactRecord) => Partial<ContactRecord>), /plain patch object/, String(bad));
  }
  assert.throws(() => mergeContactUpdate(held, (() => ({ then: () => {} })) as unknown as (e: ContactRecord) => Partial<ContactRecord>), /plain patch object/, 'a thenable');
});

test('an updater that throws propagates, and the merge never mutates the held record', () => {
  const held = rec({ metadata: { tags: ['a'] } });
  const before = clone(held);
  assert.throws(() => mergeContactUpdate(held, () => { throw new Error('boom'); }), /boom/);
  mergeContactUpdate(held, (f) => ({ metadata: { ...f.metadata, tags: ['z'] } }));
  mergeContactUpdate(held, { name: 'q' });
  assert.deepEqual(held, before);
});

// ── share settings: only what the owner changed is applied, on top of what is held ──────────────────────────

const S = (o: Partial<ContactShareSettings> = {}): ContactShareSettings => ({ ...defaultShareSettings(), ...o });

test('only the keys the owner CHANGED are applied; a setting changed elsewhere since survives', () => {
  const seen = S({ open_visibility: false, per_contact_private: false });
  const next = S({ open_visibility: true, per_contact_private: false }); // the owner turned open_visibility on
  const held = { ...S(), per_contact_private: true, share_groups: true }; // elsewhere: private on, groups on
  const out = applyShareSettingsChange(held, seen, next, true);
  assert.equal(out.open_visibility, true, 'the owner\'s change');
  assert.equal(out.per_contact_private, true, 'the change made elsewhere is not written back to what the screen showed');
  assert.equal(out.share_groups, true);
});

test('a go-private (open_visibility true -> false) is applied on top of the held settings', () => {
  const seen = S({ open_visibility: true });
  const next = S({ open_visibility: false });
  const out = applyShareSettingsChange(S({ open_visibility: true, share_trusted_circle: true }), seen, next, true);
  assert.equal(out.open_visibility, false);
  assert.equal(out.share_trusted_circle, true);
});

test('no change by the owner stores the held settings as they are', () => {
  const held = S({ per_contact_private: true, share_card: false });
  assert.deepEqual(applyShareSettingsChange(held, S(), S(), true), held);
  assert.deepEqual(applyShareSettingsChange(null, S(), S(), true), S());
  assert.deepEqual(applyShareSettingsChange(undefined, S(), S(), false), S());
});

test('the trusted-only clamp: on an edge that is not trusted open_visibility is stored false, whatever was chosen or held', () => {
  const seen = S();
  const next = S({ open_visibility: true });
  assert.equal(applyShareSettingsChange(S(), seen, next, false).open_visibility, false);
  assert.equal(applyShareSettingsChange(S({ open_visibility: true }), seen, S(), false).open_visibility, false, 'held true on an untrusted edge is clamped too');
  assert.equal(applyShareSettingsChange(S(), seen, next, true).open_visibility, true);
  assert.equal(applyShareSettingsChange(S(), seen, next, false).per_contact_private, false, 'the clamp touches only open_visibility');
});

test('SHARE_SETTING_KEYS lists every setting, so a new one cannot be missed by the merge', () => {
  assert.deepEqual([...SHARE_SETTING_KEYS].sort(), Object.keys(defaultShareSettings()).sort());
  assert.ok(SHARE_SETTING_KEYS.length >= 5);
});

// ── the unlock privacy sweep's decision, on the record held when it writes ───────────────────────────────────

const openRec = (o: Record<string, unknown> = {}) => rec({ trust_level: 'unverified', metadata: { notes: 'n', share_settings: { open_visibility: true, per_contact_private: true } }, ...o });

test('sweep: an untrusted contact that carries open_visibility gets it cleared, and every other setting and metadata key is kept', () => {
  const out = clearOpenVisibilityIfUntrusted(openRec());
  const md = out.metadata as { notes: string; share_settings: Record<string, unknown> };
  assert.equal(md.share_settings.open_visibility, false);
  assert.equal(md.share_settings.per_contact_private, true);
  assert.equal(md.notes, 'n');
});

test('sweep: nothing to do (an EMPTY patch) when the contact is trusted, or is already private, or has no settings', () => {
  assert.deepEqual(clearOpenVisibilityIfUntrusted(openRec({ trust_level: 'trusted' })), {});
  assert.deepEqual(clearOpenVisibilityIfUntrusted(openRec({ trust_level: 'verified' })), {});
  assert.deepEqual(clearOpenVisibilityIfUntrusted(openRec({ metadata: { share_settings: { open_visibility: false } } })), {});
  assert.deepEqual(clearOpenVisibilityIfUntrusted(openRec({ metadata: {} })), {});
  assert.deepEqual(clearOpenVisibilityIfUntrusted(rec()), {});
});

test('sweep: an explicit trusted:false WINS over trust_level (the reveal derivation), and trusted:true over an unverified level', () => {
  assert.ok('metadata' in clearOpenVisibilityIfUntrusted(openRec({ trust_level: 'trusted', trusted: false })), 'explicitly untrusted: cleared');
  assert.deepEqual(clearOpenVisibilityIfUntrusted(openRec({ trust_level: 'unverified', trusted: true })), {}, 'explicitly trusted: kept');
});

test('sweep: the decision uses the record it is given, so a change since an earlier snapshot wins', () => {
  const snapshot = openRec(); // untrusted and open when the sweep first looked
  assert.ok('metadata' in clearOpenVisibilityIfUntrusted(snapshot));
  const heldNow = openRec({ trust_level: 'trusted' }); // the owner trusted the contact since
  assert.deepEqual(mergeContactUpdate(heldNow, clearOpenVisibilityIfUntrusted).metadata, heldNow.metadata, 'applied to the held record it changes nothing');
});

test('sweep: it never mutates the record it is given', () => {
  const r = openRec();
  const before = clone(r);
  clearOpenVisibilityIfUntrusted(r);
  assert.deepEqual(r, before);
});

// ── static guards: the converted write sites build from the held record ─────────────────────────────────────

const src = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');

test('GUARD: ContactManagement spreads no captured metadata into an update (tags, share settings, bulk loops)', () => {
  const ui = src('../../components/ContactManagement.tsx');
  assert.doesNotMatch(ui, /metadata:\s*\{\s*\.\.\.(selectedContact|c|contact)\??\.metadata/, 'a captured metadata is spread into an update');
  assert.match(ui, /applyShareSettingsChange\(/, 'the share-settings handler merges only what changed');
  assert.equal((ui.match(/updateContact\([^,]+,\s*\(fresh\)\s*=>/g) ?? []).length >= 5, true, 'toggle group, share settings and the three bulk loops use the function form');
});

test('GUARD: the unlock sweep and break-trust build from the held record', () => {
  const store = src('./client-store.ts');
  assert.match(store, /updateContact\(c\.id, clearOpenVisibilityIfUntrusted\)/, 'the privacy sweep decides again on the record held when it writes');
  assert.match(store, /const next = mergeContactUpdate\(existing, updates\);/, 'updateContact merges through the pure helper');
  assert.doesNotMatch(store, /const next = \{ \.\.\.existing, \.\.\.updates, id: existing\.id \};/, 'the inline merge is gone');
  const trust = src('../trust/apply-trust-transition.ts');
  assert.doesNotMatch(trust, /\.\.\.\(peer\.priorTrustHistory/, 'break-trust no longer appends to the history copy `peer` carried');
  assert.doesNotMatch(trust, /\.\.\.\(peer\.metadata/, 'break-trust no longer spreads the metadata copy `peer` carried');
});
