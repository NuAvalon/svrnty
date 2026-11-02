// The edit form, owner verification, block and link writes decide from the record the store holds when the write runs. Each test holds a record
// that differs from the copy a screen would have carried, and checks that what the store has now is what survives.
//
// Run: npx tsx --test src/lib/contacts/metadata-patches.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { editFormPatch, ownerVerifyHeldPatch, blockPatch, linkHeldPatch } from './metadata-patches';
import type { ContactRecord } from '@/lib/identity/client-store';

const rec = (o: Record<string, unknown> = {}): ContactRecord =>
  ({ id: 'c1', owner_fingerprint: 'o', fingerprint: 'f', name: 'n', email: 'e', public_key: 'k', added_at: 'a', ...o }) as unknown as ContactRecord;
const meta = (p: Partial<ContactRecord>) => p.metadata as Record<string, unknown>;

// ── editFormPatch ───────────────────────────────────────────────────────────────────────────────────────────

test('edit: writes the typed fields and replaces only notes in the metadata', () => {
  const held = rec({ metadata: { notes: 'old', tags: ['a'], connection_method: 'manual', mutual_contacts: ['x'] } });
  const p = editFormPatch(held, { name: 'New', email: 'n@x', contact_info: undefined, notes: 'fresh note' });
  assert.equal(p.name, 'New');
  assert.equal(p.email, 'n@x');
  assert.deepEqual(meta(p), { notes: 'fresh note', tags: ['a'], connection_method: 'manual', mutual_contacts: ['x'] });
});

test('edit: tags and other keys come from the HELD record, so a tag added since the dialog opened survives', () => {
  const held = rec({ metadata: { tags: ['a', 'added-elsewhere'] } });
  assert.deepEqual((meta(editFormPatch(held, { name: 'n', email: '', contact_info: undefined, notes: '' })).tags), ['a', 'added-elsewhere']);
});

test('edit: a blocked flag and share settings on the held record are kept', () => {
  const held = rec({ metadata: { blocked: true, share_settings: { open_visibility: false } } });
  const m = meta(editFormPatch(held, { name: 'n', email: '', contact_info: undefined, notes: 'x' }));
  assert.equal(m.blocked, true);
  assert.deepEqual(m.share_settings, { open_visibility: false });
});

test('edit: a record with no metadata gets just the note', () => {
  assert.deepEqual(meta(editFormPatch(rec(), { name: 'n', email: '', contact_info: undefined, notes: 'x' })), { notes: 'x' });
});

// ── ownerVerifyHeldPatch ────────────────────────────────────────────────────────────────────────────────────

test('verify: records the method on top of the held metadata', () => {
  const held = rec({ metadata: { tags: ['a'], notes: 'keep' } });
  const p = ownerVerifyHeldPatch(held, 'in_person');
  assert.deepEqual((meta(p).tags), ['a']);
  assert.equal(meta(p).notes, 'keep');
  const ov = (p as unknown as { owner_verify: { method: string; owner_verified_at: string } }).owner_verify;
  assert.equal(ov.method, 'in_person');
  assert.match(ov.owner_verified_at, /^\d{4}-\d\d-\d\dT/);
});

test('verify: a setting changed since the copy was taken survives', () => {
  const held = rec({ metadata: { share_settings: { per_contact_private: true } } });
  assert.deepEqual(meta(ownerVerifyHeldPatch(held, 'other_channel')).share_settings, { per_contact_private: true });
});

// ── blockPatch ──────────────────────────────────────────────────────────────────────────────────────────────

test('block: clears trust and open_visibility on the held record and keeps the other settings and metadata', () => {
  const held = rec({ trust_level: 'trusted', trusted: true, metadata: { tags: ['a'], share_settings: { open_visibility: true, share_groups: true } } });
  const p = blockPatch(held, true) as Record<string, unknown>;
  assert.equal(p.blocked, true);
  assert.equal(p.trusted, false);
  assert.equal(p.trust_level, 'unverified');
  assert.equal(p.trusted_since, null);
  const m = p.metadata as Record<string, unknown>;
  assert.equal(m.blocked, true);
  assert.deepEqual(m.share_settings, { open_visibility: false, share_groups: true });
  assert.deepEqual(m.tags, ['a']);
});

test('block: a record with no share settings still stores open_visibility false', () => {
  assert.deepEqual((meta(blockPatch(rec(), true)).share_settings), { open_visibility: false });
});

test('unblock: changes only the flag; trust and settings are not touched', () => {
  const held = rec({ blocked: true, trust_level: 'unverified', metadata: { blocked: true, share_settings: { open_visibility: false, share_groups: true } } });
  const p = blockPatch(held, false) as Record<string, unknown>;
  assert.equal(p.blocked, false);
  assert.equal('trust_level' in p, false);
  assert.equal('trusted' in p, false);
  const m = p.metadata as Record<string, unknown>;
  assert.equal(m.blocked, false);
  assert.deepEqual(m.share_settings, { open_visibility: false, share_groups: true });
});

test('block: a setting changed in another tab since the copy was taken survives', () => {
  const held = rec({ metadata: { share_settings: { share_card: false, open_visibility: true } } });
  assert.deepEqual(meta(blockPatch(held, true)).share_settings, { share_card: false, open_visibility: false });
});

// ── linkHeldPatch ───────────────────────────────────────────────────────────────────────────────────────────

const bound = { fingerprint: 'ab'.repeat(32), public_key: 'PK' };

test('link: the bound identity is stored, pending, trust restarts at unverified', () => {
  const p = linkHeldPatch(rec({ trust_level: 'trusted' }), bound) as Record<string, unknown>;
  assert.equal(p.fingerprint, bound.fingerprint);
  assert.equal(p.public_key, 'PK');
  assert.equal(p.connection_status, 'pending');
  assert.equal(p.trust_level, 'unverified');
});

test('link: the classical channels are snapshotted from the HELD record, and its metadata is kept', () => {
  const held = rec({ name: 'Ada', email: 'ada@x', contact_info: { phones: ['1'], emails: [], urls: [], handles: {} }, metadata: { notes: 'N', tags: ['t'] } });
  const m = (linkHeldPatch(held, bound) as { metadata: Record<string, unknown> }).metadata;
  assert.deepEqual(m.tags, ['t']);
  assert.equal(m.pending, true);
  const extras = m.classical_extras as { name?: string; email?: string; phones?: string[]; notes?: string };
  assert.equal(extras.name, 'Ada');
  assert.equal(extras.email, 'ada@x');
  assert.deepEqual(extras.phones, ['1']);
  assert.equal(extras.notes, 'N');
});

test('link: does not write contact_info (the held channels stay as stored)', () => {
  assert.equal('contact_info' in (linkHeldPatch(rec({ contact_info: { phones: ['1'] } }), bound) as object), false);
});

test('no helper mutates the record it is given', () => {
  const held = rec({ trust_level: 'trusted', metadata: { tags: ['a'], share_settings: { open_visibility: true } } });
  const before = JSON.stringify(held);
  editFormPatch(held, { name: 'x', email: '', contact_info: undefined, notes: 'n' });
  ownerVerifyHeldPatch(held, 'in_person');
  blockPatch(held, true);
  linkHeldPatch(held, bound);
  assert.equal(JSON.stringify(held), before);
});
