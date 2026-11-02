// The share-settings write is clamped on the record the store holds when the write runs, and the allowed-senders mirror is reconciled to the
// record read back after the write. These tests drive both pure functions with a held record whose trust differs from what a screen showed.
//
// Run: npx tsx --test src/lib/contacts/share-settings-patch.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shareSettingsPatch, consentFromRecord, NO_CONSENT } from './share-settings-patch';
import { defaultShareSettings, type ContactShareSettings } from '@/lib/contacts/contact-lane';
import type { ContactRecord } from '@/lib/identity/client-store';

const rec = (o: Record<string, unknown> = {}): ContactRecord =>
  ({ id: 'c1', owner_fingerprint: 'o', fingerprint: 'f', name: 'n', email: 'e', public_key: 'k', added_at: 'a', ...o }) as unknown as ContactRecord;
const S = (o: Partial<ContactShareSettings> = {}): ContactShareSettings => defaultShareSettings(o);
const stored = (p: Partial<ContactRecord>) => (p.metadata as { share_settings: ContactShareSettings }).share_settings;

// ── shareSettingsPatch ──────────────────────────────────────────────────────────────────────────────────────

test('patch: the clamp is decided on the HELD record: held untrusted -> open_visibility stored false, even if the screen showed trusted', () => {
  const held = rec({ trust_level: 'unverified' });
  const p = shareSettingsPatch(held, S(), S({ open_visibility: true }));
  assert.equal(stored(p).open_visibility, false);
});

test('patch: held trusted -> the owner\'s open_visibility is stored, even if the screen showed untrusted', () => {
  const held = rec({ trust_level: 'trusted' });
  const p = shareSettingsPatch(held, S(), S({ open_visibility: true }));
  assert.equal(stored(p).open_visibility, true);
});

test('patch: an explicit trusted:false on the held record WINS over a trusted trust_level (the reveal derivation)', () => {
  const held = rec({ trust_level: 'trusted', trusted: false });
  assert.equal(stored(shareSettingsPatch(held, S(), S({ open_visibility: true }))).open_visibility, false);
});

test('patch: only the settings the owner CHANGED are applied; one changed elsewhere since survives', () => {
  const held = rec({ trust_level: 'trusted', metadata: { share_settings: S({ share_groups: true }), notes: 'keep' } });
  const p = shareSettingsPatch(held, S(), S({ per_contact_private: true }));
  assert.deepEqual(stored(p), S({ share_groups: true, per_contact_private: true }));
  assert.equal((p.metadata as { notes: string }).notes, 'keep');
});

test('patch: metadata keys come from the held record', () => {
  const held = rec({ trust_level: 'trusted', metadata: { tags: ['new-since-screen'] } });
  const p = shareSettingsPatch(held, S(), S({ share_card: false }));
  assert.deepEqual((p.metadata as { tags: string[] }).tags, ['new-since-screen']);
});

test('patch: never mutates the held record', () => {
  const held = rec({ trust_level: 'trusted', metadata: { share_settings: S() } });
  const before = JSON.stringify(held);
  shareSettingsPatch(held, S(), S({ open_visibility: true }));
  assert.equal(JSON.stringify(held), before);
});

// ── consentFromRecord ───────────────────────────────────────────────────────────────────────────────────────

test('consent: read from the stored record only', () => {
  const r = rec({ trust_level: 'verified', metadata: { share_settings: S({ open_visibility: true, per_contact_private: true }) } });
  assert.deepEqual(consentFromRecord(r), { trusted: true, openVisibility: true, blocked: false, perContactPrivate: true });
});

test('consent: trusted follows trust_level (verified or trusted), as the contact screen does', () => {
  assert.equal(consentFromRecord(rec({ trust_level: 'verified' })).trusted, true);
  assert.equal(consentFromRecord(rec({ trust_level: 'trusted' })).trusted, true);
  assert.equal(consentFromRecord(rec({ trust_level: 'unverified' })).trusted, false);
  assert.equal(consentFromRecord(rec({})).trusted, false);
});

test('consent: blocked from either the record flag or the metadata flag', () => {
  assert.equal(consentFromRecord(rec({ blocked: true })).blocked, true);
  assert.equal(consentFromRecord(rec({ metadata: { blocked: true } })).blocked, true);
  assert.equal(consentFromRecord(rec({})).blocked, false);
});

test('consent: a record with no settings reads as nothing open', () => {
  const c = consentFromRecord(rec({ trust_level: 'trusted' }));
  assert.equal(c.openVisibility, false);
  assert.equal(c.perContactPrivate, false);
});

test('consent: the value written is the value reconciled (clamped record -> openVisibility false)', () => {
  const held = rec({ trust_level: 'unverified' });
  const after = { ...held, ...shareSettingsPatch(held, S(), S({ open_visibility: true })) } as ContactRecord;
  assert.equal(consentFromRecord(after).openVisibility, false);
});

test('NO_CONSENT: every axis false', () => {
  assert.deepEqual(NO_CONSENT, { trusted: false, openVisibility: false, blocked: false, perContactPrivate: false });
});
