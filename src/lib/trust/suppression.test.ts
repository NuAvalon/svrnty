// src/lib/trust/suppression.test.ts
// ADVERSARIAL gate for the piece-2 emit-side suppression set (task #579, §F3 fail-closed invariant).
// Refutes survivor-safety properties, not "a set round-trips":
//   · §F3 FAIL-CLOSED: an UNREADABLE record suppresses EVERYONE (a locked/corrupt store never un-suppresses),
//   · a malformed/legacy blob is treated as ABSENT (never read as "nothing suppressed"),
//   · global / per-person(durable_id) / per-group suppression each bite,
//   · a NON-suppressed party is surfaceable (positive control — we don't over-suppress),
//   · durable_id keying is rotation-stable + case-insensitive (not UUID/mailbox/route).
// Run: npx tsx --test src/lib/trust/suppression.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  emptySuppression,
  isSuppressionRecord,
  isPartySuppressed,
  suppressPerson,
  unsuppressPerson,
  suppressGroup,
  unsuppressGroup,
  setGlobalSuppression,
  type SuppressionRecord,
} from './suppression.js';

const ANNA = 'a'.repeat(64);     // a durable_id (canonical fingerprint, 64-hex)
const CAROL = 'c'.repeat(64);

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (§F3 FAIL-CLOSED-ON-DOUBT) — the HARDEST invariant. An UNREADABLE record (null) suppresses EVERYONE:
// the emit path then emits to no one. "Can't confirm un-suppressed ⇒ exclude."
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(§F3) a null (unreadable) record suppresses every party', () => {
  assert.equal(isPartySuppressed(null, { durableId: ANNA }), true, 'unreadable ⇒ suppress');
  assert.equal(isPartySuppressed(null, { durableId: CAROL, groupIds: ['work'] }), true, 'unreadable ⇒ suppress (even with groups)');
  assert.equal(isPartySuppressed(null, { durableId: '' }), true, 'unreadable ⇒ suppress (even an empty id)');
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (MALFORMED ⇒ ABSENT) — a partial/legacy blob must never narrow to a valid record; the guard rejects it so
// the caller treats it as null ⇒ fail-closed. A `{global:false}`-only legacy shape must NOT un-suppress.
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(MALFORMED ⇒ ABSENT) isSuppressionRecord rejects partial/legacy/hostile shapes', () => {
  assert.equal(isSuppressionRecord(null), false);
  assert.equal(isSuppressionRecord({}), false);
  assert.equal(isSuppressionRecord({ global: false }), false, 'missing arrays');
  assert.equal(isSuppressionRecord({ global: false, groups: [], persons: [1] }), false, 'non-string person');
  assert.equal(isSuppressionRecord({ global: 'no', groups: [], persons: [] }), false, 'non-bool global');
  assert.equal(isSuppressionRecord({ global: false, groups: 'work', persons: [] }), false, 'groups not array');
  assert.equal(isSuppressionRecord(emptySuppression()), true, 'a well-formed empty record is valid');
  assert.equal(isSuppressionRecord({ global: true, groups: ['x'], persons: [ANNA] }), true);
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (GLOBAL go-private) — global suppresses everyone, overriding any party.
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(GLOBAL) global=true suppresses all parties', () => {
  const rec = setGlobalSuppression(emptySuppression(), true);
  assert.equal(isPartySuppressed(rec, { durableId: ANNA }), true);
  assert.equal(isPartySuppressed(rec, { durableId: CAROL, groupIds: [] }), true);
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (PER-PERSON / durable_id) — a person-suppressed durable_id bites; an unrelated person does NOT (positive
// control, no over-suppression); keying is case-insensitive + stable (rotation-independent — it's the
// canonical fingerprint, not a UUID/mailbox/route).
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(PER-PERSON) person suppression bites only the listed durable_id, case-insensitive', () => {
  const rec = suppressPerson(emptySuppression(), ANNA.toUpperCase());
  assert.equal(isPartySuppressed(rec, { durableId: ANNA }), true, 'listed (lowercased) ⇒ suppressed');
  assert.equal(isPartySuppressed(rec, { durableId: ANNA.toUpperCase() }), true, 'listed (uppercase query) ⇒ suppressed');
  assert.equal(isPartySuppressed(rec, { durableId: CAROL }), false, 'POSITIVE CONTROL — unlisted party surfaceable');
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (PER-GROUP) — a party in a suppressed group is suppressed; group ids are opaque + case-insensitive.
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(PER-GROUP) a party in a suppressed group is suppressed', () => {
  const rec = suppressGroup(emptySuppression(), 'Work');
  assert.equal(isPartySuppressed(rec, { durableId: CAROL, groupIds: ['work'] }), true, 'in suppressed group');
  assert.equal(isPartySuppressed(rec, { durableId: CAROL, groupIds: ['family'] }), false, 'POSITIVE CONTROL — other group surfaceable');
  assert.equal(isPartySuppressed(rec, { durableId: CAROL }), false, 'no groups ⇒ not group-suppressed');
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (MUTATIONS) — idempotent, normalized, reversible; un-suppress restores surfaceability.
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(MUTATIONS) suppress/unsuppress are idempotent + reversible', () => {
  let rec = emptySuppression();
  rec = suppressPerson(rec, ANNA);
  rec = suppressPerson(rec, ANNA); // idempotent
  rec = suppressPerson(rec, ANNA.toUpperCase()); // normalized — no dup
  assert.equal(rec.persons.length, 1, 'no duplicate person entries');
  assert.equal(isPartySuppressed(rec, { durableId: ANNA }), true);
  rec = unsuppressPerson(rec, ANNA);
  assert.equal(isPartySuppressed(rec, { durableId: ANNA }), false, 'un-suppress restores surfaceability');

  let g = suppressGroup(emptySuppression(), 'work');
  g = suppressGroup(g, 'WORK'); // normalized
  assert.equal(g.groups.length, 1);
  g = unsuppressGroup(g, 'work');
  assert.equal(g.groups.length, 0);

  const gp = setGlobalSuppression(emptySuppression(), true);
  assert.equal(gp.global, true);
  assert.equal(setGlobalSuppression(gp, false).global, false);
});

// ── empty record surfaces everyone (the default-discoverable baseline, pre-any-suppression) ───────────
test('an empty record suppresses no one (default-discoverable baseline)', () => {
  const rec = emptySuppression();
  assert.equal(isPartySuppressed(rec, { durableId: ANNA }), false);
  assert.equal(isPartySuppressed(rec, { durableId: CAROL, groupIds: ['work', 'family'] }), false);
});
