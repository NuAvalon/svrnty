// src/lib/trust/edge-trusted-consistency.test.ts
// piece-1 ★★ TRUSTED-DEFINITION CONSISTENCY (Athena #158853) + H1 SET-path clamp.
// G (sweep), H1 (clamp), H2 (disable) MUST all test "trusted" with the REVEAL's derivation
// (contact-edge.ts: `c.trusted ?? (trust_level === 'verified' || 'trusted')`), NOT trust_level-only —
// else an edge {c.trusted:false, trust_level:'trusted'} slips the clamp yet is HIDDEN by the reveal (gap).
// These assert the predicate (and its equivalence to the reveal projection) + the H1 clamp expression.
// handleShareSettingsChange is a React-closure, not unit-testable in isolation → we test the clamp
// EXPRESSION directly, per the patch's note.
//
// Run: node --import tsx --test src/lib/trust/edge-trusted-consistency.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { contactRecordToEdge } from './contact-edge';

// The exact predicate defined (verbatim) in all 3 piece-1 locations: client-store.ts
// migratePerContactPrivacyOnUnlock (G), ContactManagement.tsx (H1), ContactDetailDialog.tsx (H2).
const edgeTrusted = (c: { trusted?: boolean; trust_level?: string }): boolean =>
  (c.trusted ?? (c.trust_level === 'verified' || c.trust_level === 'trusted')) === true;

// The H1 clamp expression (ContactManagement.handleShareSettingsChange): open_visibility forced false
// on a NON-edgeTrusted edge; pcp is NOT clamped.
type Share = { open_visibility: boolean; per_contact_private: boolean };
function clamp(contact: { trusted?: boolean; trust_level?: string }, next: Share): Share {
  return edgeTrusted(contact) ? next : { ...next, open_visibility: false };
}

test('edgeTrusted: explicit c.trusted===false WINS over trust_level (matches the reveal at contact-edge.ts)', () => {
  const gap = { trusted: false, trust_level: 'trusted' };
  assert.equal(edgeTrusted(gap), false); // explicit false short-circuits the ?? — NOT trusted
  // ≡ the reveal: contactRecordToEdge projects the SAME derivation → trusted === false (HIDDEN)
  assert.equal(contactRecordToEdge(gap).trusted, false);
});

test('edgeTrusted: every shape agrees with the reveal projection (contactRecordToEdge.trusted)', () => {
  const cases = [
    { trust_level: 'trusted' },                   // trust_level only → trusted
    { trust_level: 'verified' },                  // trust_level only → trusted
    { trust_level: 'unverified' },                // → NOT trusted
    { trusted: true, trust_level: 'unverified' }, // explicit true wins → trusted
    { trusted: false, trust_level: 'trusted' },   // explicit false wins → NOT trusted
    {},                                           // nothing → NOT trusted
  ];
  for (const c of cases) {
    assert.equal(edgeTrusted(c), contactRecordToEdge(c).trusted === true, JSON.stringify(c));
  }
});

test('H1 clamp: NON-edgeTrusted contact + next.open_visibility=true → persisted open_visibility=false; reconcile consent openVisibility=false', () => {
  const contact = { trust_level: 'unverified' }; // not trusted
  const next: Share = { open_visibility: true, per_contact_private: false };
  const clamped = clamp(contact, next);
  // the reconcile consent is built from `clamped` (H1 supersedes the D1 `next`):
  // openVisibility = clamped.open_visibility === true. Compute it BEFORE the narrowing assert below.
  const consentOpenVisibility = clamped.open_visibility === true;
  assert.equal(clamped.open_visibility, false); // clamp fired — no untrusted-open record written
  assert.equal(consentOpenVisibility, false);   // the allowed_senders consent mirror is false
});

test('H1 clamp: edgeTrusted contact → open_visibility=true passes through; pcp is NEVER clamped', () => {
  const trusted = { trust_level: 'trusted' };
  const clamped = clamp(trusted, { open_visibility: true, per_contact_private: true });
  assert.equal(clamped.open_visibility, true);     // trusted → passes through → consent openVisibility: true
  assert.equal(clamped.per_contact_private, true); // pcp untouched (valid on any edge)

  // pcp is not clamped even on a NON-trusted edge: ONLY open_visibility is forced false
  const untrusted = { trust_level: 'unverified' };
  const c2 = clamp(untrusted, { open_visibility: true, per_contact_private: true });
  assert.equal(c2.open_visibility, false);     // open_vis clamped
  assert.equal(c2.per_contact_private, true);  // pcp preserved
});

test('H1 clamp: the ★★ gap edge {trusted:false, trust_level:"trusted"} IS clamped (trust_level-only isTrusted would WRONGLY let it pass)', () => {
  const gap = { trusted: false, trust_level: 'trusted' };
  const clamped = clamp(gap, { open_visibility: true, per_contact_private: false });
  assert.equal(clamped.open_visibility, false); // edgeTrusted(gap)=false → clamp fires (reveal HIDES it anyway)
});
