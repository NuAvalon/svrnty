// src/lib/contacts/contact-update-allowlist-guard.test.ts
// Cross-file divergence guard (the lockstep pattern — Flint + Athena). The contact.update field
// allowlist is declared in TWO files: the VERIFY side (trust/contact-update.ts) rejects any wire
// update touching a non-allowlisted field; the APPLY side (contacts/apply-contact-update.ts) writes
// each allowlisted field onto the stored record via FIELD_MAP. They MUST stay identical —
//   • a field on VERIFY but not APPLY → verified, then silently dropped (data loss),
//   • a field on APPLY but not VERIFY → applied without ever being verified.
// Each file's own test asserts its half; THIS test cross-checks the two sets are EQUAL, so editing
// one allowlist without the other fails here. Grow/shrink the vocabulary = change BOTH + the FIELD_MAP.
// Run: npx tsx --test src/lib/contacts/contact-update-allowlist-guard.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CONTACT_UPDATE_ALLOWED_FIELDS as VERIFY_ALLOWLIST } from '../trust/contact-update';
import { CONTACT_UPDATE_ALLOWED_FIELDS as APPLY_ALLOWLIST, CONTACT_UPDATE_FIELD_MAP_KEYS } from './apply-contact-update';

test('contact.update verify-side and apply-side allowlists are IDENTICAL (lockstep divergence guard)', () => {
  const verifyOnly = [...VERIFY_ALLOWLIST].filter((f) => !APPLY_ALLOWLIST.has(f)).sort();
  const applyOnly = [...APPLY_ALLOWLIST].filter((f) => !VERIFY_ALLOWLIST.has(f)).sort();
  assert.deepEqual(
    { verifyOnly, applyOnly },
    { verifyOnly: [], applyOnly: [] },
    'contact.update allowlist DIVERGED between trust/contact-update.ts (verify) and ' +
      'contacts/apply-contact-update.ts (apply). A verify-only field is verified then silently ' +
      'dropped; an apply-only field is applied unverified. Any field listed here must be added to ' +
      '(or removed from) BOTH allowlists + the FIELD_MAP together. ' +
      `verify-only=${JSON.stringify(verifyOnly)} apply-only=${JSON.stringify(applyOnly)}`,
  );
});

// The adjacent link (Flint's strengthening, #116041): the allowlist ≡ the FIELD_MAP domain. Every
// allowlisted field must have a FIELD_MAP entry — otherwise apply throws 'field-not-mappable' at
// runtime; this moves that catch to CI. And no FIELD_MAP entry should exist for a non-allowlisted
// field (dead/latent mapper). Combined with the test above (verify ≡ apply), this closes the full
// lockstep: verify-allowlist ≡ apply-allowlist ≡ FIELD_MAP-domain.
test('apply allowlist ≡ FIELD_MAP domain — every allowlisted field maps, no dead mappers (closes the lockstep)', () => {
  const unmappable = [...APPLY_ALLOWLIST].filter((f) => !CONTACT_UPDATE_FIELD_MAP_KEYS.has(f)).sort();
  const deadMappers = [...CONTACT_UPDATE_FIELD_MAP_KEYS].filter((f) => !APPLY_ALLOWLIST.has(f)).sort();
  assert.deepEqual(
    { unmappable, deadMappers },
    { unmappable: [], deadMappers: [] },
    'apply allowlist ↔ FIELD_MAP domain DIVERGED. An unmappable field is allowlisted but has no ' +
      "FIELD_MAP entry → apply throws 'field-not-mappable' at runtime (this test moves that catch to CI). " +
      'A dead mapper is a FIELD_MAP entry for a non-allowlisted field (latent/dead). Keep them equal. ' +
      `unmappable=${JSON.stringify(unmappable)} dead-mappers=${JSON.stringify(deadMappers)}`,
  );
});
