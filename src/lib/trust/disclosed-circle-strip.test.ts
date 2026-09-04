import assert from 'node:assert/strict';
import { test } from 'node:test';
import { stripOwnerLocalForPublish } from './trust-recipe';

// §C F1 (Flint privacy co-review 2026-09-03) — the visibility-overlay OUTPUTS are owner-local and
// MUST NEVER ride onto the publish wire:
//   disclosed_circle = the computed mutual-known circle (KNOW layer, Apollo populates it)
//   they_trust       = the reciprocal-trust output (TRUST layer, Phase-2)
// They live in the SAME owner-local band as blocked / distress_inbound (contact-edge.ts:58), so
// stripOwnerLocalForPublish must delete them at BOTH the top level and inside metadata. This
// mirrors distress.test.ts's strip test — the co-land guard for the populate change.
test('stripOwnerLocalForPublish strips disclosed_circle + they_trust (top-level AND metadata)', () => {
  const stripped = stripOwnerLocalForPublish({
    fingerprint: 'peer-abc',
    disclosed_circle: ['contact-1', 'contact-2'],
    they_trust: ['contact-3'],
    metadata: {
      disclosed_circle: ['contact-1', 'contact-2'],
      they_trust: ['contact-3'],
      open_visibility: true,
      share_settings: { open_visibility: true },
    },
  });

  // Top-level: neither owner-local overlay field survives.
  assert.equal('disclosed_circle' in stripped, false);
  assert.equal('they_trust' in stripped, false);

  // Metadata band: same — must be gone.
  const m = stripped.metadata as Record<string, unknown>;
  assert.equal('disclosed_circle' in m, false);
  assert.equal('they_trust' in m, false);

  // Sanity: a wire-safe field is preserved (we strip owner-local, not everything).
  assert.equal((stripped as Record<string, unknown>).fingerprint, 'peer-abc');
});
