// src/lib/messaging/canonical.ts
// Canonical signing input for note v0 — mirrors format/canonicalize exclude pattern
// without importing frozen format helpers into a new domain prematurely.

import { canonicalize } from '@/lib/format/canonical';
import type { NoteWireV0 } from './types';

/**
 * Bytes signed for a note v0. Excludes the two SIGNATURE-ATTACHMENT fields (`signature` and the
 * sender's `public_key`) so the preimage is identical whether computed before attaching them (sign
 * side) or after they arrive on the wire (verify side). Everything else — including `from_fingerprint`
 * and `body` — is bound, so tampering any of it fails verification.
 */
export function noteSigningInput(note: NoteWireV0): string {
  return canonicalize(note, { exclude: ['signature', 'public_key'] });
}
