// src/lib/messaging/canonical.ts
// Canonical signing input for note v0 — mirrors format/canonicalize exclude pattern
// without importing frozen format helpers into a new domain prematurely.

import { canonicalize } from '@/lib/format/canonical';
import type { NoteWireV0 } from './types';

/** Bytes signed for a note v0 (excludes top-level `signature` if attached later). */
export function noteSigningInput(note: NoteWireV0): string {
  return canonicalize(note, { exclude: ['signature'] });
}
