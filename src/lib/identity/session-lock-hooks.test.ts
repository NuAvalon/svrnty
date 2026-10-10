// src/lib/identity/session-lock-hooks.test.ts
// P1#1 (cross-identity notes-leak): lockSession AND setActiveFingerprint must fire the registered
// session-lock hooks, so a session-scoped key held elsewhere (the notes store's _notesKey) is dropped
// on lock AND on identity-switch — else B inherits A's still-loaded key and reads A's plaintext notes.
// This proves client-store's firing mechanism at BOTH chokepoints (setActiveFingerprint is the TRUE
// switch chokepoint — restore + import-activation route through it, not lockSession). The full
// cross-identity breach (real IndexedDB: A-writes → switch → B-sees-zero) is Flint's breach-matrix.
// Run: npx tsx --test src/lib/identity/session-lock-hooks.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { onSessionLock, lockSession, setActiveFingerprint } from '@/lib/identity/client-store';

test('lockSession fires registered session-lock hooks (notes-key drop on lock)', () => {
  let fired = 0;
  onSessionLock(() => { fired += 1; });
  lockSession();
  assert.equal(fired, 1, 'the registered hook (lockNotesStore in prod) fires on lock');
});

test('setActiveFingerprint fires the hooks BEFORE the write (switch-path notes-key drop — the TRUE chokepoint)', async () => {
  let fired = 0;
  onSessionLock(() => { fired += 1; });
  // fireSessionLockHooks runs before the IndexedDB txPut; the write throws without a real DB here, but
  // the hook has already fired — which is the point: restore/import switches drop the prior key too.
  try { await setActiveFingerprint('f'.repeat(64)); } catch { /* txPut needs IndexedDB in prod */ }
  assert.equal(fired, 1, 'the hook fires on identity-switch, before the active-fingerprint write');
});
