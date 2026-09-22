// Grow session-guard invariant (Track-S #541; root cause KB#89759). Grow mints an invite via
// loadKey(), which fails when the identity is encrypted-at-rest (canLock) but the in-memory session
// key is gone. That desync is reachable on an iOS-PWA background→restore: the React tree comes back
// "unlocked" (identity set, appState 'unlocked' → Grow reachable) while the JS module heap re-inits
// and _sessionKey is null. Left unguarded, opening Grow renders a dead panel — no QR, no short link.
//
// Two guards keep Grow from ever presenting a dead/silent panel in that state:
//   1. page.tsx onGrow must consult the LIVE session (isSessionUnlocked()) and re-gate to the unlock
//      flow (handleLockNow) when the encrypted identity's key is absent — not open Grow blindly.
//   2. GrowSheet.mint() must never SILENTLY return when the identity isn't ready — it surfaces a
//      cause-agnostic message (Flint/Hypatia fail-closed-with-clear-prompt).
//
// Static source guards (blocker-c-failclosed.test.ts style) so a future refactor can't silently
// regress the fix. The end-to-end behaviour is covered by the real cold-visitor invite e2e (Hypatia).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

test('page.tsx: onGrow re-gates when the encrypted-identity session key is absent (no dead-Grow desync)', () => {
  const src = readFileSync(new URL('../../app/page.tsx', import.meta.url), 'utf8');

  // isSessionUnlocked must be imported (the guard reads the live session, not stale React state).
  assert.match(src, /\bisSessionUnlocked\b/, 'isSessionUnlocked must be imported/used');

  const onGrowIdx = src.indexOf('onGrow=');
  assert.ok(onGrowIdx >= 0, 'onGrow handler not found');
  // Bound the slice to the onGrow prop exactly (up to the next TopNav prop) rather than a fixed
  // window — the guard sits below a multi-line explanatory comment.
  const onRecoveryIdx = src.indexOf('onRecovery=', onGrowIdx);
  assert.ok(onRecoveryIdx > onGrowIdx, 'onRecovery prop (handler end marker) not found');
  const handler = src.slice(onGrowIdx, onRecoveryIdx);

  assert.match(
    handler,
    /!isSessionUnlocked\(\)/,
    'onGrow must check the live session (!isSessionUnlocked()) before opening Grow',
  );
  assert.match(
    handler,
    /handleLockNow\(\)/,
    'onGrow must re-gate (handleLockNow) when the session key is absent, not open a dead Grow',
  );
});

test('GrowSheet.tsx: mint() never silently returns when the identity is not ready', () => {
  const src = readFileSync(new URL('./GrowSheet.tsx', import.meta.url), 'utf8');

  const mintIdx = src.indexOf('const mint = useCallback');
  assert.ok(mintIdx >= 0, 'mint useCallback not found');
  const body = src.slice(mintIdx, src.indexOf('}, [identity]', mintIdx));

  // The identity-absent branch must be a block that sets an error — not a bare silent `return`.
  assert.match(
    body,
    /if \(!identity\?\.identity\?\.fingerprint\) \{/,
    'identity-absent branch must be a block (not a bare silent return)',
  );
  assert.doesNotMatch(
    body,
    /if \(!identity\?\.identity\?\.fingerprint\) return;/,
    'identity-absent branch must not silently return',
  );

  const guardIdx = body.indexOf('!identity?.identity?.fingerprint');
  const guardBlock = body.slice(guardIdx, guardIdx + 600);
  assert.match(guardBlock, /setError\(/, 'identity-absent branch must surface a message (never silent)');
});
