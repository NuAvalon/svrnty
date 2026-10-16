import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { RELAY_COPY } from './relay-copy';

describe('Relay settings glass — Flint copy + fail-closed switch', () => {
  const dir = dirname(fileURLToPath(import.meta.url));
  const src = readFileSync(join(dir, 'RelaySettings.tsx'), 'utf8');

  it('keeps the helper and never auto-switches', () => {
    assert.match(src, /RELAY_COPY\.currentPrefix/);
    assert.match(src, /RELAY_COPY\.placeholder/);
    assert.equal(RELAY_COPY.currentPrefix, "You're on:");
    assert.equal(RELAY_COPY.placeholder, 'https://your-relay.example:8100');
    assert.equal(
      RELAY_COPY.helper.includes('never your notes (those stay sealed end-to-end)'),
      true,
    );
    assert.equal(
      RELAY_COPY.helper.includes('Switching relays moves your dead-drop, not your identity.'),
      true,
    );
    assert.match(src, /disabled=\{!switchEnabled\}/);
    assert.match(src, /setPhase\('confirm'\)/);
    assert.match(src, /switchToRelay/);
    assert.doesNotMatch(src, /auto-switch|autoswitch/i);
  });

  it('never calls the result "done" and reads complete / failedFps / overlapUntil', () => {
    assert.equal(RELAY_COPY.nowOn('https://b.example').includes('done'), false);
    assert.equal(RELAY_COPY.incomplete(3).includes('done'), false);
    assert.match(RELAY_COPY.incomplete(3), /3 friends not yet notified/);
    assert.match(RELAY_COPY.incomplete(1), /1 friend not yet notified/);
    const seam = readFileSync(join(dir, 'relay-migrate-seam.ts'), 'utf8');
    assert.match(seam, /complete/);
    assert.match(seam, /failedFps/);
    assert.match(seam, /overlapUntil/);
    assert.match(src, /out\.complete/);
    assert.match(src, /out\.failedFps\.length/);
    assert.match(src, /writeChosenRelayUrl/);
    assert.match(src, /RelayMigrateUnwiredError/);
    assert.doesNotMatch(src, /You're now on \$\{health\.url\}/);
  });
});
