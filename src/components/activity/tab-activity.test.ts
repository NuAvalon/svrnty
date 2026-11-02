import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { galaxyActivitySignature, shouldMarkGalaxyActivity } from './tab-activity';

describe('tab activity embers', () => {
  it('does not glow on the first snapshot', () => {
    const sig = galaxyActivitySignature(1, ['aaa']);
    assert.equal(shouldMarkGalaxyActivity(null, sig), false);
  });

  it('glows when attention appears later, without exposing a count in the signature UI', () => {
    const before = galaxyActivitySignature(0, []);
    const after = galaxyActivitySignature(1, ['aaa']);
    assert.equal(shouldMarkGalaxyActivity(before, after), true);
    assert.doesNotMatch(after, /unread|count/i);
  });

  it('stays quiet when the snapshot is unchanged', () => {
    const sig = galaxyActivitySignature(2, ['b', 'a']);
    assert.equal(shouldMarkGalaxyActivity(sig, galaxyActivitySignature(2, ['a', 'b'])), false);
  });
});
