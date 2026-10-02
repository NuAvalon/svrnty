import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isConnectAddLogicLive } from '../claim-gates';
import {
  landInGate,
  promoteGateToKnown,
  resolveConnectLink,
} from './add-logic';

const dir = dirname(fileURLToPath(import.meta.url));

describe('connect add-logic stub — fail closed until Apollo wires', () => {
  const card = {
    displayName: 'River',
    fingerprint: 'aa'.repeat(32),
    entityType: 'human' as const,
  };

  it('claim gate is false', () => {
    assert.equal(isConnectAddLogicLive(), false);
  });

  it('resolve never returns a card while unwired (does not invent a person)', async () => {
    const r = await resolveConnectLink({ code: 'abc', keyFragment: 'secret' });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'not_wired');
  });

  it('landInGate never returns Known — Gate-not-Known on arrival', async () => {
    const r = await landInGate(card);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'not_wired');
    if (r.ok) assert.equal(r.state, 'gate');
  });

  it('promote refuses Trusted and refuses while unwired', async () => {
    const r = await promoteGateToKnown(card.fingerprint, 'known');
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, 'not_wired');
    const bad = await promoteGateToKnown(card.fingerprint, 'trusted' as 'known');
    assert.equal(bad.ok, false);
  });

  it('stub does not import relay decrypt, identity persist, or grow-gate admit', () => {
    const src = readFileSync(join(dir, 'add-logic.ts'), 'utf8');
    assert.doesNotMatch(src, /resolveRelay/);
    assert.doesNotMatch(src, /addContact/);
    assert.doesNotMatch(src, /enqueueGateArrival/);
    assert.doesNotMatch(src, /admitGateArrival/);
    assert.doesNotMatch(src, /from '@\/lib\/crypto/);
    assert.doesNotMatch(src, /from '@\/lib\/trust\/grow-gate/);
    assert.doesNotMatch(src, /from '@\/lib\/identity/);
    assert.doesNotMatch(src, /from '@\/lib\/sync\/vault/);
  });
});
