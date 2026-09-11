import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  defaultRelayHost,
  normalizeRelayHost,
  registerTeamMethodRelayMove,
  requestMethodRelayMove,
  teamMethodRelayMoveRegistered,
} from './method-relay';
import { addOwnerMethod, emptyOwnerCard, methodRelayHost } from '@/components/identity/owner-card';

test('normalizeRelayHost: https host only; refuse javascript/data/http', () => {
  assert.equal(normalizeRelayHost('relay.example.test'), 'relay.example.test');
  assert.equal(normalizeRelayHost('https://Relay.Example.TEST/path'), 'relay.example.test');
  assert.equal(normalizeRelayHost('http://relay.example.test'), null);
  assert.equal(normalizeRelayHost('javascript:alert(1)'), null);
  assert.equal(normalizeRelayHost('data:text/html,hi'), null);
  assert.equal(normalizeRelayHost(''), null);
});

test('defaultRelayHost is a non-empty deployment host', () => {
  assert.ok(defaultRelayHost().length > 0);
});

test('requestMethodRelayMove saves local intent when the fleet seam is unwired', async () => {
  registerTeamMethodRelayMove(null);
  assert.equal(teamMethodRelayMoveRegistered(), false);
  let bag = emptyOwnerCard();
  bag = addOwnerMethod(bag, 'email', 'a@b.test');
  const { result, bag: next } = await requestMethodRelayMove(bag, bag.methods[0].id, 'self.example.test');
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.host, 'self.example.test');
    assert.equal(result.delivered, false);
  }
  assert.equal(methodRelayHost(next.methods[0]), 'self.example.test');
});

test('requestMethodRelayMove calls the registered team seam', async () => {
  let seen: { methodId: string; host: string } | null = null;
  registerTeamMethodRelayMove(async (args) => {
    seen = args;
    return { ok: true };
  });
  let bag = emptyOwnerCard();
  bag = addOwnerMethod(bag, 'phone', '+15551212');
  const { result } = await requestMethodRelayMove(bag, bag.methods[0].id, 'https://other.relay.test');
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.delivered, true);
  assert.deepEqual(seen, { methodId: bag.methods[0].id, host: 'other.relay.test' });
  registerTeamMethodRelayMove(null);
});

test('invalid host does not rewrite the bag', async () => {
  let bag = emptyOwnerCard();
  bag = addOwnerMethod(bag, 'email', 'a@b.test');
  const before = JSON.stringify(bag);
  const { result, bag: next } = await requestMethodRelayMove(bag, bag.methods[0].id, 'javascript:x');
  assert.equal(result.ok, false);
  assert.equal(JSON.stringify(next), before);
});
