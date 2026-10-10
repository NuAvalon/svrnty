import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeRelayUrl, validateRelayHealth } from './relay-health';
import { RELAY_COPY } from './relay-copy';

function jsonOk(body: unknown, status = 200) {
  return async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
}

describe('relay health — full satellite only', () => {
  it('normalizes https and rejects javascript', () => {
    assert.equal(normalizeRelayUrl('https://relay.example:8100/'), 'https://relay.example:8100');
    assert.equal(normalizeRelayUrl('javascript:alert(1)'), null);
    assert.equal(normalizeRelayUrl('data:text/html,x'), null);
  });

  it('accepts a full svrnty satellite', async () => {
    const out = await validateRelayHealth('https://relay.example:8100', jsonOk({
      status: 'online',
      service: 'satellite',
      mode: 'full',
    }));
    assert.equal(out.ok, true);
    if (out.ok) assert.equal(out.url, 'https://relay.example:8100');
  });

  it('rejects registration-only and registry-mode satellites', async () => {
    const reg = await validateRelayHealth('https://reg.example:8101', jsonOk({
      status: 'online',
      service: 'registration',
    }));
    assert.equal(reg.ok, false);
    if (!reg.ok) assert.equal(reg.reason, RELAY_COPY.invalid.registrationOnly);

    const registry = await validateRelayHealth('https://sat.example:8100', jsonOk({
      status: 'online',
      service: 'satellite',
      mode: 'registry',
    }));
    assert.equal(registry.ok, false);
    if (!registry.ok) assert.equal(registry.reason, RELAY_COPY.invalid.registrationOnly);
  });

  it('rejects a non-svrnty 200 and a dead host', async () => {
    const other = await validateRelayHealth('https://example.com', jsonOk({ ok: true }));
    assert.equal(other.ok, false);
    if (!other.ok) assert.equal(other.reason, RELAY_COPY.invalid.notRelay);

    const dead = await validateRelayHealth('https://down.example', async () => {
      throw new Error('network');
    });
    assert.equal(dead.ok, false);
    if (!dead.ok) assert.equal(dead.reason, RELAY_COPY.invalid.reach);
  });
});
