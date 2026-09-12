// src/lib/relay/relay-config.test.ts
// Unit tests for the client-side relay-endpoint config ("set your relay"). Pure validation +
// normalization + parse, plus the localStorage-backed read/write/resolve path against an
// in-memory stub. No server, no crypto — this module only records WHICH relay the client uses.
//
// Run: npx tsx --test relay-config.test.ts

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  BUNDLED_RELAY_BASE,
  DEFAULT_RELAY_CONFIG,
  RELAY_CONFIG_KEY,
  isValidRelayBase,
  normalizeRelayBase,
  parseRelayConfig,
  isCustomRelay,
  readRelayConfig,
  writeRelayConfig,
  clearRelayConfig,
  resolveRelayBase,
  relayHostLabel,
  relayStatusLine,
} from './relay-config';

// Minimal in-memory localStorage stub (node has none). Mirrors the setItem/getItem/removeItem
// surface the module uses.
function installLocalStorage(): Map<string, string> {
  const store = new Map<string, string>();
  (globalThis as { localStorage?: unknown }).localStorage = {
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
    clear: () => store.clear(),
  };
  return store;
}

beforeEach(() => {
  installLocalStorage();
});

test('isValidRelayBase: bundled default is always valid', () => {
  assert.equal(isValidRelayBase(BUNDLED_RELAY_BASE), true);
});

test('isValidRelayBase: absolute https origin is valid', () => {
  assert.equal(isValidRelayBase('https://relay.duskworks.io'), true);
  assert.equal(isValidRelayBase('https://relay.duskworks.io/api/relay'), true);
});

test('isValidRelayBase: http allowed ONLY for loopback (self-host testing)', () => {
  assert.equal(isValidRelayBase('http://localhost:8787'), true);
  assert.equal(isValidRelayBase('http://127.0.0.1:8787'), true);
  assert.equal(isValidRelayBase('http://relay.duskworks.io'), false); // plain http off-loopback
});

test('isValidRelayBase: rejects embedded credentials', () => {
  assert.equal(isValidRelayBase('https://user:pass@relay.duskworks.io'), false);
});

test('isValidRelayBase: rejects non-http(s) schemes and junk', () => {
  assert.equal(isValidRelayBase('javascript:alert(1)'), false);
  assert.equal(isValidRelayBase('data:text/html,x'), false);
  assert.equal(isValidRelayBase('ftp://relay.example'), false);
  assert.equal(isValidRelayBase('not a url'), false);
  assert.equal(isValidRelayBase(''), false);
  assert.equal(isValidRelayBase('/api/other'), false); // a same-origin path that isn't the bundled default
});

test('normalizeRelayBase: strips trailing slash, leaves default verbatim', () => {
  assert.equal(normalizeRelayBase('https://relay.duskworks.io/'), 'https://relay.duskworks.io');
  assert.equal(normalizeRelayBase('https://relay.duskworks.io///'), 'https://relay.duskworks.io');
  assert.equal(normalizeRelayBase('  https://relay.duskworks.io  '), 'https://relay.duskworks.io');
  assert.equal(normalizeRelayBase(BUNDLED_RELAY_BASE), BUNDLED_RELAY_BASE);
});

test('parseRelayConfig: null / junk / invalid base all fall back to default', () => {
  assert.deepEqual(parseRelayConfig(null), DEFAULT_RELAY_CONFIG);
  assert.deepEqual(parseRelayConfig('{not json'), DEFAULT_RELAY_CONFIG);
  assert.deepEqual(parseRelayConfig(JSON.stringify({ relayBase: 'http://evil.example' })), DEFAULT_RELAY_CONFIG);
  assert.deepEqual(parseRelayConfig(JSON.stringify({ relayBase: 42 })), DEFAULT_RELAY_CONFIG);
});

test('parseRelayConfig: valid custom base is parsed and normalized', () => {
  assert.deepEqual(
    parseRelayConfig(JSON.stringify({ relayBase: 'https://relay.duskworks.io/' })),
    { relayBase: 'https://relay.duskworks.io' },
  );
});

test('isCustomRelay: default is not custom, a chosen relay is', () => {
  assert.equal(isCustomRelay(DEFAULT_RELAY_CONFIG), false);
  assert.equal(isCustomRelay({ relayBase: 'https://relay.duskworks.io' }), true);
});

test('read/write/resolve round-trip via localStorage', () => {
  assert.equal(resolveRelayBase(), BUNDLED_RELAY_BASE); // nothing stored → default
  const stored = writeRelayConfig({ relayBase: 'https://relay.duskworks.io/' });
  assert.deepEqual(stored, { relayBase: 'https://relay.duskworks.io' }); // returns normalized
  assert.deepEqual(readRelayConfig(), { relayBase: 'https://relay.duskworks.io' });
  assert.equal(resolveRelayBase(), 'https://relay.duskworks.io');
});

test('writeRelayConfig throws on an invalid base (surfaced as a UI validation error)', () => {
  assert.throws(() => writeRelayConfig({ relayBase: 'http://evil.example' }), RangeError);
});

test('clearRelayConfig resets to the bundled relay', () => {
  writeRelayConfig({ relayBase: 'https://relay.duskworks.io' });
  assert.equal(resolveRelayBase(), 'https://relay.duskworks.io');
  clearRelayConfig();
  assert.equal(resolveRelayBase(), BUNDLED_RELAY_BASE);
});

test('a corrupt stored value degrades to the default (fail-safe read)', () => {
  const store = installLocalStorage();
  store.set(RELAY_CONFIG_KEY, '{ garbage');
  assert.deepEqual(readRelayConfig(), DEFAULT_RELAY_CONFIG);
});

test('relayHostLabel / relayStatusLine: honest copy, no over-claim', () => {
  assert.equal(relayHostLabel(DEFAULT_RELAY_CONFIG), 'the built-in relay');
  assert.equal(relayHostLabel({ relayBase: 'https://relay.duskworks.io/api/relay' }), 'relay.duskworks.io');
  // Status line names the relay and states the sealed-before-leaving guarantee — never "trusted".
  assert.match(relayStatusLine(DEFAULT_RELAY_CONFIG), /sealed before they leave your device/);
  assert.match(relayStatusLine({ relayBase: 'https://relay.duskworks.io' }), /relay.duskworks.io/);
  assert.match(relayStatusLine({ relayBase: 'https://relay.duskworks.io' }), /only carries the ciphertext/);
});
