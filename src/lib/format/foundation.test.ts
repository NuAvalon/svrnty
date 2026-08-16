// Foundation tests — canonical (0.1/0.2) + dedup (0.13). Run:
//   npx tsx --test  (extensionless — matches repo convention; or tsc→CJS in CI)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize } from './canonical';
import {
  normalizeChannel, dedupKey, edgeChannels, sharesChannel, livingWinsSurvivor,
} from '../contacts/dedup';

test('canonicalize: stable key order + NFC + float/null/exclude guards', () => {
  assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalize({ n: 'é' }), canonicalize({ n: 'é' })); // composed == decomposed
  assert.throws(() => canonicalize({ v: 1.5 }));   // floats rejected
  assert.throws(() => canonicalize({ a: null }));  // null rejected
  assert.equal(canonicalize({ a: undefined, b: 1 }), '{"b":1}'); // undefined omitted
  assert.equal(canonicalize({ signature: 'x', v: 1 }, { exclude: ['signature'] }), '{"v":1}');
  assert.equal(canonicalize({ z: [{ b: 1, a: 2 }], a: 'x' }), '{"a":"x","z":[{"a":2,"b":1}]}');
});

test('normalizeChannel: E.164 + conservative email + idempotent', () => {
  assert.equal(normalizeChannel('phone', '+1 (415) 555-0123').key, '+14155550123');
  assert.equal(normalizeChannel('phone', '415-555-0123').unnormalizable, true); // no country code
  assert.equal(normalizeChannel('email', '  Foo@Bar.COM ').key, 'foo@bar.com');
  assert.equal(normalizeChannel('email', 'a+tag@x.com').key, 'a+tag@x.com'); // +tag preserved (no over-merge)
  const once = normalizeChannel('telegram', '@Handle');
  assert.equal(once.key, normalizeChannel('telegram', once.key).key); // idempotent
});

// Minimal valid TrustEdge factory (only fields dedup reads matter; rest satisfies the type at compile).
const edge = (over: Record<string, unknown> = {}) => ({
  id: 'x', peer_fingerprint: '', peer_name: 'n', peer_email: '', peer_public_key: '',
  trusted: false, trusted_since: null, last_interaction: '', decay_days: 730,
  trust_history: [], verification: { method: 'none', verified_at: null },
  mutual: { they_trust_me: null, last_sync: null, reciprocal: false },
  tags: [], notes: '', connection_channels: [], added_at: '', ...over,
}) as any;

test('edgeChannels: pulls peer_email + contact_info.{phone,emails,handles}', () => {
  const e = edge({ peer_email: 'A@B.com', contact_info: { phone: '+14155550123', emails: ['c@d.com'], handles: { telegram: '@h' } } });
  const keys = edgeChannels(e).map(dedupKey).filter(Boolean);
  assert.ok(keys.includes('email:a@b.com'));
  assert.ok(keys.includes('phone:+14155550123'));
  assert.ok(keys.includes('email:c@d.com'));
  assert.ok(keys.includes('telegram:h'));
});

test('sharesChannel: matches on any normalized collision, across fields', () => {
  const a = edge({ peer_email: 'shared@x.com' });
  const b = edge({ id: 'y', contact_info: { emails: ['SHARED@x.com'] } }); // case-folds to same
  assert.equal(sharesChannel(a, b), true);
  assert.equal(sharesChannel(a, edge({ id: 'z', peer_email: 'other@x.com' })), false);
});

test('livingWinsSurvivor: trusted > known > gray, deterministic by arg order', () => {
  const gray = edge({ id: 'g', peer_fingerprint: '' });
  const known = edge({ id: 'k', peer_fingerprint: 'FP1', trusted: false });
  const trusted = edge({ id: 't', peer_fingerprint: 'FP2', trusted: true });
  assert.equal(livingWinsSurvivor(gray, known).id, 'k');
  assert.equal(livingWinsSurvivor(known, trusted).id, 't');
  assert.equal(livingWinsSurvivor(gray, trusted).id, 't');
  assert.equal(livingWinsSurvivor(trusted, gray).id, 't'); // order-independent
});
