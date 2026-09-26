// src/lib/config/domain.test.ts
// Domain/link config — the one self-hoster knob + the share-link shapes it produces.
// Run: npx tsx --test src/lib/config/domain.test.ts
//
// domain.ts reads NEXT_PUBLIC_* at MODULE-EVAL time, so env-override cases re-import a
// fresh module instance (cache-busting query) after setting process.env.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SVRNTY_BASE_URL, SVRNTY_DOMAIN, shareUrl, shareUrlShort, slugUrlShort } from './domain';

type DomainModule = typeof import('./domain');

let reimportCounter = 0;

/** Load a fresh copy of domain.ts with the given NEXT_PUBLIC_* env, then restore env. */
async function loadWithEnv(env: {
  NEXT_PUBLIC_SVRNTY_DOMAIN?: string;
  NEXT_PUBLIC_SVRNTY_BASE_URL?: string;
}): Promise<DomainModule> {
  const keys = ['NEXT_PUBLIC_SVRNTY_DOMAIN', 'NEXT_PUBLIC_SVRNTY_BASE_URL'] as const;
  const saved = keys.map((k) => [k, process.env[k]] as const);
  for (const k of keys) delete process.env[k];
  for (const [k, v] of Object.entries(env)) process.env[k] = v;
  try {
    return (await import(`./domain.ts?case=${reimportCounter++}`)) as DomainModule;
  } finally {
    for (const [k, v] of saved) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

// --- SVRNTY_DOMAIN / SVRNTY_BASE_URL -------------------------------------------------

test('defaults: svrnty.is / https://svrnty.is when no env override is set', async () => {
  const mod = await loadWithEnv({});
  assert.equal(mod.SVRNTY_DOMAIN, 'svrnty.is');
  assert.equal(mod.SVRNTY_BASE_URL, 'https://svrnty.is');
});

test('default base URL carries a scheme; default domain does not', async () => {
  const mod = await loadWithEnv({});
  assert.ok(mod.SVRNTY_BASE_URL.startsWith('https://'));
  assert.ok(!mod.SVRNTY_DOMAIN.includes('://'));
});

test('NEXT_PUBLIC_SVRNTY_DOMAIN overrides the domain AND derives the base URL', async () => {
  const mod = await loadWithEnv({ NEXT_PUBLIC_SVRNTY_DOMAIN: 'id.example.com' });
  assert.equal(mod.SVRNTY_DOMAIN, 'id.example.com');
  assert.equal(mod.SVRNTY_BASE_URL, 'https://id.example.com');
});

test('NEXT_PUBLIC_SVRNTY_BASE_URL overrides the base URL independently of the domain', async () => {
  const mod = await loadWithEnv({ NEXT_PUBLIC_SVRNTY_BASE_URL: 'http://localhost:3000' });
  assert.equal(mod.SVRNTY_DOMAIN, 'svrnty.is'); // untouched
  assert.equal(mod.SVRNTY_BASE_URL, 'http://localhost:3000');
});

test('both overrides set: each is honored verbatim (base URL is NOT re-derived)', async () => {
  const mod = await loadWithEnv({
    NEXT_PUBLIC_SVRNTY_DOMAIN: 'id.example.com',
    NEXT_PUBLIC_SVRNTY_BASE_URL: 'http://id.example.com:8080',
  });
  assert.equal(mod.SVRNTY_DOMAIN, 'id.example.com');
  assert.equal(mod.SVRNTY_BASE_URL, 'http://id.example.com:8080');
});

test('empty-string env vars fall back to the defaults (|| semantics)', async () => {
  const mod = await loadWithEnv({
    NEXT_PUBLIC_SVRNTY_DOMAIN: '',
    NEXT_PUBLIC_SVRNTY_BASE_URL: '',
  });
  assert.equal(mod.SVRNTY_DOMAIN, 'svrnty.is');
  assert.equal(mod.SVRNTY_BASE_URL, 'https://svrnty.is');
});

test('self-host override propagates to every link helper — no svrnty.is left behind', async () => {
  const mod = await loadWithEnv({ NEXT_PUBLIC_SVRNTY_DOMAIN: 'id.example.com' });
  assert.equal(mod.shareUrl('ABC123', 'k'), 'https://id.example.com/c/ABC123#k');
  assert.equal(mod.shareUrlShort('ABC123'), 'id.example.com/c/ABC123');
  assert.equal(mod.shareUrlShort('ABC123', 'k'), 'id.example.com/c/ABC123#k');
  assert.equal(mod.slugUrlShort('alice'), 'id.example.com/alice');
  for (const link of [
    mod.shareUrl('ABC123', 'k'),
    mod.shareUrlShort('ABC123', 'k'),
    mod.slugUrlShort('alice'),
  ]) {
    assert.ok(!link.includes('svrnty.is'), `leaked default domain: ${link}`);
  }
});

test('a base-URL override with a trailing slash is used verbatim (documents current behavior)', async () => {
  const mod = await loadWithEnv({ NEXT_PUBLIC_SVRNTY_BASE_URL: 'https://x.example/' });
  assert.equal(mod.shareUrl('ABC', 'k'), 'https://x.example//c/ABC#k');
});

// --- shareUrl ------------------------------------------------------------------------

test('shareUrl: `${base}/c/${code}#${keyFragment}`', () => {
  assert.equal(shareUrl('ABC123', 'sEcReTkEy'), `${SVRNTY_BASE_URL}/c/ABC123#sEcReTkEy`);
});

test('shareUrl parses as a URL whose path is /c/<code> and whose hash holds the key', () => {
  const u = new URL(shareUrl('ABC123', 'sEcReTkEy'));
  assert.equal(u.pathname, '/c/ABC123');
  assert.equal(u.hash, '#sEcReTkEy');
  assert.equal(u.search, '');
});

test('INVARIANT: the key fragment is always AFTER the #, never in path or query', () => {
  const cases: Array<[string, string]> = [
    ['ABC123', 'sEcReTkEy'],
    ['aa', 'k'],
    ['CODE-with-dashes', 'AAAA1111bbbb2222'],
    ['0', 'ZZZ'],
    ['LONGCODE1234567890', 'x'.repeat(256)],
  ];
  for (const [code, key] of cases) {
    const url = shareUrl(code, key);
    const hashIndex = url.indexOf('#');
    assert.ok(hashIndex !== -1, `no fragment delimiter in ${url}`);

    const beforeHash = url.slice(0, hashIndex);
    const afterHash = url.slice(hashIndex + 1);

    // The key lives entirely in the fragment...
    assert.equal(afterHash, key);
    // ...and nowhere in the server-visible half (origin + path + query).
    assert.ok(!beforeHash.includes(key), `key leaked into server-visible part: ${beforeHash}`);

    // Parsed view: nothing the server receives carries the key.
    const u = new URL(url);
    assert.equal(u.hash, `#${key}`);
    assert.ok(!u.pathname.includes(key), `key leaked into path: ${u.pathname}`);
    assert.equal(u.search, '', 'share links must not carry a query string');
    assert.ok(!u.search.includes(key));
    assert.ok(!`${u.origin}${u.pathname}${u.search}`.includes(key));
  }
});

test('INVARIANT: exactly one # — the key cannot be split across the path boundary', () => {
  const url = shareUrl('ABC123', 'key');
  assert.equal(url.split('#').length - 1, 1);
});

test('shareUrl: the code sits in the path, before the fragment', () => {
  const url = shareUrl('ABC123', 'key');
  const [beforeHash] = url.split('#');
  assert.ok(beforeHash.endsWith('/c/ABC123'));
});

test('shareUrl: an empty key fragment still emits the # delimiter', () => {
  assert.equal(shareUrl('ABC123', ''), `${SVRNTY_BASE_URL}/c/ABC123#`);
});

test('shareUrl: an empty code yields the /c/ path with the key still in the fragment', () => {
  const url = shareUrl('', 'k');
  assert.equal(url, `${SVRNTY_BASE_URL}/c/#k`);
  assert.equal(new URL(url).pathname, '/c/');
});

test('shareUrl is pure — same inputs, same output, no mutation of inputs', () => {
  assert.equal(shareUrl('ABC123', 'k'), shareUrl('ABC123', 'k'));
  assert.notEqual(shareUrl('ABC123', 'k'), shareUrl('ABC124', 'k'));
  assert.notEqual(shareUrl('ABC123', 'k1'), shareUrl('ABC123', 'k2'));
});

// --- shareUrlShort -------------------------------------------------------------------

test('shareUrlShort without a key: scheme-less `${domain}/c/${code}`, no fragment', () => {
  const s = shareUrlShort('ABC123');
  assert.equal(s, `${SVRNTY_DOMAIN}/c/ABC123`);
  assert.ok(!s.includes('#'));
  assert.ok(!s.includes('://'));
});

test('shareUrlShort with a key: `${domain}/c/${code}#${keyFragment}`', () => {
  const s = shareUrlShort('ABC123', 'sEcReTkEy');
  assert.equal(s, `${SVRNTY_DOMAIN}/c/ABC123#sEcReTkEy`);
  assert.ok(!s.includes('://'));
});

test('shareUrlShort: an explicit undefined key behaves like the omitted argument', () => {
  assert.equal(shareUrlShort('ABC123', undefined), shareUrlShort('ABC123'));
});

test('shareUrlShort: an empty-string key is falsy → the no-key form (no trailing #)', () => {
  const s = shareUrlShort('ABC123', '');
  assert.equal(s, `${SVRNTY_DOMAIN}/c/ABC123`);
  assert.ok(!s.includes('#'));
});

test('INVARIANT: shareUrlShort keeps the key after the #, never in the path', () => {
  const key = 'sEcReTkEy';
  const s = shareUrlShort('ABC123', key);
  const hashIndex = s.indexOf('#');
  assert.ok(hashIndex !== -1);
  assert.equal(s.slice(hashIndex + 1), key);
  assert.ok(!s.slice(0, hashIndex).includes(key));
  assert.ok(!s.includes('?'), 'display links must not carry a query string');
});

test('shareUrlShort is the scheme-less form of shareUrl for the same inputs', async () => {
  const mod = await loadWithEnv({});
  assert.equal(mod.shareUrl('ABC123', 'k'), `https://${mod.shareUrlShort('ABC123', 'k')}`);
});

// --- slugUrlShort --------------------------------------------------------------------

test('slugUrlShort: `${domain}/${slug}` — scheme-less, no /c/ segment', () => {
  const s = slugUrlShort('alice');
  assert.equal(s, `${SVRNTY_DOMAIN}/alice`);
  assert.ok(!s.includes('://'));
  assert.ok(!s.includes('/c/'));
  assert.ok(!s.includes('#'));
});

test('slugUrlShort: an empty slug yields a bare trailing slash', () => {
  assert.equal(slugUrlShort(''), `${SVRNTY_DOMAIN}/`);
});

test('slugUrlShort: the slug is interpolated verbatim (documents current behavior)', () => {
  assert.equal(slugUrlShort('a.b_c-d'), `${SVRNTY_DOMAIN}/a.b_c-d`);
});

test('slugUrlShort and shareUrlShort share the same domain prefix', () => {
  assert.ok(slugUrlShort('alice').startsWith(`${SVRNTY_DOMAIN}/`));
  assert.ok(shareUrlShort('ABC').startsWith(`${SVRNTY_DOMAIN}/`));
});
