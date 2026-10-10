// src/lib/config/domain.test.ts
// Domain/link config — the one self-hoster knob + the share-link shapes it produces.
// Run: npx tsx --test src/lib/config/domain.test.ts
//
// domain.ts reads NEXT_PUBLIC_* at MODULE-EVAL time (consts, not lazy), so a changed env can
// only be observed in a FRESH process — an in-process `import('./domain.ts?case=N')`
// cache-bust is loader-dependent (some tsx builds hand back the already-evaluated module, in
// which case the override silently reads back as the default). Each env case therefore spawns
// the sibling helper FILE `__domain-env-probe.ts` with the env preset and asserts on the JSON
// snapshot it prints. A helper file (not an inline `tsx -e` string) keeps the spawn portable
// across tsx/node versions and platforms.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { SVRNTY_BASE_URL, SVRNTY_DOMAIN, shareUrl, shareUrlShort } from './domain';
import { SNAPSHOT_MARKER } from './__domain-env-probe';

/** What a subprocess evaluation of domain.ts reports back. */
interface DomainSnapshot {
  SVRNTY_DOMAIN: string;
  SVRNTY_BASE_URL: string;
  shareUrl: string;
  shareUrlShortNoKey: string;
  shareUrlShortWithKey: string;
}

const PROBE_PATH = fileURLToPath(new URL('./__domain-env-probe.ts', import.meta.url));

/** How to run a .ts file in a child process: the resolved tsx CLI, else `npx tsx`. */
function probeCommands(): Array<{ file: string; args: string[] }> {
  const candidates: Array<{ file: string; args: string[] }> = [];
  try {
    const tsxCli = createRequire(import.meta.url).resolve('tsx/cli');
    candidates.push({ file: process.execPath, args: [tsxCli, PROBE_PATH] });
  } catch {
    // tsx/cli not resolvable from here — fall through to npx.
  }
  candidates.push({ file: 'npx', args: ['--no-install', 'tsx', PROBE_PATH] });
  return candidates;
}

/**
 * Evaluate domain.ts in a child process under the given NEXT_PUBLIC_* env (any not listed is
 * unset, so defaults are defaults even on a machine that sets them) and return its outputs.
 * `probe` chooses the arguments the link helpers are called with.
 */
function loadWithEnv(
  env: { NEXT_PUBLIC_SVRNTY_DOMAIN?: string; NEXT_PUBLIC_SVRNTY_BASE_URL?: string },
  probe: { code?: string; key?: string; slug?: string } = {},
): DomainSnapshot {
  const childEnv: NodeJS.ProcessEnv = { ...process.env };
  delete childEnv.NEXT_PUBLIC_SVRNTY_DOMAIN;
  delete childEnv.NEXT_PUBLIC_SVRNTY_BASE_URL;

  const failures: string[] = [];
  for (const { file, args } of probeCommands()) {
    let stdout: string;
    try {
      stdout = execFileSync(file, args, {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          ...childEnv,
          ...env,
          __PROBE_CODE: probe.code ?? 'ABC123',
          __PROBE_KEY: probe.key ?? 'k',
          __PROBE_SLUG: probe.slug ?? 'alice',
        },
      });
    } catch (err) {
      // Surface the child's own stderr — `Command failed: …` alone says nothing.
      const e = err as { stderr?: Buffer | string; stdout?: Buffer | string; message?: string };
      failures.push(`${file} ${args.join(' ')}\n${e.stderr ?? e.stdout ?? e.message ?? err}`);
      continue;
    }

    const at = stdout.lastIndexOf(SNAPSHOT_MARKER);
    if (at === -1) {
      failures.push(`${file} ${args.join(' ')}\nno snapshot marker in stdout:\n${stdout}`);
      continue;
    }
    return JSON.parse(stdout.slice(at + SNAPSHOT_MARKER.length)) as DomainSnapshot;
  }

  throw new Error(`env probe failed for ${JSON.stringify(env)}:\n\n${failures.join('\n\n')}`);
}

// --- SVRNTY_DOMAIN / SVRNTY_BASE_URL -------------------------------------------------

test('the harness really observes an override (guards against a hollow pass)', () => {
  // If the subprocess/env plumbing silently failed, every override case below would read
  // back the default and pass vacuously. Assert the two differ before trusting them.
  const base = loadWithEnv({});
  const overridden = loadWithEnv({ NEXT_PUBLIC_SVRNTY_DOMAIN: 'id.example.com' });
  assert.notEqual(overridden.SVRNTY_DOMAIN, base.SVRNTY_DOMAIN);
});

test('defaults: svrnty.is / https://svrnty.is when no env override is set', () => {
  const snap = loadWithEnv({});
  assert.equal(snap.SVRNTY_DOMAIN, 'svrnty.is');
  assert.equal(snap.SVRNTY_BASE_URL, 'https://svrnty.is');
});

test('default base URL carries a scheme; default domain does not', () => {
  const snap = loadWithEnv({});
  assert.ok(snap.SVRNTY_BASE_URL.startsWith('https://'));
  assert.ok(!snap.SVRNTY_DOMAIN.includes('://'));
});

test('NEXT_PUBLIC_SVRNTY_DOMAIN overrides the domain AND derives the base URL', () => {
  const snap = loadWithEnv({ NEXT_PUBLIC_SVRNTY_DOMAIN: 'id.example.com' });
  assert.equal(snap.SVRNTY_DOMAIN, 'id.example.com');
  assert.equal(snap.SVRNTY_BASE_URL, 'https://id.example.com');
});

test('NEXT_PUBLIC_SVRNTY_BASE_URL overrides the base URL independently of the domain', () => {
  const snap = loadWithEnv({ NEXT_PUBLIC_SVRNTY_BASE_URL: 'http://localhost:3000' });
  assert.equal(snap.SVRNTY_DOMAIN, 'svrnty.is'); // untouched
  assert.equal(snap.SVRNTY_BASE_URL, 'http://localhost:3000');
});

test('both overrides set: each is honored verbatim (base URL is NOT re-derived)', () => {
  const snap = loadWithEnv({
    NEXT_PUBLIC_SVRNTY_DOMAIN: 'id.example.com',
    NEXT_PUBLIC_SVRNTY_BASE_URL: 'http://id.example.com:8080',
  });
  assert.equal(snap.SVRNTY_DOMAIN, 'id.example.com');
  assert.equal(snap.SVRNTY_BASE_URL, 'http://id.example.com:8080');
});

test('empty-string env vars fall back to the defaults (|| semantics)', () => {
  const snap = loadWithEnv({
    NEXT_PUBLIC_SVRNTY_DOMAIN: '',
    NEXT_PUBLIC_SVRNTY_BASE_URL: '',
  });
  assert.equal(snap.SVRNTY_DOMAIN, 'svrnty.is');
  assert.equal(snap.SVRNTY_BASE_URL, 'https://svrnty.is');
});

test('self-host override propagates to every link helper — no svrnty.is left behind', () => {
  const snap = loadWithEnv({ NEXT_PUBLIC_SVRNTY_DOMAIN: 'id.example.com' });
  assert.equal(snap.shareUrl, 'https://id.example.com/c/ABC123#k');
  assert.equal(snap.shareUrlShortNoKey, 'id.example.com/c/ABC123');
  assert.equal(snap.shareUrlShortWithKey, 'id.example.com/c/ABC123#k');
  for (const link of [snap.shareUrl, snap.shareUrlShortWithKey]) {
    assert.ok(!link.includes('svrnty.is'), `leaked default domain: ${link}`);
  }
});

test('INVARIANT holds under a self-host override: the key stays after the #', () => {
  const snap = loadWithEnv({ NEXT_PUBLIC_SVRNTY_DOMAIN: 'id.example.com' }, { key: 'sEcReTkEy' });
  const u = new URL(snap.shareUrl);
  assert.equal(u.hash, '#sEcReTkEy');
  assert.ok(!`${u.origin}${u.pathname}${u.search}`.includes('sEcReTkEy'));
});

test('a base-URL override with a trailing slash is used verbatim (documents current behavior)', () => {
  const snap = loadWithEnv({ NEXT_PUBLIC_SVRNTY_BASE_URL: 'https://x.example/' }, { code: 'ABC' });
  assert.equal(snap.shareUrl, 'https://x.example//c/ABC#k');
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
    // The real shape: relay.ts hands in base64url(raw AES key) — includes '-' and '_'.
    ['r3lAyC0d3', 'Zm9vYmFy-_0123456789abcdefGHIJKLMNOPQRSTUV'],
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

test('shareUrlShort is the scheme-less form of shareUrl for the same inputs', () => {
  const snap = loadWithEnv({});
  assert.equal(snap.shareUrl, `https://${snap.shareUrlShortWithKey}`);
});

// (slugUrlShort removed — dead public-URL functionality dropped in #176; see __domain-env-probe.ts)
