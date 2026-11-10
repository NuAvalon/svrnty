// The script lock: one policy, a new nonce per response, set by middleware so the header and
// the HTML come from the same place. Run: npx tsx --test src/lib/csp.test.ts
import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { NextRequest } from 'next/server';
import { makeScriptNonce, buildCsp } from './csp';
import { middleware, config } from '../../middleware';

const ROOT = path.resolve(__dirname, '../..');
const req = (p: string, headers: Record<string, string> = {}) =>
  new NextRequest(`https://svrnty.test${p}`, { headers });
const cspOf = (r: Response) => r.headers.get('content-security-policy') ?? '';
function nonceOf(csp: string): string {
  const m = /'nonce-([^']+)'/.exec(csp);
  assert.ok(m, `no nonce in: ${csp}`);
  return m![1];
}
const P = (n: string) =>
  `default-src 'self'; script-src 'self' 'nonce-${n}'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; media-src 'self' blob:; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`;
const directives = (csp: string) =>
  new Map(csp.split(';').map((d) => d.trim().split(/\s+/)).map(([name, ...values]) => [name, values] as const));

test('the nonce is 128 bits of canonical base64', () => {
  const n = makeScriptNonce();
  assert.equal(Buffer.from(n, 'base64').length, 16);
  assert.equal(Buffer.from(n, 'base64').toString('base64'), n);
  assert.match(n, /^[A-Za-z0-9+/]{22}==$/);
});

test('the nonce is taken from the platform CSPRNG, 16 bytes', () => {
  const spy = mock.method(globalThis.crypto, 'getRandomValues', (a: Uint8Array) => a.fill(7));
  try {
    assert.equal(makeScriptNonce(), Buffer.alloc(16, 7).toString('base64'));
    assert.equal(spy.mock.callCount(), 1);
    assert.equal((spy.mock.calls[0].arguments[0] as Uint8Array).length, 16);
  } finally { spy.mock.restore(); }
});

test('nonces do not repeat', () => {
  const s = new Set(Array.from({ length: 2000 }, makeScriptNonce));
  assert.equal(s.size, 2000);
});

test('the production policy is exactly this', () => {
  assert.equal(buildCsp('abc', { dev: false }), P('abc'));
});

test('script-src never holds a token that lets injected script run', () => {
  const script = directives(buildCsp('abc', { dev: false })).get('script-src')!;
  assert.deepEqual(script, ["'self'", "'nonce-abc'"]);
  for (const bad of ["'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'", "'wasm-unsafe-eval'"]) {
    assert.ok(!script.includes(bad), `found ${bad}`);
  }
});

test("'unsafe-inline' appears on style-src and nowhere else", () => {
  for (const [name, values] of directives(buildCsp('abc', { dev: false }))) {
    assert.equal(values.includes("'unsafe-inline'"), name === 'style-src', name);
  }
});

test("connect-src is exactly 'self', and default-src backs up every other kind of load", () => {
  const d = directives(buildCsp('abc', { dev: false }));
  assert.deepEqual(d.get('connect-src'), ["'self'"]);
  assert.deepEqual(d.get('default-src'), ["'self'"]);
});

test('no directive allows a whole scheme or any host', () => {
  for (const [name, values] of directives(buildCsp('abc', { dev: false }))) {
    for (const bad of ['*', 'https:', 'http:', 'ws:', 'wss:']) assert.ok(!values.includes(bad), `${name} has ${bad}`);
    for (const v of values) assert.ok(!/\/\//.test(v), `${name} names a host: ${v}`);
  }
});

test("dev mode adds only 'unsafe-eval', and never 'unsafe-inline'", () => {
  assert.equal(
    buildCsp('abc', { dev: true }),
    P('abc').replace("'nonce-abc'", "'nonce-abc' 'unsafe-eval'"),
  );
});

for (const p of ['/', '/msg', '/u/alice', '/c/abc123', '/dev/seals', '/a/b/c']) {
  test(`${p}: header and request override carry the same fresh nonce`, () => {
    const r = middleware(req(p));
    const csp = cspOf(r);
    const n = nonceOf(csp);
    assert.equal(csp, P(n));
    assert.equal(r.headers.get('x-middleware-request-x-nonce'), n);
    assert.equal(r.headers.get('x-middleware-request-content-security-policy'), csp);
    const over = (r.headers.get('x-middleware-override-headers') ?? '').split(',');
    assert.ok(over.includes('x-nonce') && over.includes('content-security-policy'), over.join());
  });
}

test('/alice is rewritten to the profile page and still gets the policy and the override', () => {
  const r = middleware(req('/alice'));
  assert.match(r.headers.get('x-middleware-rewrite') ?? '', /\/u\/alice$/);
  const csp = cspOf(r);
  const n = nonceOf(csp);
  assert.equal(r.headers.get('x-middleware-request-x-nonce'), n);
  assert.equal(r.headers.get('x-middleware-request-content-security-policy'), csp);
});

test('reserved names are not rewritten', () => {
  assert.equal(middleware(req('/msg')).headers.get('x-middleware-rewrite'), null);
});

for (const p of ['/', '/alice']) {
  test(`${p}: a client cannot choose the nonce or the policy`, () => {
    const r = middleware(req(p, { 'x-nonce': 'evil', 'content-security-policy': "script-src 'nonce-evil'" }));
    const n = nonceOf(cspOf(r));
    assert.notEqual(n, 'evil');
    assert.equal(r.headers.get('x-middleware-request-x-nonce'), n);
    assert.ok(!(r.headers.get('x-middleware-request-content-security-policy') ?? '').includes('evil'));
  });
}

test('two responses never share a nonce', () => {
  assert.notEqual(nonceOf(cspOf(middleware(req('/')))), nonceOf(cspOf(middleware(req('/')))));
});

for (const p of ['/api/version', '/api/whatever/x', '/_next/webpack-hmr']) {
  test(`${p}: not a page, so it gets no policy and no nonce`, () => {
    const r = middleware(req(p));
    assert.equal(cspOf(r), '');
    assert.equal(r.headers.get('x-middleware-request-x-nonce'), null);
  });
}

test('the build-time dev switch: only development gets unsafe-eval', () => {
  const was = process.env.NODE_ENV;
  const env = process.env as Record<string, string | undefined>;
  try {
    env.NODE_ENV = 'development';
    assert.ok(cspOf(middleware(req('/'))).includes("'unsafe-eval'"));
    env.NODE_ENV = 'production';
    assert.ok(!cspOf(middleware(req('/'))).includes("'unsafe-eval'"));
    env.NODE_ENV = 'test';
    assert.ok(!cspOf(middleware(req('/'))).includes("'unsafe-eval'"));
  } finally { env.NODE_ENV = was; }
});

test('the matcher still keeps relay bodies out of middleware and still covers pages', () => {
  const m = new RegExp(`^${config.matcher[0]}$`);
  for (const p of ['/api/relay', '/api/relay/envelope', '/api/relay/ack', '/_next/static/x.js']) assert.equal(m.test(p), false, p);
  for (const p of ['/', '/msg', '/u/a', '/c/a', '/a']) assert.equal(m.test(p), true, p);
});

test('every inline script in the root layout carries the nonce', () => {
  const src = fs.readFileSync(path.join(ROOT, 'app/layout.tsx'), 'utf8');
  assert.equal((src.match(/<script\b/g) ?? []).length, 3);
  const tags = src.match(/<script\b[^>]*?dangerouslySetInnerHTML/g) ?? [];
  assert.equal(tags.length, 3);
  for (const t of tags) assert.match(t, /nonce=\{nonce\}/, t);
});

test('the root layout is per-request and reads the nonce from the request', () => {
  const src = fs.readFileSync(path.join(ROOT, 'app/layout.tsx'), 'utf8');
  assert.match(src, /export const dynamic = 'force-dynamic'/);
  assert.match(src, /\(await headers\(\)\)\.get\('x-nonce'\)/);
  assert.match(src, /export default async function RootLayout/);
});

test('the self-host Caddyfile leaves the policy to the app and still refuses framing', () => {
  const live = fs.readFileSync(path.join(ROOT, 'Caddyfile'), 'utf8').split('\n').filter((l) => !l.trim().startsWith('#')).join('\n');
  assert.ok(!/Content-Security-Policy/i.test(live));
  assert.match(live, /X-Frame-Options "DENY"/);
});
