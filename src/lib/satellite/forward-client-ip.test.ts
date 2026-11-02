// src/lib/satellite/forward-client-ip.test.ts
// The satellite keys its rate limits on the client address. Every /api/satellite proxy must forward the
// client IP the edge gave us, or all users share one bucket. Behaviour pins + a static fence over the routes.
// Run: npx tsx --test src/lib/satellite/forward-client-ip.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { NextRequest } from 'next/server';
import { forwardedClientIp } from './forward-client-ip';

const req = (headers: Record<string, string>) => new NextRequest('http://localhost/api/satellite/x', { headers });

test('F1 forwards the FIRST X-Forwarded-For entry (the one the edge wrote), and only that one', () => {
  assert.deepEqual(forwardedClientIp(req({ 'x-forwarded-for': '203.0.113.7' })), { 'X-Forwarded-For': '203.0.113.7' });
  assert.deepEqual(forwardedClientIp(req({ 'x-forwarded-for': '203.0.113.7, 10.0.0.1' })), { 'X-Forwarded-For': '203.0.113.7' });
  assert.deepEqual(forwardedClientIp(req({ 'x-forwarded-for': '2001:db8::1' })), { 'X-Forwarded-For': '2001:db8::1' });
});

test('F2 falls back to X-Real-IP, then forwards nothing', () => {
  assert.deepEqual(forwardedClientIp(req({ 'x-real-ip': '198.51.100.5' })), { 'X-Forwarded-For': '198.51.100.5' });
  assert.deepEqual(forwardedClientIp(req({})), {});
});

test('F3 a value that is not an IP is never forwarded', () => {
  for (const v of ['unknown', 'not-an-ip', '203.0.113.7:443', '1.2.3.4.5', ' ', 'evil.example']) {
    assert.deepEqual(forwardedClientIp(req({ 'x-forwarded-for': v })), {}, v);
  }
});

// ---- static fence: every fetch in app/api/satellite forwards the client IP ----
const ROOT = join(process.cwd(), 'app/api/satellite');
function routeFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? routeFiles(p) : n === 'route.ts' ? [p] : [];
  });
}
function fetchCalls(src: string): { at: number; call: string }[] {
  const out: { at: number; call: string }[] = [];
  for (let i = src.indexOf('fetch('); i >= 0; i = src.indexOf('fetch(', i + 6)) {
    let depth = 0, j = i + 5;
    for (; j < src.length; j++) { if (src[j] === '(') depth++; else if (src[j] === ')' && --depth === 0) break; }
    out.push({ at: i, call: src.slice(i, j + 1) });
  }
  return out;
}
const FORWARDED_HEADERS_DECL = 'const headers: Record<string, string> = { ...forwardedClientIp(request) };';
/** The `headers` a call uses is the NEAREST `const headers` declared before it (same handler), not any in the file. */
function nearestHeadersDecl(src: string, at: number): string {
  const k = src.lastIndexOf('const headers', at);
  return k < 0 ? '' : src.slice(k, src.indexOf('\n', k));
}

test('F4 FENCE: every satellite fetch passes forwardedClientIp (inline, or via a headers object built from it)', () => {
  const files = routeFiles(ROOT);
  assert.ok(files.length >= 7, `expected the satellite proxy routes, found ${files.length}`);
  let calls = 0;
  for (const f of files) {
    const src = readFileSync(f, 'utf8');
    for (const { at, call } of fetchCalls(src)) {
      calls++;
      const ok = call.includes('forwardedClientIp(request)')
        // shorthand `{ ..., headers }` (NOT an inline `headers: {...}`, which must carry the helper itself)
        || (/[{,]\s*headers\s*[,}]/.test(call) && nearestHeadersDecl(src, at).trim() === FORWARDED_HEADERS_DECL);
      assert.ok(ok, `${f}: a satellite fetch does not forward the client IP:\n${call.slice(0, 160)}`);
    }
  }
  assert.ok(calls >= 11, `expected >= 11 satellite fetch calls, found ${calls}`);
});

test('F5 end to end: the PSI proxy sends the client IP to the satellite', async () => {
  const { GET } = await import('../../../app/api/satellite/trust/psi/[...path]/route');
  const seen: Record<string, string>[] = [];
  const orig = globalThis.fetch;
  globalThis.fetch = (async (_u: unknown, init?: RequestInit) => {
    seen.push((init?.headers ?? {}) as Record<string, string>);
    return new Response('{}', { status: 200 });
  }) as typeof fetch;
  try {
    const r = new NextRequest('http://localhost/api/satellite/trust/psi/result/abc', {
      headers: { 'x-forwarded-for': '203.0.113.9', 'X-Signature': 's' },
    });
    await GET(r, { params: Promise.resolve({ path: ['result', 'abc'] }) });
  } finally {
    globalThis.fetch = orig;
  }
  assert.equal(seen.length, 1);
  assert.equal(seen[0]['X-Forwarded-For'], '203.0.113.9');
});
