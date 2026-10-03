// /allowed proxy forwards the satellite mutual-connection ops (allowed_senders) that PSI /initiate's
// mutual-gate reads. POST add (body-allowlisted {sender_fingerprint, signature}); DELETE revoke + GET
// list carry the X-Signature header. The DELETE is the #111-satellite-completeness leg (block/untrust
// must revoke the satellite entry, else a blocked adversary's client still discovers the survivor).
// Locks allowlist + path-guard + method/header forwarding so a future edit can't silently regress it.
// Run: npx tsx --test src/lib/sync/allowed-proxy.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
import { POST, DELETE, GET } from '../../../app/api/satellite/allowed/[...path]/route';

const SAT = 'http://registration:8101';
const OWNER = 'o'.repeat(64);
const SENDER = 's'.repeat(64);

function stubFetch(status: number, body: unknown): {
  calls: Array<{ url: string; init?: RequestInit }>;
  restore: () => void;
} {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const orig = globalThis.fetch;
  globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), init });
    return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  return { calls, restore: () => { globalThis.fetch = orig; } };
}

const P = (path: string[]) => ({ params: Promise.resolve({ path }) });

function postReq(body: string): NextRequest {
  return new NextRequest('http://localhost/api/satellite/allowed/owner', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  });
}

test('POST add forwards {sender_fingerprint, signature} to /allowed/{owner}, strips extras', async () => {
  const f = stubFetch(200, { status: 'allowed', mutual: false });
  try {
    const res = await POST(
      postReq(JSON.stringify({
        sender_fingerprint: SENDER,
        signature: '1700000000:YmFzZTY0c2ln',
        tags: ['x'], display_name: 'leak', // device-local extras must NOT forward
      })),
      P([OWNER]),
    );
    assert.equal(res.status, 200);
    assert.equal(f.calls.length, 1);
    assert.equal(f.calls[0].url, `${SAT}/allowed/${OWNER}`);
    const sent = JSON.parse(f.calls[0].init!.body as string);
    assert.deepEqual(Object.keys(sent).sort(), ['sender_fingerprint', 'signature']);
  } finally { f.restore(); }
});

test('POST without signature → 400, no satellite call', async () => {
  const f = stubFetch(200, {});
  try {
    const res = await POST(postReq(JSON.stringify({ sender_fingerprint: SENDER })), P([OWNER]));
    assert.equal(res.status, 400);
    assert.equal(f.calls.length, 0);
  } finally { f.restore(); }
});

test('path traversal rejected → 400, no satellite call', async () => {
  const f = stubFetch(200, {});
  try {
    const res = await POST(postReq(JSON.stringify({ sender_fingerprint: SENDER, signature: 'x' })), P(['..', 'etc']));
    assert.equal(res.status, 400);
    assert.equal(f.calls.length, 0);
  } finally { f.restore(); }
});

test('DELETE revoke forwards to /allowed/{owner}/{sender} with X-Signature header', async () => {
  const f = stubFetch(200, { status: 'removed' });
  try {
    const dreq = new NextRequest('http://localhost/api/satellite/allowed/o/s', {
      method: 'DELETE',
      headers: { 'X-Signature': '1700000000:revokesig' },
    });
    const res = await DELETE(dreq, P([OWNER, SENDER]));
    assert.equal(res.status, 200);
    assert.equal(f.calls[0].url, `${SAT}/allowed/${OWNER}/${SENDER}`);
    assert.equal(f.calls[0].init!.method, 'DELETE');
    assert.equal((f.calls[0].init!.headers as Record<string, string>)['X-Signature'], '1700000000:revokesig');
  } finally { f.restore(); }
});

test('GET list forwards with X-Signature header', async () => {
  const f = stubFetch(200, { owner_fingerprint: OWNER, allowed: [], count: 0 });
  try {
    const greq = new NextRequest('http://localhost/api/satellite/allowed/o', {
      method: 'GET',
      headers: { 'X-Signature': 'listsig' },
    });
    const res = await GET(greq, P([OWNER]));
    assert.equal(res.status, 200);
    assert.equal(f.calls[0].url, `${SAT}/allowed/${OWNER}`);
    assert.equal((f.calls[0].init?.headers as Record<string, string>)['X-Signature'], 'listsig');
  } finally { f.restore(); }
});
