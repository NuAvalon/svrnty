// /bind proxy forwards the satellite's tag#3 bind contract {fingerprint, sig_pubkey, nonce, epoch,
// binding_sig} — NOT the old sign_pubkey/signature (the deployed satellite 422'd those, blocking every
// bind). Locks the field-name alignment so a future edit can't silently regress it.
// Run: npx tsx --test src/lib/sync/bind-proxy.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
import { POST } from '../../../app/api/satellite/bind/route';

const SAT = 'http://registration:8101';

function validBind(): Record<string, unknown> {
  return {
    fingerprint: 'a'.repeat(64),
    sig_pubkey: 'b'.repeat(64), // raw ed25519 auth pub, lowercase hex
    nonce: 'c'.repeat(32), // lowercase hex, even length
    epoch: 0,
    binding_sig: 'YmluZGluZ19zaWc=', // base64 Ed25519(identity priv, svrnty-bind:...)
  };
}

function stubFetch(status: number, body: unknown): { calls: Array<{ url: string; init?: RequestInit }>; restore: () => void } {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const orig = globalThis.fetch;
  globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), init });
    return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  return { calls, restore: () => { globalThis.fetch = orig; } };
}

function req(body: string): NextRequest {
  return new NextRequest('http://localhost/api/satellite/bind', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  });
}

test('/bind forwards the 5 satellite fields (sig_pubkey + binding_sig), nothing stripped', async () => {
  const f = stubFetch(200, { status: 'bound' });
  try {
    const body = validBind();
    const res = await POST(req(JSON.stringify(body)));
    assert.equal(res.status, 200);
    assert.equal(f.calls.length, 1);
    assert.equal(f.calls[0].url, `${SAT}/bind`);
    const sent = JSON.parse(f.calls[0].init!.body as string);
    assert.deepEqual(sent, body); // all 5 fields reach the satellite byte-for-byte
  } finally {
    f.restore();
  }
});

test('/bind rejects the OLD sign_pubkey/signature shape → 400, no satellite call (the 422 blocker)', async () => {
  const f = stubFetch(200, { status: 'bound' });
  try {
    const old = { fingerprint: 'a'.repeat(64), sign_pubkey: 'b'.repeat(64), nonce: 'c'.repeat(32), epoch: 0, signature: 'x' };
    const res = await POST(req(JSON.stringify(old)));
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, 'fingerprint, sig_pubkey, and binding_sig are required');
    assert.equal(f.calls.length, 0);
  } finally {
    f.restore();
  }
});

test('/bind strips unknown/device-local extras (allowlist discipline)', async () => {
  const f = stubFetch(200, { status: 'bound' });
  try {
    const res = await POST(req(JSON.stringify({ ...validBind(), tags: ['x'], display_name: 'leak', signature: 'old' })));
    assert.equal(res.status, 200);
    const sent = JSON.parse(f.calls[0].init!.body as string);
    assert.deepEqual(Object.keys(sent).sort(), ['binding_sig', 'epoch', 'fingerprint', 'nonce', 'sig_pubkey']);
  } finally {
    f.restore();
  }
});
