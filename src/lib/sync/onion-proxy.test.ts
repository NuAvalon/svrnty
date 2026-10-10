// /onion deposit + /route/{route_id} poll proxy: forward the sealed envelope OPAQUE (the #179 no-strip
// lesson, both directions), allowlist device-local extras OUT, validate the route_id shape.
// Run: npx tsx --test src/lib/sync/onion-proxy.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
import { POST as ONION_POST } from '../../../app/api/satellite/onion/route';
import { GET as ROUTE_GET } from '../../../app/api/satellite/route/[route_id]/route';

const SAT = 'http://registration:8101';

// A well-formed onion OUTER cell = a MailboxEnvelopePackage (mailbox-envelope.ts:39).
function sealedCell(): Record<string, unknown> {
  return {
    v: 1,
    alg: 'x25519-mlkem1024-aes256gcm',
    mailbox_fp: 'a'.repeat(64),
    epk: 'ZXBr', // base64 placeholder
    kem_ct: 'a2VtX2N0',
    nonce: 'bm9uY2U',
    ct: 'Y2lwaGVydGV4dA',
  };
}

type Captured = { url: string; init?: RequestInit };

function stubFetch(status: number, body: unknown): { calls: Captured[]; restore: () => void } {
  const calls: Captured[] = [];
  const orig = globalThis.fetch;
  globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), init });
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  return { calls, restore: () => { globalThis.fetch = orig; } };
}

function onionReq(body: string): NextRequest {
  return new NextRequest('http://localhost/api/satellite/onion', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  });
}

// ── /onion deposit ───────────────────────────────────────────────────────────────────────────────────

test('/onion forwards all 7 envelope fields byte-exact — NOTHING stripped (#179)', async () => {
  const f = stubFetch(200, { deposited: true });
  try {
    const cell = sealedCell();
    const res = await ONION_POST(onionReq(JSON.stringify(cell)));
    assert.equal(res.status, 200);
    assert.equal(f.calls.length, 1);
    assert.equal(f.calls[0].url, `${SAT}/onion`);
    const sent = JSON.parse(f.calls[0].init!.body as string);
    // Every field the client sealed must reach the satellite — a stripped field = unpeelable = silent fail.
    assert.deepEqual(sent, cell);
  } finally {
    f.restore();
  }
});

test('/onion strips device-local / unknown extras (allowlist discipline)', async () => {
  const f = stubFetch(200, { deposited: true });
  try {
    const cell = { ...sealedCell(), tags: ['dv'], blocked: true, group: 'x', note: 'leak-me' };
    const res = await ONION_POST(onionReq(JSON.stringify(cell)));
    assert.equal(res.status, 200);
    const sent = JSON.parse(f.calls[0].init!.body as string);
    assert.deepEqual(Object.keys(sent).sort(), ['alg', 'ct', 'epk', 'kem_ct', 'mailbox_fp', 'nonce', 'v']);
    assert.equal('tags' in sent, false);
    assert.equal('blocked' in sent, false);
  } finally {
    f.restore();
  }
});

test('/onion rejects a cell missing a crypto field → 400, no satellite call', async () => {
  const f = stubFetch(200, { deposited: true });
  try {
    const { kem_ct, ...partial } = sealedCell();
    void kem_ct;
    const res = await ONION_POST(onionReq(JSON.stringify(partial)));
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, 'Invalid onion cell');
    assert.equal(f.calls.length, 0);
  } finally {
    f.restore();
  }
});

test('/onion rejects wrong version (v!==1) → 400', async () => {
  const f = stubFetch(200, { deposited: true });
  try {
    const res = await ONION_POST(onionReq(JSON.stringify({ ...sealedCell(), v: 2 })));
    assert.equal(res.status, 400);
    assert.equal(f.calls.length, 0);
  } finally {
    f.restore();
  }
});

test('/onion empty / non-object body → 400 Invalid request body', async () => {
  const f = stubFetch(200, {});
  try {
    assert.equal((await ONION_POST(onionReq(''))).status, 400);
    assert.equal((await ONION_POST(onionReq('[]'))).status, 400);
    assert.equal(f.calls.length, 0);
  } finally {
    f.restore();
  }
});

test('/onion relays the satellite status verbatim (uniform-400 is NOT masked)', async () => {
  const f = stubFetch(400, { error: 'bad cell' });
  try {
    const res = await ONION_POST(onionReq(JSON.stringify(sealedCell())));
    assert.equal(res.status, 400); // satellite's own 400 passes through, no proxy oracle layered on
    assert.equal(f.calls.length, 1);
  } finally {
    f.restore();
  }
});

// ── /route/{route_id} poll ───────────────────────────────────────────────────────────────────────────

const VALID_ID = 'deadbeef'.repeat(4); // 32 hex chars

function routeParams(id: string) {
  return { params: Promise.resolve({ route_id: id }) };
}

test('/route forwards a valid 32-hex route_id and relays the cells verbatim', async () => {
  const cells = [{ alg: 'x', epk: 'e', kem_ct: 'k', nonce: 'n', ct: 'c' }];
  const f = stubFetch(200, { cells });
  try {
    const req = new NextRequest(`http://localhost/api/satellite/route/${VALID_ID}`);
    const res = await ROUTE_GET(req, routeParams(VALID_ID));
    assert.equal(res.status, 200);
    assert.equal(f.calls[0].url, `${SAT}/route/${VALID_ID}`);
    assert.deepEqual((await res.json()).cells, cells);
  } finally {
    f.restore();
  }
});

test('/route rejects non-hex / wrong-length / path-traversal route_id → 400, no satellite call', async () => {
  const f = stubFetch(200, { cells: [] });
  try {
    for (const bad of ['short', 'g'.repeat(32), '../secret', VALID_ID + 'ff', `${VALID_ID.slice(0, 30)}/x`]) {
      const req = new NextRequest(`http://localhost/api/satellite/route/x`);
      const res = await ROUTE_GET(req, routeParams(bad));
      assert.equal(res.status, 400, `expected 400 for ${bad}`);
    }
    assert.equal(f.calls.length, 0);
  } finally {
    f.restore();
  }
});
