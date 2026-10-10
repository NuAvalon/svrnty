// Empty / invalid PSI POST body must 400 (never throw / never 502).
// Run: npx tsx --test src/lib/sync/psi-proxy-empty-body.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
import { POST } from '../../../app/api/satellite/trust/psi/[...path]/route';

const params = { params: Promise.resolve({ path: ['sync'] }) };

test('empty PSI POST body → 400', async () => {
  const req = new NextRequest('http://localhost/api/satellite/trust/psi/sync', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '',
  });
  const res = await POST(req, params);
  assert.equal(res.status, 400);
  const json = await res.json();
  assert.equal(json.error, 'Invalid request body');
});

test('non-object PSI POST body → 400', async () => {
  const req = new NextRequest('http://localhost/api/satellite/trust/psi/sync', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '[]',
  });
  const res = await POST(req, params);
  assert.equal(res.status, 400);
  const json = await res.json();
  assert.equal(json.error, 'Invalid request body');
});
