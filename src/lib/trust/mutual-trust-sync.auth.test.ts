// src/lib/trust/mutual-trust-sync.auth.test.ts
// Regression lock: PSI client auth signs the tag#3 DOMAIN-SEPARATED preimage the deployed satellite
// requires (svrnty-psi-auth:{fp}:{ts}) — NOT the bare {fp}:{ts} that 403'd on PSI (the live web-client bug).
// Run: npx tsx --test src/lib/trust/mutual-trust-sync.auth.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { buildAuthSignature } from './mutual-trust-sync.js';

const enc = (s: string) => new TextEncoder().encode(s);

test('buildAuthSignature signs svrnty-psi-auth:{fp}:{ts}, wire {ts}:{b64sig}', () => {
  const sk = ed25519.utils.randomSecretKey();
  const pk = ed25519.getPublicKey(sk);
  const fp = 'c9bc8bad984fc92140ff7616402874c9c3daf5234466946c28e144ca8b668ea7';

  const wire = buildAuthSignature(fp, (d) => ed25519.sign(d, sk));
  const idx = wire.indexOf(':');
  const ts = Number(wire.slice(0, idx));
  const sig = Buffer.from(wire.slice(idx + 1), 'base64');

  assert.ok(Number.isInteger(ts) && ts > 1_700_000_000, 'wire begins with unix seconds');
  // Verifies over the PREFIXED preimage the deployed satellite accepts (200)...
  assert.equal(ed25519.verify(sig, enc(`svrnty-psi-auth:${fp}:${ts}`), pk), true);
  // ...and must NOT verify over the bare preimage (the regression that 403'd on PSI).
  assert.equal(ed25519.verify(sig, enc(`${fp}:${ts}`), pk), false);
});
