import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { PEER_MESH_ANTI_SURVEILLANCE } from './peer-mesh-copy';

const dir = dirname(fileURLToPath(import.meta.url));

test('peer-mesh legend keeps consent and the anti-surveillance clause', () => {
  assert.match(PEER_MESH_ANTI_SURVEILLANCE, /disclosures, not observations/i);
  assert.match(PEER_MESH_ANTI_SURVEILLANCE, /never infers who knows whom/i);

  const map = readFileSync(join(dir, 'TrustMap.tsx'), 'utf8');
  assert.match(map, /PEER_MESH_ANTI_SURVEILLANCE/);
  assert.match(map, /they both consented to show/);
  assert.doesNotMatch(map, /dangerouslySetInnerHTML/);

  const blob = PEER_MESH_ANTI_SURVEILLANCE.toLowerCase();
  assert.equal(blob.includes('post-quantum'), false);
  assert.equal(blob.includes('end-to-end'), false);
  assert.equal(blob.includes('social recovery'), false);
});
