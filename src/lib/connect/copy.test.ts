import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CONNECT_COPY,
  boundConnectName,
  entityTypeLabel,
} from './copy';

const dir = dirname(fileURLToPath(import.meta.url));

describe('connect copy — claim-honesty', () => {
  it('entity type is attested, never verified, and does not guess human', () => {
    assert.equal(entityTypeLabel('agent'), 'attested: agent');
    assert.equal(entityTypeLabel('human'), 'attested: human');
    assert.equal(entityTypeLabel('org'), 'attested: organization');
    assert.equal(entityTypeLabel(undefined), 'not yet attested');
    assert.equal(entityTypeLabel('human').includes('verified'), false);
    assert.equal(entityTypeLabel(undefined).includes('human'), false);
  });

  it('bounds hostile names (I-10a)', () => {
    assert.equal(boundConnectName(''), '');
    assert.equal(boundConnectName('  Ada  '), 'Ada');
    const poisoned = `Ada\u0000${'x'.repeat(200)}\u202e`;
    const n = boundConnectName(poisoned);
    assert.equal(n.includes('\u0000'), false);
    assert.equal(n.includes('\u202e'), false);
    assert.ok(n.length <= 80);
  });

  it('does not claim persist, mutual trust, post-quantum, or verified entity', () => {
    const blob = JSON.stringify(CONNECT_COPY).toLowerCase();
    assert.equal(blob.includes('post-quantum'), false);
    assert.equal(blob.includes('end-to-end'), false);
    assert.equal(blob.includes('social recovery'), false);
    assert.equal(blob.includes('verified'), false);
    assert.match(CONNECT_COPY.notWired, /not live yet/);
    assert.match(CONNECT_COPY.addToKnownHint, /one-sided/);
    assert.match(CONNECT_COPY.addToKnownHint, /does not grant Trust/i);
    assert.match(CONNECT_COPY.localOnly, /not make you mutual/);
  });

  it('glass source never uses innerHTML and never mounts ceremony persist', () => {
    const ui = readFileSync(join(dir, '../../components/connect/ConnectOneStep.tsx'), 'utf8');
    const card = readFileSync(join(dir, '../../components/connect/ConnectArrivalCard.tsx'), 'utf8');
    const blob = `${ui}\n${card}`;
    assert.doesNotMatch(blob, /dangerouslySetInnerHTML/);
    assert.doesNotMatch(blob, /addContact/);
    assert.doesNotMatch(blob, /enqueueGateArrival/);
    assert.doesNotMatch(blob, /admitGateArrival/);
    assert.doesNotMatch(blob, /resolveRelay/);
    assert.doesNotMatch(blob, /import\s+.*JoinerCeremony/);
    assert.match(ui, /CONNECT_COPY\.addToKnown/);
    assert.match(card, /entityTypeLabel/);
    assert.match(card, /IdentitySeal/);
  });
});
