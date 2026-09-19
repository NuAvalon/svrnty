import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  displayNameWithAlias,
  ownerLocalLeaksInText,
  patchOwnerLocal,
  readOwnerLocal,
  stripOwnerLocalAnnotations,
} from './owner-local-annotations';
import { contactRecordToEdge } from '@/lib/trust/contact-edge';
import { toVCard } from './vcard';
import { stripOwnerLocalForPublish } from '@/lib/trust/trust-recipe';

test('read/patch owner_local alias + notes', () => {
  const rec = { owner_local: { alias: 'Al', notes: 'met at dock' } };
  assert.deepEqual(readOwnerLocal(rec), { alias: 'Al', notes: 'met at dock' });
  const next = patchOwnerLocal(readOwnerLocal(rec), { alias: 'Ally' });
  assert.equal(next.alias, 'Ally');
  assert.equal(next.notes, 'met at dock');
});

test('displayNameWithAlias prefers the local alias', () => {
  assert.equal(displayNameWithAlias('Alice', { alias: 'Al' }), 'Al');
  assert.equal(displayNameWithAlias('Alice', {}), 'Alice');
});

test('receiver-local alias/notes/tags survive a simulated sender card-update', () => {
  // applyVerifiedContactUpdate is `{ ...current }` then allowlisted setters
  // (name/notes/…). owner_local is not allowlisted, so a shallow copy keeps it.
  const current = {
    id: 'c1',
    fingerprint: 'FP_ALICE',
    name: 'Alice',
    notes: 'old',
    owner_local: { alias: 'Dock-Al', notes: 'private-receiver-note-xyz' },
    metadata: { tags: ['family-cluster-label'], notes: 'old-meta' },
    version: 1,
  };
  const next = {
    ...current,
    name: 'Alice A.',
    notes: 'sender wrote this',
    version: 2,
  };
  assert.equal(next.name, 'Alice A.');
  assert.equal(next.notes, 'sender wrote this');
  assert.deepEqual(next.owner_local, current.owner_local);
  assert.deepEqual(next.metadata.tags, ['family-cluster-label']);
});

test('NEGATIVE: owner_local alias/notes/tags never appear on vCard export', () => {
  const rec = {
    id: 'c1',
    fingerprint: 'FP_ALICE',
    name: 'Alice',
    email: 'alice@old.example',
    public_key: 'PK_ALICE',
    owner_local: { alias: 'SecretAliasQZ7', notes: 'secret-receiver-note-qz7' },
    metadata: { tags: ['secret-group-label-qz7'] },
    notes: 'portable phone-book note',
  };
  const edge = contactRecordToEdge(rec);
  const vcf = toVCard(edge);
  assert.ok(vcf.includes('FN:Alice'));
  assert.ok(!vcf.includes('SecretAliasQZ7'));
  assert.ok(!vcf.includes('secret-receiver-note-qz7'));
  assert.ok(!vcf.includes('secret-group-label-qz7'));
  assert.ok(!vcf.includes('CATEGORIES'));
  assert.ok(!vcf.includes('owner_local'));
});

test('NEGATIVE: stripOwnerLocalAnnotations drops owner_local from a publish-shaped payload', () => {
  const payload = {
    fingerprint: 'FP',
    display_name: 'Alice',
    owner_local: { alias: 'SecretAliasQZ7', notes: 'secret-receiver-note-qz7' },
    alias: 'SecretAliasQZ7',
    metadata: {
      tags: ['secret-group-label-qz7'],
      blocked: true,
      owner_local: { alias: 'nested' },
    },
  };
  const stripped = stripOwnerLocalAnnotations(payload);
  assert.equal('owner_local' in stripped, false);
  assert.equal('alias' in stripped, false);
  const meta = stripped.metadata as Record<string, unknown>;
  assert.equal('tags' in meta, false);
  assert.equal('blocked' in meta, false);
  assert.equal('owner_local' in meta, false);
  const asText = JSON.stringify(stripped);
  assert.equal(ownerLocalLeaksInText(asText, payload.owner_local), false);
  assert.ok(!asText.includes('secret-group-label-qz7'));
});

test('NEGATIVE: fleet stripOwnerLocalForPublish + glass strip together', () => {
  const payload = {
    fingerprint: 'FP',
    owner_verify: { owner_verified_at: 'x', method: 'in_person' },
    owner_local: { alias: 'SecretAliasQZ7', notes: 'secret-receiver-note-qz7' },
    metadata: {
      owner_verify: { owner_verified_at: 'x', method: 'in_person' },
      notes: 'bro',
      tags: ['secret-group-label-qz7'],
      owner_local: { alias: 'nested' },
    },
  };
  const fleet = stripOwnerLocalForPublish(payload);
  const both = stripOwnerLocalAnnotations(fleet as Record<string, unknown>);
  assert.equal('owner_verify' in both, false);
  assert.equal('owner_local' in both, false);
  const meta = both.metadata as Record<string, unknown>;
  assert.equal('tags' in meta, false);
  assert.equal('owner_verify' in meta, false);
  assert.equal('owner_local' in meta, false);
});
