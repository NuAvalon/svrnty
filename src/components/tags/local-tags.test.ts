/**
 * CUR-8 — pure local-tag helpers.
 * Run: npx tsx --test src/components/tags/local-tags.test.ts
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  assignTag,
  collectTagCatalog,
  normalizeTagLabel,
  readContactTags,
  removeTag,
  renameTag,
  sanitizeTagText,
  tagPersistPatch,
  TAG_MAX_LEN,
} from './local-tags';

describe('normalizeTagLabel', () => {
  it('trims and collapses whitespace', () => {
    assert.equal(normalizeTagLabel('  core   builders  '), 'core builders');
  });

  it('rejects empty / oversized', () => {
    assert.equal(normalizeTagLabel('   '), null);
    assert.equal(normalizeTagLabel('x'.repeat(TAG_MAX_LEN + 1)), null);
  });

  it('strips control and bidi overrides', () => {
    assert.equal(sanitizeTagText('hi\u202Ethere'), 'hithere');
    assert.equal(normalizeTagLabel('ok\u0000tag'), 'oktag');
  });
});

describe('read / assign / remove / rename', () => {
  it('prefers top-level tags, falls back to metadata', () => {
    assert.deepEqual(readContactTags({ tags: ['A'], metadata: { tags: ['B'] } }), ['A']);
    assert.deepEqual(readContactTags({ metadata: { tags: ['B'] } }), ['B']);
  });

  it('assigns case-insensitively without dupes', () => {
    assert.deepEqual(assignTag(['Core'], 'core'), ['Core']);
    assert.deepEqual(assignTag(['Core'], 'builders'), ['Core', 'builders']);
  });

  it('removes and renames across casing', () => {
    assert.deepEqual(removeTag(['Core', 'radio'], 'CORE'), ['radio']);
    assert.deepEqual(renameTag(['Core', 'radio'], 'core', 'inner'), ['inner', 'radio']);
    // Rename onto an existing label: collapse + adopt the new casing from `to`
    assert.deepEqual(renameTag(['Core', 'inner'], 'core', 'INNER'), ['INNER']);
  });
});

describe('collectTagCatalog + persist patch', () => {
  it('unions members under one label', () => {
    const catalog = collectTagCatalog([
      { id: '1', tags: ['core'] },
      { id: '2', metadata: { tags: ['Core', 'radio'] } },
    ]);
    assert.equal(catalog.length, 2);
    const core = catalog.find((t) => t.label.toLowerCase() === 'core')!;
    assert.deepEqual(core.memberIds.sort(), ['1', '2']);
  });

  it('writes tags on both top-level and metadata (local-only shape)', () => {
    const patch = tagPersistPatch({ notes: 'x' }, ['builders']);
    assert.deepEqual(patch.tags, ['builders']);
    assert.deepEqual(patch.metadata, { notes: 'x', tags: ['builders'] });
  });
});
