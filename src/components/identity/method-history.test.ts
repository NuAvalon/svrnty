// CUR-2 — method-history unit tests (no crypto).

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  appendMethodRevision,
  latestRevision,
  loadMethodHistory,
  requestRestorePrevious,
  revisionsForPeer,
  saveMethodHistory,
  summarizeRevision,
} from './method-history';

const OWNER = 'aa'.repeat(20);
const PEER = 'bb'.repeat(20);

function memStorage() {
  const map = new Map<string, string>();
  return {
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    setItem: (k: string, v: string) => {
      map.set(k, v);
    },
    removeItem: (k: string) => {
      map.delete(k);
    },
    clear: () => map.clear(),
  };
}

test('append + load method history', () => {
  (globalThis as any).localStorage = memStorage();
  saveMethodHistory(OWNER, []);
  const a = appendMethodRevision(OWNER, {
    kind: 'email',
    value: 'old@x.co',
    recipientFingerprints: [PEER],
  });
  const b = appendMethodRevision(OWNER, {
    kind: 'email',
    value: 'new@x.co',
    previousValue: 'old@x.co',
    recipientFingerprints: [PEER],
  });
  const list = loadMethodHistory(OWNER);
  assert.equal(list.length, 2);
  assert.equal(a.localVersion, 1);
  assert.equal(b.localVersion, 2);
  assert.equal(latestRevision(list)?.value, 'new@x.co');
  assert.match(summarizeRevision(b), /email/);
});

test('revisionsForPeer falls back to full log when none tagged', () => {
  (globalThis as any).localStorage = memStorage();
  appendMethodRevision(OWNER, { kind: 'site', value: 'https://a.example' });
  const all = loadMethodHistory(OWNER);
  assert.equal(revisionsForPeer(all, PEER).length, 1);
});

test('restore-previous appends draft and honestly reports signing-not-live', async () => {
  (globalThis as any).localStorage = memStorage();
  appendMethodRevision(OWNER, {
    kind: 'email',
    value: 'one@x.co',
    recipientFingerprints: [PEER],
  });
  const second = appendMethodRevision(OWNER, {
    kind: 'email',
    value: 'two@x.co',
    previousValue: 'one@x.co',
    recipientFingerprints: [PEER],
  });
  const result = await requestRestorePrevious({
    ownerFingerprint: OWNER,
    revisionId: second.id,
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'signing-not-live');
  const list = loadMethodHistory(OWNER);
  assert.equal(list.length, 3);
  assert.equal(list[2].value, 'one@x.co');
  assert.equal(list[2].status, 'local-only');
});

test('restore with no previous fails honestly', async () => {
  (globalThis as any).localStorage = memStorage();
  const only = appendMethodRevision(OWNER, { kind: 'phone', value: '+1' });
  const result = await requestRestorePrevious({
    ownerFingerprint: OWNER,
    revisionId: only.id,
  });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.reason, 'no-previous');
});
