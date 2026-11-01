// src/lib/headless/hop-trail.test.ts — layer 3 hop trail: the binding rules (Flint #189024 + C4, Hypatia 6139992d), each as a NEG.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DECRYPTED_HOP, HOP_TRAIL_FILE, HOP_TRAIL_MAX_BYTES, RECEIVER_HOPS, SENDER_HOPS, type Hop, isHop, ownAgentName, peerLabel, readHopTrail, recordHop, renderHop,
} from './hop-trail';
import { DEAD_LETTER_REASONS } from '@/lib/sync/dead-letter';

function dir() {
  return mkdtempSync(join(tmpdir(), 'hoptrail-'));
}
const at = (iso: string) => () => new Date(iso);
const lines = (d: string) => (existsSync(join(d, HOP_TRAIL_FILE)) ? readFileSync(join(d, HOP_TRAIL_FILE), 'utf8').split('\n').filter(Boolean) : []);

test('H1 a row has ONLY the known keys, ts is this host\'s UTC write time, and the file is born 0600', () => {
  const d = dir();
  try {
    assert.equal(recordHop(d, 'relay-accepted', { note_id: 'note_4c06ce75' }, 'archie', { now: at('2026-11-01T00:00:00.000Z'), agent: 'athena' }), true);
    const [l] = lines(d);
    assert.deepEqual(JSON.parse(l), { ts: '2026-11-01T00:00:00.000Z', hop: 'relay-accepted', note_id: 'note_4c06ce75', agent: 'athena', peer: 'archie' });
    assert.equal(statSync(join(d, HOP_TRAIL_FILE)).mode & 0o777, 0o600);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test('H2 the hop list is fixed: free text, "read"/"seen", an unknown reason, or a held: reason outside the #720 causes writes NOTHING', () => {
  const d = dir();
  try {
    for (const bad of ['read', 'seen', 'opened by archie', 'dropped:because the key was weird', 'dropped:', 'held:decrypt-failed', 'held:', 'DEPOSITED']) {
      assert.equal(isHop(bad), false, bad);
      assert.equal(recordHop(d, bad as Hop, { note_id: 'n1' }), false, bad);
    }
    for (const r of DEAD_LETTER_REASONS) assert.equal(isHop(`dropped:${r}`), true);
    assert.equal(isHop('held:missing-key') && isHop('held:ratchet-local'), true);
    for (const h of [...SENDER_HOPS, ...RECEIVER_HOPS]) assert.equal(isHop(h), true);
    assert.equal(DECRYPTED_HOP, 'opened', 'the named hop is the receiver\'s decrypted-on-this-host hop (order-pinned)');
    assert.deepEqual(lines(d), []);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test('H3 ids are opaque ids only: a space, a slash, a newline, an over-long id or no id at all writes NOTHING', () => {
  const d = dir();
  try {
    for (const ids of [{ note_id: 'hello world' }, { note_id: 'a/b' }, { note_id: 'x\n{"hop":"opened"}' }, { note_id: 'x'.repeat(129) }, { envelope_id: '' }, {}]) {
      assert.equal(recordHop(d, 'polled', ids), false, JSON.stringify(ids).slice(0, 40));
    }
    assert.deepEqual(lines(d), []);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test('H4 NEVER a fingerprint: peerLabel refuses hex "names", a person is always "person", an unnamed agent is omitted; a bad peer writes nothing', () => {
  assert.equal(peerLabel('agent', 'Archie'), 'archie');
  assert.equal(peerLabel('agent', '962fb7b4'), undefined, 'an 8-hex display name (the seam\'s fp.slice(0,8) default) is never a name');
  assert.equal(peerLabel('agent', '962fb7b4acbe91782f00'), undefined);
  // fps that START WITH A LETTER pass the name pattern's first-char rule, so only the hex check stops them (M1 found this gap)
  assert.equal(peerLabel('agent', 'cbb1738a'), undefined);
  assert.equal(peerLabel('agent', 'deadbeef'), undefined);
  assert.equal(peerLabel('agent', 'AB12CD34EF'), undefined, 'case-folded first, then refused');
  assert.equal(peerLabel('agent', 'Peter Alberts'), undefined, 'not a valid agent name');
  assert.equal(peerLabel('agent', undefined), undefined);
  assert.equal(peerLabel('human', 'Peter'), 'person', 'the wire kind for a person is "human": ALWAYS labelled "person", never their name');
  assert.equal(peerLabel('person', 'Peter'), 'person');
  assert.equal(peerLabel(undefined, 'archie'), undefined);
  const d = dir();
  try {
    assert.equal(recordHop(d, 'opened', { note_id: 'n1' }, '962fb7b4'), false);
    assert.equal(recordHop(d, 'opened', { note_id: 'n1' }, 'Peter'), false);
    assert.equal(recordHop(d, 'opened', { note_id: 'n1' }, undefined, { agent: '77f68335' }), true, 'a hex agent name is dropped, the row still lands');
    assert.deepEqual(JSON.parse(lines(d)[0]).agent, undefined);
    assert.equal(ownAgentName({ SVRNTY_AGENT_NAME: 'Athena' }), 'athena');
    assert.equal(ownAgentName({ SVRNTY_AGENT_NAME: '77f68335' }), undefined);
    assert.equal(ownAgentName({ SVRNTY_AGENT_NAME: 'cbb1738a' }), undefined);
    assert.equal(recordHop(d, 'opened', { note_id: 'n2' }, 'deadbeef'), false, 'a letter-first fp as peer writes nothing');
    assert.equal(ownAgentName({}), undefined, 'never derived from a path');
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test('H5 a trail file someone widened (0644) or replaced with a symlink is NOT written to, and is never chmod-repaired', () => {
  const d = dir();
  try {
    writeFileSync(join(d, HOP_TRAIL_FILE), '');
    chmodSync(join(d, HOP_TRAIL_FILE), 0o644);
    assert.equal(recordHop(d, 'polled', { envelope_id: 'e1' }), false);
    assert.equal(statSync(join(d, HOP_TRAIL_FILE)).mode & 0o777, 0o644, 'left as found: we refuse, we do not repair');
    assert.deepEqual(lines(d), []);
    const d2 = dir();
    const target = join(d2, 'target.txt');
    writeFileSync(target, 'untouched\n', { mode: 0o600 });
    rmSync(join(d, HOP_TRAIL_FILE));
    symlinkSync(target, join(d, HOP_TRAIL_FILE));
    assert.equal(recordHop(d, 'polled', { envelope_id: 'e1' }), false);
    assert.equal(readFileSync(target, 'utf8'), 'untouched\n', 'O_NOFOLLOW: a planted symlink never steers the write');
    rmSync(d2, { recursive: true, force: true });
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test('H6 bounded: rows older than 14 days are pruned on write; a trail past 5 MB is cut back with the NEWEST rows kept, still 0600', () => {
  const d = dir();
  try {
    recordHop(d, 'sealed', { note_id: 'old1' }, undefined, { now: at('2026-10-01T00:00:00.000Z') });
    recordHop(d, 'sealed', { note_id: 'mid1' }, undefined, { now: at('2026-10-20T00:00:00.000Z') });
    recordHop(d, 'sealed', { note_id: 'new1' }, undefined, { now: at('2026-11-01T00:00:00.000Z') });
    assert.deepEqual(lines(d).map((l) => JSON.parse(l).note_id), ['mid1', 'new1'], 'the 31-day-old row is gone, the 12-day-old one stays');
    const row = (i: number) => JSON.stringify({ ts: '2026-10-31T23:00:00.000Z', hop: 'polled', envelope_id: `env-${String(i).padStart(7, '0')}` }) + '\n';
    let big = '';
    for (let i = 0; big.length <= HOP_TRAIL_MAX_BYTES; i++) big += row(i);
    writeFileSync(join(d, HOP_TRAIL_FILE), big, { mode: 0o600 });
    assert.equal(recordHop(d, 'polled', { envelope_id: 'env-last' }, undefined, { now: at('2026-11-01T00:00:00.000Z') }), true);
    const st = statSync(join(d, HOP_TRAIL_FILE));
    assert.ok(st.size < HOP_TRAIL_MAX_BYTES, `pruned below the cap (${st.size})`);
    assert.equal(st.mode & 0o777, 0o600);
    const all = lines(d);
    assert.equal(JSON.parse(all[all.length - 1]).envelope_id, 'env-last', 'the newest row survives');
    assert.notEqual(JSON.parse(all[0]).envelope_id, 'env-0000000', 'the oldest rows were the ones dropped');
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test('H7 fail-open: no dir, a missing dir, or an unwritable dir returns false and NEVER throws', () => {
  assert.equal(recordHop(undefined, 'sealed', { note_id: 'n1' }), false);
  assert.equal(recordHop(join(tmpdir(), 'hoptrail-does-not-exist-' + process.pid), 'sealed', { note_id: 'n1' }), false);
  const d = dir();
  try {
    chmodSync(d, 0o500);
    assert.doesNotThrow(() => recordHop(d, 'sealed', { note_id: 'n1' }));
  } finally {
    chmodSync(d, 0o700);
    rmSync(d, { recursive: true, force: true });
  }
});

test('H8 the reader keeps KNOWN keys only, skips junk lines, and drops a fingerprint-looking peer/agent even if a file holds one', () => {
  const d = dir();
  try {
    writeFileSync(join(d, HOP_TRAIL_FILE), [
      JSON.stringify({ ts: '2026-11-01T00:00:00.000Z', hop: 'opened', note_id: 'n1', body: 'SECRET BODY', peer_fp: '962fb7b4', peer: '962fb7b4' }),
      'not json',
      JSON.stringify({ ts: 'yesterday', hop: 'opened', note_id: 'n1' }),
      JSON.stringify({ ts: '2026-11-01T00:00:01.000Z', hop: 'read', note_id: 'n1' }),
      JSON.stringify({ ts: '2026-11-01T00:00:02.000Z', hop: 'persisted', note_id: 'n1', peer: 'person', agent: 'athena' }),
    ].join('\n') + '\n', { mode: 0o600 });
    assert.deepEqual(readHopTrail(d, 'n1'), [
      { ts: '2026-11-01T00:00:00.000Z', hop: 'opened', note_id: 'n1' },
      { ts: '2026-11-01T00:00:02.000Z', hop: 'persisted', note_id: 'n1', peer: 'person', agent: 'athena' },
    ]);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test('H9 rendering (Hypatia): only receipt-verified says "delivered"; opened is "decrypted on this host"; nothing says read / seen / opened by', () => {
  const all: Hop[] = [...SENDER_HOPS, ...RECEIVER_HOPS, ...DEAD_LETTER_REASONS.map((r) => `dropped:${r}` as Hop), 'held:missing-key', 'held:ratchet-local'];
  for (const hop of all) {
    for (const peer of [undefined, 'archie', 'person']) {
      const s = renderHop({ ts: '2026-11-01T00:00:00.000Z', hop, note_id: 'n1', ...(peer ? { peer } : {}) });
      assert.doesNotMatch(s, /\bread\b|\bseen\b|opened by/i, `${hop}: ${s}`);
      if (hop !== 'receipt-verified') assert.doesNotMatch(s, /deliver(ed)?\b(?! receipt)/i, `${hop}: ${s}`);
    }
  }
  assert.equal(renderHop({ ts: 'x', hop: 'opened', note_id: 'n' }), 'decrypted on this host');
  assert.equal(renderHop({ ts: 'x', hop: 'relay-accepted', note_id: 'n' }), 'on the relay');
  assert.doesNotMatch(renderHop({ ts: 'x', hop: 'deposited', note_id: 'n' }), /\bsent\b|delivered/i);
  assert.equal(renderHop({ ts: 'x', hop: 'receipt-verified', note_id: 'n', peer: 'archie' }), "delivered to archie's app");
});
