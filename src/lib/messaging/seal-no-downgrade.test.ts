// src/lib/messaging/seal-no-downgrade.test.ts
//
// B group 2, commit 4d (Flint #439 / #454): a send never downgrades, and the notes store never goes backwards.
//   1. sealNoteTo REFUSES to seal without a recipient ML-KEM key (it used to fall back to classical OpenPGP). The send sites already skip
//      a recipient with no verified pq_kem, so this throw is the loud backstop for a caller bug.
//   2. The classical builder lives in seal-classical-fixture.ts, and NO app code imports it. The test runner does not set NODE_ENV, so
//      "outside tests" is enforced by import structure and pinned here by walking the tree.
//   3. The notes IndexedDB is at DB_VERSION >= 2 with the ratchet_sessions store (a lower version than a browser already holds is a
//      VersionError lockout: reproduced earlier). The deploy-side guard (guard7) checks the same number on a real build.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { mintHeadlessAgent } from '../identity/headless-mint';
import { sealNoteTo } from './seal';
import { sealNoteClassicalFixture } from './seal-classical-fixture';
import { NOTE_WIRE_TYPE } from './domains';
import type { NoteWireV0 } from './types';

const ROOT = join(__dirname, '..', '..', '..');

async function note(): Promise<{ wire: NoteWireV0; pub: string; kem: string }> {
  const peer = await mintHeadlessAgent({ throwaway: true });
  const id = peer.introduction.card.identity as unknown as { public_key: string; pq_kem_public_key: string };
  const wire = {
    type: NOTE_WIRE_TYPE, note_id: 'note_x', thread_id: 'thr_x', from_fingerprint: 'fp', body: 'hello', sent_at: new Date().toISOString(),
  } as unknown as NoteWireV0;
  return { wire, pub: id.public_key, kem: id.pq_kem_public_key };
}

test('sealNoteTo refuses to seal without a recipient ML-KEM key: no classical downgrade, loud not silent', async () => {
  const n = await note();
  await assert.rejects(() => sealNoteTo(n.wire, n.pub), /refusing to seal without a recipient ML-KEM key/);
  await assert.rejects(() => sealNoteTo(n.wire, n.pub, ''), /refusing to seal without a recipient ML-KEM key/);
});

test('control: with the recipient KEM key the same note seals (hybrid), and the fixture still builds the classical shape for tests', async () => {
  const n = await note();
  const hybrid = await sealNoteTo(n.wire, n.pub, n.kem);
  assert.ok(hybrid.length > 100);
  const classical = await sealNoteClassicalFixture(n.wire, n.pub);
  assert.match(classical, /BEGIN PGP MESSAGE/);
  assert.notEqual(hybrid, classical);
});

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.next' || name.startsWith('.')) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx)$/.test(name)) out.push(p);
  }
  return out;
}

test('no application code imports the classical fixture: only *.test.ts, e2e/ fixtures and the fixture itself may', () => {
  const offenders = [...walk(join(ROOT, 'src')), ...walk(join(ROOT, 'app'))]
    .filter((f) => !/\.test\.tsx?$/.test(f) && !f.endsWith('seal-classical-fixture.ts'))
    // an actual import (static or dynamic), not a mention in a comment
    .filter((f) => /(?:from\s+|import\s*\(\s*|require\s*\(\s*)['"][^'"]*seal-classical-fixture['"]/.test(readFileSync(f, 'utf8')))
    .map((f) => relative(ROOT, f));
  assert.deepEqual(offenders, [], 'app code must never be able to build a classical note');
});

test('the notes IndexedDB stays at DB_VERSION >= 2 and creates ratchet_sessions (a lower version locks out browsers already upgraded)', () => {
  const src = readFileSync(join(__dirname, 'store.ts'), 'utf8');
  const m = /const DB_VERSION = (\d+);/.exec(src);
  assert.ok(m, 'DB_VERSION constant found');
  assert.ok(Number(m![1]) >= 2, `DB_VERSION is ${m![1]}`);
  assert.match(src, /createObjectStore\('ratchet_sessions'/);
});
