// src/lib/headless/headless-store-atrest.test.ts
// At-rest encryption for the headless book (Part B durable store). Proves: an agent's notes/contacts are
// AES-256-GCM encrypted on disk when an atRestKey is supplied (closes the plaintext device-at-rest +
// cloud-backup-exfil gap, Flint #168811), round-trips, and NEVER silently clobbers the book on a wrong/
// missing key (do-no-harm: surface, never lose data). Plaintext parity when no key (dev/test).
//
// Run: npx tsx --test src/lib/headless/headless-store-atrest.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { HeadlessStore, type HeadlessContact } from './headless-store';

function tmpBook(): string {
  const dir = mkdtempSync(join(tmpdir(), 'hs-atrest-'));
  return join(dir, 'book.json');
}
const contact = (fp: string): HeadlessContact => ({
  id: `id-${fp}`, fingerprint: fp, public_key: `PUB-${fp}`,
});

test('at-rest: with a key the on-disk file is an AES-256-GCM envelope (NOT plaintext), and round-trips', () => {
  const path = tmpBook();
  const key = new Uint8Array(randomBytes(32));
  const a = new HeadlessStore({ path, atRestKey: key });
  a.upsertContact(contact('alice'));
  a.putNote({ note_id: 'n1', thread_id: 't1', from_fingerprint: 'alice', body: 'secret body', direction: 'inbound', sent_at: '2026-01-01T00:00:00Z' } as never);

  // On disk: an at-rest envelope, and the plaintext body must NOT appear anywhere in the file.
  const raw = readFileSync(path, 'utf8');
  const env = JSON.parse(raw);
  assert.equal(env.svrnty_at_rest, 1, 'file is an at-rest envelope, not plaintext JSON');
  assert.equal(env.alg, 'aes-256-gcm');
  assert.ok(!raw.includes('secret body'), 'plaintext body MUST NOT be present on disk');
  assert.ok(!raw.includes('PUB-alice'), 'plaintext contact key MUST NOT be present on disk');

  // Reload with the same key → data intact.
  const b = new HeadlessStore({ path, atRestKey: key });
  assert.equal(b.getContactByFingerprint('alice')?.public_key, 'PUB-alice');
  assert.equal(b.listNotes()[0]?.body, 'secret body');
  rmSync(path, { force: true });
});

test('at-rest: a WRONG key THROWS on load — never silently starts fresh (no data loss)', () => {
  const path = tmpBook();
  const a = new HeadlessStore({ path, atRestKey: new Uint8Array(randomBytes(32)) });
  a.upsertContact(contact('bob'));

  assert.throws(
    () => new HeadlessStore({ path, atRestKey: new Uint8Array(randomBytes(32)) }),
    'wrong key → GCM auth failure throws, does not clobber the encrypted book',
  );
  rmSync(path, { force: true });
});

test('at-rest: an encrypted file with NO key supplied THROWS (refuses to clobber)', () => {
  const path = tmpBook();
  const a = new HeadlessStore({ path, atRestKey: new Uint8Array(randomBytes(32)) });
  a.upsertContact(contact('carol'));

  assert.throws(
    () => new HeadlessStore({ path }),
    /encrypted at rest but no atRestKey/,
  );
  rmSync(path, { force: true });
});

test('at-rest: no key → plaintext JSON (dev/test parity, backward compatible)', () => {
  const path = tmpBook();
  const a = new HeadlessStore({ path });
  a.upsertContact(contact('dave'));
  const env = JSON.parse(readFileSync(path, 'utf8'));
  assert.equal(env.svrnty_at_rest, undefined, 'no key → plaintext HeadlessData, not an envelope');
  assert.ok(Array.isArray(env.contacts));
  const b = new HeadlessStore({ path });
  assert.equal(b.getContactByFingerprint('dave')?.id, 'id-dave');
  rmSync(path, { force: true });
});

test('at-rest: a 32-byte key is required (AES-256)', () => {
  assert.throws(() => new HeadlessStore({ atRestKey: new Uint8Array(16) }), /32 bytes/);
});

test('at-rest: plaintext file + key = migration — loads, then next flush re-writes encrypted', () => {
  const path = tmpBook();
  // Write a plaintext book (legacy).
  new HeadlessStore({ path }).upsertContact(contact('erin'));
  assert.equal(JSON.parse(readFileSync(path, 'utf8')).svrnty_at_rest, undefined);

  // Open with a key → reads the plaintext legacy book, and the write-on-mutate re-writes it encrypted.
  const key = new Uint8Array(randomBytes(32));
  const m = new HeadlessStore({ path, atRestKey: key });
  assert.equal(m.getContactByFingerprint('erin')?.id, 'id-erin', 'migrated the legacy plaintext book');
  m.upsertContact(contact('frank')); // triggers flush → now encrypted
  assert.equal(JSON.parse(readFileSync(path, 'utf8')).svrnty_at_rest, 1, 'migrated to encrypted at rest');

  const reopened = new HeadlessStore({ path, atRestKey: key });
  assert.equal(reopened.getContactByFingerprint('erin')?.id, 'id-erin');
  assert.equal(reopened.getContactByFingerprint('frank')?.id, 'id-frank');
  rmSync(path, { force: true });
});
