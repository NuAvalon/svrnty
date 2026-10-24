// src/lib/headless/headless-store-atrest.test.ts
// At-rest encryption for the headless book (Part B durable store). Proves: an agent's notes/contacts are
// AES-256-GCM encrypted on disk when an atRestKey is supplied (closes the plaintext device-at-rest +
// cloud-backup-exfil gap, Flint #168811), round-trips, and NEVER silently clobbers the book on a wrong/
// missing key (do-no-harm: surface, never lose data). Plaintext parity when no key (dev/test).
//
// Run: npx tsx --test src/lib/headless/headless-store-atrest.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, rmSync, mkdtempSync } from 'node:fs';
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

// ── S14 on main's store-race fixes (Flint #179187, item 2): at-rest encryption layered on fail-closed read + writer lock ──
import { writeFileSync, readdirSync, mkdirSync } from 'node:fs';

test('at-rest + main: a TORN encrypted file THROWS on load — never an empty book, and the torn file is left untouched', () => {
  const path = tmpBook();
  const key = new Uint8Array(randomBytes(32));
  const a = new HeadlessStore({ path, atRestKey: key });
  a.upsertContact(contact('alice'));
  const good = readFileSync(path, 'utf8');
  const torn = good.slice(0, Math.floor(good.length / 2));
  writeFileSync(path, torn);
  assert.throws(() => new HeadlessStore({ path, atRestKey: key }), /./, 'a torn file must stop the command');
  assert.equal(readFileSync(path, 'utf8'), torn, 'the torn file was not overwritten by an empty book');
});

test('at-rest + main: an undecryptable file (wrong key) THROWS and is left byte-identical', () => {
  const path = tmpBook();
  const a = new HeadlessStore({ path, atRestKey: new Uint8Array(randomBytes(32)) });
  a.upsertContact(contact('alice'));
  const before = readFileSync(path, 'utf8');
  assert.throws(() => new HeadlessStore({ path, atRestKey: new Uint8Array(randomBytes(32)) }));
  assert.equal(readFileSync(path, 'utf8'), before);
});

test('at-rest + writer lock: under lockDir every mutation re-reads, applies, and flushes ENCRYPTED; two stores lose nothing', () => {
  const path = tmpBook();
  const lockDir = join(path, '..', 'locks');
  mkdirSync(lockDir, { recursive: true });
  const key = new Uint8Array(randomBytes(32));
  const a = new HeadlessStore({ path, lockDir, atRestKey: key });
  const b = new HeadlessStore({ path, lockDir, atRestKey: key });
  a.upsertContact(contact('from-a'));
  b.upsertContact(contact('from-b')); // b's snapshot predates a's write: the locked re-read must keep a's record
  a.upsertContact(contact('from-a-2'));
  const raw = readFileSync(path, 'utf8');
  assert.ok(!raw.includes('PUB-from-a') && !raw.includes('PUB-from-b'), 'no plaintext contact on disk');
  assert.equal(JSON.parse(raw).svrnty_at_rest, 1, 'the file is the encrypted envelope');
  const c = new HeadlessStore({ path, atRestKey: key });
  assert.deepEqual(c.listContacts().map((x) => x.fingerprint).sort(), ['from-a', 'from-a-2', 'from-b']);
  assert.ok(!readdirSync(join(path, '..')).some((f) => f.endsWith('.key')), 'the at-rest key is not written next to the file');
});

test('at-rest + main: a missing key on an encrypted file THROWS even under the lock path', () => {
  const path = tmpBook();
  const lockDir = join(path, '..', 'locks');
  mkdirSync(lockDir, { recursive: true });
  const a = new HeadlessStore({ path, lockDir, atRestKey: new Uint8Array(randomBytes(32)) });
  a.upsertContact(contact('alice'));
  assert.throws(() => new HeadlessStore({ path, lockDir }), /encrypted at rest/);
});

// ── Flint R3 on #275: migrating plaintext -> encrypted must not leave the plaintext book in <path>.bak ──
import { existsSync, copyFileSync } from 'node:fs';

const MARK = 'PLAINTEXT-MARKER-9f3a';
const noteWithMarker = { note_id: 'n-mark', thread_id: 't-mark', from_fingerprint: 'zed', body: MARK, direction: 'inbound', sent_at: '2026-01-01T00:00:00Z' } as never;

/** A legacy plaintext book flushed three times, so BOTH <path> and <path>.bak are plaintext and carry MARK. */
function legacyPlaintextBook(): string {
  const path = tmpBook();
  const legacy = new HeadlessStore({ path });
  legacy.upsertContact(contact('zed'));
  legacy.putNote(noteWithMarker);
  legacy.upsertContact(contact('wes')); // .bak is the PREVIOUS version: this third flush is what puts MARK into it
  assert.ok(readFileSync(path, 'utf8').includes(MARK), 'control: the legacy book is plaintext');
  assert.ok(existsSync(`${path}.bak`) && readFileSync(`${path}.bak`, 'utf8').includes(MARK), 'control: the legacy .bak is plaintext too');
  return path;
}

test('R3: after migrating to at-rest encryption NO plaintext remains on disk — neither the book nor its .bak', () => {
  const path = legacyPlaintextBook();
  const key = new Uint8Array(randomBytes(32));
  const m = new HeadlessStore({ path, atRestKey: key });
  m.upsertContact(contact('yan')); // first keyed flush = the migration

  assert.equal(JSON.parse(readFileSync(path, 'utf8')).svrnty_at_rest, 1);
  assert.ok(!readFileSync(path, 'utf8').includes(MARK), 'book is encrypted');
  const bak = readFileSync(`${path}.bak`, 'utf8');
  assert.ok(!bak.includes(MARK), 'the .bak holds NO plaintext marker (this was the leak)');
  assert.equal(JSON.parse(bak).svrnty_at_rest, 1, 'the .bak is a sealed at-rest envelope');
  rmSync(path, { force: true });
});

test('R3: the sealed .bak is still a usable rollback — same key opens it and the pre-migration book is intact', () => {
  const path = legacyPlaintextBook();
  const key = new Uint8Array(randomBytes(32));
  new HeadlessStore({ path, atRestKey: key }).upsertContact(contact('yan'));
  const restored = `${path}.restored`;
  copyFileSync(`${path}.bak`, restored);
  const r = new HeadlessStore({ path: restored, atRestKey: key });
  assert.equal(r.getContactByFingerprint('zed')?.id, 'id-zed', 'pre-migration contact restorable');
  assert.equal(r.listNotes()[0]?.body, MARK, 'pre-migration note restorable');
  assert.ok(r.getContactByFingerprint('yan') == null, 'and it really is the PREVIOUS version (yan was added by the migrating flush)');
  rmSync(path, { force: true });
});

test('R3: later flushes keep the .bak sealed (no regression on the second flush)', () => {
  const path = legacyPlaintextBook();
  const key = new Uint8Array(randomBytes(32));
  const m = new HeadlessStore({ path, atRestKey: key });
  m.upsertContact(contact('yan'));
  m.upsertContact(contact('xi'));
  const bak = readFileSync(`${path}.bak`, 'utf8');
  assert.ok(!bak.includes(MARK) && JSON.parse(bak).svrnty_at_rest === 1);
  rmSync(path, { force: true });
});

test('R3 control: with NO key (dev/test parity) the .bak stays a plain byte copy — behaviour unchanged', () => {
  const path = legacyPlaintextBook();
  new HeadlessStore({ path }).upsertContact(contact('yan'));
  assert.ok(readFileSync(`${path}.bak`, 'utf8').includes(MARK), 'plaintext mode keeps plaintext backups, as before');
  rmSync(path, { force: true });
});
