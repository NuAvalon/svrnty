// src/lib/messaging/notes-manage.test.ts
// svrnty #616 gate tests — message management (multi-select delete/archive).
// Executable proofs that the store + UI contracts hold. Written FIRST (red in
// CI) per the brief: archive + recently_deleted object stores in the SAME
// per-identity `svrnty-notes-<fp>` DB, atomic multi-delete, additive-only
// schema migration, multi-select UI affordances.
//
// Convention (device-mailbox-lifecycle.test.ts): source-level assertions via
// readFileSync — the IDB layer is browser-only, and the gates that matter are
// structural (migration additive-only, single-tx atomicity, fail-closed).
// Run: npx tsx --test src/lib/messaging/notes-manage.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const storeSrc = () =>
  readFileSync(new URL('./store.ts', import.meta.url), 'utf8');
const inboxSrc = () =>
  readFileSync(
    new URL('../../components/notes/NotesInbox.tsx', import.meta.url),
    'utf8',
  );
const fnBody = (src: string, sig: string): string => {
  const i = src.indexOf(sig);
  assert.notStrictEqual(i, -1, `missing ${sig}`);
  return src.slice(i, i + 4000);
};

// ── migration: additive only, never deletes ──────────────────────────────

test('migration v->2 adds archive + recently_deleted stores, never drops', () => {
  const src = storeSrc();
  assert.match(src, /DB_VERSION\s*=\s*2\b/,
    'schema bump required — new stores need a version');
  const upgrade = fnBody(src, 'onupgradeneeded');
  assert.match(upgrade, /createObjectStore\('archive'/,
    "archive object store must be created in onupgradeneeded");
  assert.match(upgrade, /createObjectStore\('recently_deleted'/,
    "recently_deleted bin store must be created in onupgradeneeded");
  // additive-only: the whole file must never drop a store — legacy rows
  // (and the orphaned 'svrnty-notes' DB) are preserved by construction.
  assert.doesNotMatch(src, /deleteObjectStore/,
    'migration must be additive — never deleteObjectStore');
});

// ── atomic multi-move: ONE transaction spanning source+dest ──────────────

for (const [fn, srcStore, dstStore] of [
  ['archiveNotes', 'notes', 'archive'],
  ['deleteNotes', 'notes', 'recently_deleted'],
  ['restoreNotes', 'recently_deleted', 'notes'],
  ['restoreArchived', 'archive', 'notes'],
  ['purgeDeleted', 'recently_deleted', 'recently_deleted'],
] as const) {
  test(`${fn}: single readwrite tx over ${srcStore}->${dstStore}, all-or-nothing`, () => {
    const body = fnBody(storeSrc(), `export async function ${fn}(`);
    assert.match(
      body,
      new RegExp(`db\\.transaction\\(\\[['"]${srcStore}['"]`),
      `${fn} must open ONE transaction covering ${srcStore} (atomic batch)`);
    if (srcStore !== dstStore) {
      assert.match(
        body,
        new RegExp(`db\\.transaction\\(\\[[^\\]]*['"]${dstStore}['"]`),
        `${fn} tx must span ${dstStore} in the same transaction`);
    }
    assert.match(body, /tx\.onabort|tx\.onerror/,
      `${fn} must surface tx abort/error — a half-moved batch is a lie`);
  });
}

test('deleteNotes stamps deleted_at; archiveNotes stamps archived_at', () => {
  assert.match(fnBody(storeSrc(), 'export async function deleteNotes('),
    /deleted_at/);
  assert.match(fnBody(storeSrc(), 'export async function archiveNotes('),
    /archived_at/);
});

// ── bin retention: lazy purge on read (matches expires_at convention) ────

test('recently_deleted self-purges past retention on read', () => {
  const src = storeSrc();
  assert.match(src, /DELETED_RETENTION|BIN_RETENTION/,
    'a named retention constant bounds the bin (no forever-trash)');
  const body = fnBody(src, 'listDeletedNotes');
  assert.match(body, /purge|delete/,
    'listDeletedNotes must sweep rows past retention (hard delete)');
});

// ── encrypted-at-rest parity: moved rows keep the enc blob ───────────────

test('moved rows carry the same EncryptedBlob — no re-wrap, no new format', () => {
  // Flint line: management moves ROWS (key + enc blob), never re-encrypts
  // and never invents a blob shape. The move helpers must write the row
  // they read — the only added fields are the *_at stamps.
  const body = fnBody(storeSrc(), 'export async function deleteNotes(');
  assert.doesNotMatch(body, /encryptJson|decryptJson/,
    'delete moves the encrypted row verbatim — touching the blob is a crypto change');
});

// ── UI: multi-select affordances in NotesInbox ───────────────────────────

test('NotesInbox exposes multi-select + archive/bin actions', () => {
  const src = inboxSrc();
  assert.match(src, /selectionMode|selectMode|selectedIds/,
    'a selection state must drive multi-select');
  assert.match(src, /data-testid="[^"]*archive/,
    'archive action needs a testid hook');
  assert.match(src, /data-testid="[^"]*delete/,
    'delete action needs a testid hook');
  // management calls must go through the store API — never ad-hoc IDB.
  assert.match(src, /archiveNotes|deleteNotes/,
    'UI must call the store management API, not raw objectStore writes');
});

// ── privacy invariant: bin/archive never serialize onto wire payloads ────

test('no send/export path touches archive or recently_deleted', () => {
  // tags/bin/archive are device-local (AGENTS I-10 family + tag invariant):
  // nothing in these stores may serialize into a wire/export payload.
  const send = readFileSync(
    new URL('./transport.ts', import.meta.url), 'utf8');
  assert.doesNotMatch(send, /recently_deleted|archive/,
    'transport must never read management stores');
});
