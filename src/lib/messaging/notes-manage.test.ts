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
  const rest = src.slice(i + sig.length);
  const next = rest.search(/\n(export |async function |function )/);
  return src.slice(i, next === -1 ? i + 4000 : i + sig.length + next);
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
  ['purgeDeleted', 'recently_deleted', null],
] as const) {
  test(`${fn}: delegates to the single-tx mover ${srcStore}->${dstStore ?? 'purge'}`, () => {
    const body = fnBody(storeSrc(), `export function ${fn}(`);
    const call = dstStore
      ? new RegExp(`_moveNotes\\('${srcStore}',\\s*'${dstStore}'`)
      : new RegExp(`_moveNotes\\('${srcStore}',\\s*null`);
    assert.match(body, call,
      `${fn} must route through the shared atomic mover`);
  });
}

test('_moveNotes: ONE readwrite tx spanning source+dest, abort-safe', () => {
  const body = fnBody(storeSrc(), 'async function _moveNotes(');
  assert.match(body, /db\.transaction\(stores,\s*'readwrite'\)/,
    'the mover must open exactly one readwrite transaction');
  assert.match(body, /tx\.oncomplete/);
  assert.match(body, /tx\.onabort\s*=|tx\.onerror\s*=/,
    'abort/error must reject — a half-moved batch is a lie');
  // all-or-nothing semantics live in the single tx: read→put→delete per id
  assert.match(body, /src\.get\(id\)/);
  assert.match(body, /dst\.put\(/);
  assert.match(body, /src\.delete\(id\)/);
});

test('deleteNotes stamps deleted_at; archiveNotes stamps archived_at', () => {
  assert.match(fnBody(storeSrc(), 'export function deleteNotes('),
    /deleted_at/);
  assert.match(fnBody(storeSrc(), 'export function archiveNotes('),
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
  // and never invents a blob shape. The mover must write the row it read —
  // the only touched fields are the *_at stamp / strip keys.
  const body = fnBody(storeSrc(), 'async function _moveNotes(');
  assert.doesNotMatch(body, /encryptJson|decryptJson/,
    'moves carry the encrypted row verbatim — touching the blob is a crypto change');
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
