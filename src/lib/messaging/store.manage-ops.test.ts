/**
 * #616 gate anchors — store.manage-ops.test.ts
 *
 * BEHAVIORAL anchors: every test calls the REAL store ops against a REAL
 * IndexedDB (fake-indexeddb) with a REAL derived key (initNotesStore →
 * PBKDF2 → AES-GCM). No source-text assertions — a green run means the
 * store actually did it.
 *
 * The crypto line (Flint 2026-10-23) is binding: tests never touch key
 * material or blob format. The 'enc' field is a black box — asserted
 * ciphertext-shaped, moved byte-identically, never re-wrapped (I10 spy).
 *
 * Run: npx tsx --test src/lib/messaging/store.manage-ops.test.ts
 */
import { describe, it, before, mock } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import "fake-indexeddb/auto";

// node18: globalThis.crypto only exists under --experimental-global-webcrypto;
// the shim keeps the file runnable under a plain `tsx --test`.
if (!globalThis.crypto) (globalThis as any).crypto = webcrypto;

import {
  initNotesStore,
  isNotesStoreUnlocked,
  lockNotesStore,
  putThread,
  putNote,
  listNotesForThread,
  archiveNotes,
  unarchiveNotes,
  deleteNotesAtomic,
  restoreFromBin,
  deletePermanently,
  emptyBin,
  listArchived,
  listBin,
  newNoteId,
} from "./store";

const FP_A = "a".repeat(64);
const FP_B = "b".repeat(64);
const PASS = "e2e-passphrase-1234";
const LOCK_ERR = "Notes store locked — call initNotesStore() first";
const DB_A = `svrnty-notes-${FP_A}`;

function note(id: string, threadId = "t1", body = "note body") {
  return {
    note_id: id,
    thread_id: threadId,
    direction: "inbound" as const,
    from_fingerprint: FP_B,
    to_fingerprints: [FP_A],
    sent_at: new Date().toISOString(),
    body,
    participant_kind: "human" as const,
    retention: { expires_at: null },
    wire_type: "svrnty-note-v0" as const,
  };
}
function thread(id: string) {
  return {
    thread_id: id,
    kind: "direct" as const,
    participants: [
      { fingerprint: FP_A, kind: "human" as const, display_name: "me" },
      { fingerprint: FP_B, kind: "human" as const, display_name: "peer" },
    ],
    created_at: new Date().toISOString(),
    last_activity_at: new Date().toISOString(),
    retention: { expires_at: null },
  };
}

/** Raw row read straight from IndexedDB — bypasses every store helper. */
async function rawRows(dbName: string, store: string): Promise<any[]> {
  const db = await new Promise<IDBDatabase>((res, rej) => {
    const r = indexedDB.open(dbName);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
    r.onupgradeneeded = () => r.result.close(); // never upgrade on read
  });
  const rows = await new Promise<any[]>((res, rej) => {
    const req = db.transaction(store, "readonly").objectStore(store).getAll();
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
  db.close();
  return rows;
}

// Each describe owns its thread/note ids — fake-indexeddb state persists
// for the file's lifetime, and init/lock mutate module-level state.

describe("I8 — ops refuse when locked (specific error, nothing moves)", () => {
  before(async () => {
    await initNotesStore(PASS, FP_A);
    await putThread(thread("t-lock"));
    await putNote(note("n-lock", "t-lock"));
  });

  it("every move/delete/list op throws the locked error", async () => {
    lockNotesStore();
    assert.equal(isNotesStoreUnlocked(), false);
    const ops: Array<() => Promise<unknown>> = [
      () => archiveNotes(["n-lock"]),
      () => unarchiveNotes(["n-lock"]),
      () => deleteNotesAtomic(["n-lock"]),
      () => restoreFromBin(["n-lock"]),
      () => deletePermanently(["n-lock"]),
      () => emptyBin(),
      () => listArchived(),
      () => listBin(),
    ];
    for (const op of ops) {
      await assert.rejects(op, (e: Error) => e.message === LOCK_ERR);
    }
    // nothing moved: the seeded row is still live in 'notes'
    const live = await rawRows(DB_A, "notes");
    assert.ok(live.some((r) => r.note_id === "n-lock"));
    assert.equal((await rawRows(DB_A, "archive")).length, 0);
    assert.equal((await rawRows(DB_A, "recently_deleted")).length, 0);
    await initNotesStore(PASS, FP_A); // restore for later describes
  });
});

describe("I1 — archived records are ciphertext at rest", () => {
  it("moved rows keep an enc blob, never plaintext fields", async () => {
    await putThread(thread("t-i1"));
    await putNote(note("n-i1", "t-i1", "plaintext-body-marker"));
    await archiveNotes(["n-i1"]);
    const arch = await rawRows(DB_A, "archive");
    const row = arch.find((r) => r.note_id === "n-i1");
    assert.ok(row?.enc?.iv, "row carries an enc.iv");
    assert.ok(row?.enc?.ciphertext, "row carries an enc.ciphertext");
    assert.equal(row.body, undefined);
    assert.equal(row.plaintext, undefined);
    // ciphertext, not the plaintext body
    assert.ok(!JSON.stringify(row).includes("plaintext-body-marker"));
  });
});

describe("I7 — archive→unarchive round-trips, blob verbatim", () => {
  it("moved rows carry the same EncryptedBlob — no re-wrap", async () => {
    await putThread(thread("t-i7"));
    await putNote(note("n-i7", "t-i7"));
    const before = (await rawRows(DB_A, "notes")).find(
      (r) => r.note_id === "n-i7");
    await archiveNotes(["n-i7"]);
    const mid = (await rawRows(DB_A, "archive")).find(
      (r) => r.note_id === "n-i7");
    await unarchiveNotes(["n-i7"]);
    const after = (await rawRows(DB_A, "notes")).find(
      (r) => r.note_id === "n-i7");
    // same ciphertext bytes at every hop — never re-encrypted
    assert.deepEqual(mid.enc, before.enc);
    assert.deepEqual(after.enc, before.enc);
    assert.equal(
      (await rawRows(DB_A, "archive")).some((r) => r.note_id === "n-i7"),
      false);
  });
});

describe("I4 — multi-move is atomic on mid-tx fault", () => {
  it("an injected put fault aborts the whole move (nothing migrates)", async () => {
    await putThread(thread("t-i4"));
    for (const id of ["a-i4", "b-i4", "c-i4"]) await putNote(note(id, "t-i4"));
    // real fault: the second dst.put throws inside its onsuccess handler
    let calls = 0;
    const orig = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function (v: any, k?: any) {
      calls += 1;
      if (calls === 2) throw new Error("injected mid-tx fault");
      return orig.call(this, v, k);
    };
    try {
      await assert.rejects(deleteNotesAtomic(["a-i4", "b-i4", "c-i4"]));
    } finally {
      IDBObjectStore.prototype.put = orig;
    }
    const live = await rawRows(DB_A, "notes");
    for (const id of ["a-i4", "b-i4", "c-i4"]) {
      assert.ok(live.some((r) => r.note_id === id), `${id} stayed live`);
    }
    assert.equal(
      (await rawRows(DB_A, "recently_deleted")).filter(
        (r) => r.note_id.endsWith("-i4")).length, 0);
  });
});

describe("I5 — move/delete is a local op (no network)", () => {
  it("ops never call fetch", async () => {
    const spy = mock.method(globalThis, "fetch", async () => {
      throw new Error("network is off-limits on this path");
    });
    await putThread(thread("t-i5"));
    await putNote(note("n-i5", "t-i5"));
    await archiveNotes(["n-i5"]);
    await unarchiveNotes(["n-i5"]);
    await deleteNotesAtomic(["n-i5"]);
    await restoreFromBin(["n-i5"]);
    assert.equal(spy.mock.callCount(), 0);
    spy.mock.restore();
  });
});

describe("I6 — ops are owner-scoped to the unlocked identity DB", () => {
  it("only the bound svrnty-notes-<fp> DB is ever opened", async () => {
    const opened: string[] = [];
    const orig = indexedDB.open.bind(indexedDB);
    (indexedDB as any).open = (name: string, v?: number) => {
      opened.push(name);
      return orig(name, v);
    };
    try {
      lockNotesStore(); // drop the cached handle so ops must re-open
      await initNotesStore(PASS, FP_A);
      await putNote(note("n-i6", "t-i5"));
      await archiveNotes(["n-i6"]);
      await deleteNotesAtomic(["n-i6"]);
    } finally {
      (indexedDB as any).open = orig;
    }
    assert.ok(opened.length > 0, "expected real indexedDB.open calls");
    for (const name of opened) assert.equal(name, DB_A);
  });
});

describe("I10 — moves never invoke crypto (opaque blob only)", () => {
  it("crypto.subtle gets 0 encrypt/decrypt/deriveKey calls on the move path", async () => {
    const enc = mock.method(crypto.subtle, "encrypt");
    const dec = mock.method(crypto.subtle, "decrypt");
    const der = mock.method(crypto.subtle, "deriveKey");
    const imp = mock.method(crypto.subtle, "importKey");
    await putThread(thread("t-i10"));
    await putNote(note("n-i10", "t-i10"));
    enc.mock.resetCalls(); dec.mock.resetCalls();
    der.mock.resetCalls(); imp.mock.resetCalls();
    await archiveNotes(["n-i10"]);
    await unarchiveNotes(["n-i10"]);
    await deleteNotesAtomic(["n-i10"]);
    await restoreFromBin(["n-i10"]);
    await deletePermanently(["n-i10"]);
    assert.equal(enc.mock.callCount(), 0);
    assert.equal(dec.mock.callCount(), 0);
    assert.equal(der.mock.callCount(), 0);
    assert.equal(imp.mock.callCount(), 0);
    for (const m of [enc, dec, der, imp]) m.mock.restore();
  });
});

describe("I11 — nothing leaves the bin except an explicit user op", () => {
  it("binned rows persist across reads; no timer/purge path", async () => {
    await putThread(thread("t-i11"));
    await putNote(note("n-i11", "t-i11"));
    await deleteNotesAtomic(["n-i11"]);
    // reads and unrelated ops must never drain the bin
    await listBin();
    await listArchived();
    await listNotesForThread("t-i11");
    await new Promise((r) => setTimeout(r, 50));
    const bin = await rawRows(DB_A, "recently_deleted");
    assert.ok(bin.some((r) => r.note_id === "n-i11"));
  });
  it("delete→restore round-trips back to live", async () => {
    await restoreFromBin(["n-i11"]);
    const live = await listNotesForThread("t-i11");
    assert.ok(live.some((n) => n.note_id === "n-i11"));
  });
});

describe("I2 — v1→v2 migration is additive and lossless", () => {
  it("a v1-seeded DB upgrades keeping every store + row", async () => {
    // build the v1 schema by hand (threads/notes/ring_channels/settings)
    const V1 = `svrnty-notes-${FP_B}`;
    const v1 = await new Promise<IDBDatabase>((res, rej) => {
      const r = indexedDB.open(V1, 1);
      r.onupgradeneeded = () => {
        const db = r.result;
        db.createObjectStore("threads", { keyPath: "thread_id" });
        const n = db.createObjectStore("notes", { keyPath: "note_id" });
        n.createIndex("thread_id", "thread_id");
        db.createObjectStore("ring_channels", { keyPath: "channel_id" });
        db.createObjectStore("settings", { keyPath: "key" });
      };
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
    await new Promise<void>((res, rej) => {
      const tx = v1.transaction("notes", "readwrite");
      tx.objectStore("notes").put({
        note_id: "legacy-n1", thread_id: "legacy-t", enc: { v: 1 },
      });
      tx.oncomplete = () => res();
      tx.onerror = () => rej(tx.error);
    });
    v1.close();

    await initNotesStore(PASS, FP_B); // opens at v2 → upgrade fires
    const db = await new Promise<IDBDatabase>((res, rej) => {
      const r = indexedDB.open(V1);
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
    for (const s of
      ["threads", "notes", "ring_channels", "settings",
       "archive", "recently_deleted"]) {
      assert.ok(db.objectStoreNames.contains(s), `${s} survived/added`);
    }
    const legacy = await new Promise<any>((res, rej) => {
      const q = db.transaction("notes", "readonly")
        .objectStore("notes").get("legacy-n1");
      q.onsuccess = () => res(q.result);
      q.onerror = () => rej(q.error);
    });
    assert.equal(legacy?.note_id, "legacy-n1");
    db.close();
    lockNotesStore();
  });
});
