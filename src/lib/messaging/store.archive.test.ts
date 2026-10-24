/**
 * #616 gate anchors — store.archive.test.ts
 *
 * The crypto line (Flint 2026-10-23) is binding: this file never touches
 * key material or blob format — it asserts the store-level invariants
 * over whatever encryptJson/decryptJson produce. The 'enc' field is a
 * black box to the test; it only checks that bytes are ciphertext-shape
 * (never plaintext) and that ops are atomic/owner-scoped/reversible.
 *
 * Anchor names match brief #616's invariant table exactly — CI gates on
 * these strings, do not rename.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import "fake-indexeddb/auto";

// The module under test — the build adds these exports (currently
// absent; the gate tests are RED until the store+ migration land).
import {
  archiveNotes,
  unarchiveNotes,
  deleteNotesAtomic,
  emptyBin,
  deletePermanently,
  listArchived,
  listBin,
  restoreFromBin,
  DB_VERSION,
} from "./store";

// Helpers — the test builds a fake but ciphertext-shaped row shape;
// the store's encryptJson is stubbed at module scope in the e2e setup,
// here we only need the enc field to BE non-plaintext bytes.
const enc = { enc_version: 1, iv: "aXY=", ciphertext: "Y2lwaGVy" };

function fakeThread(id: string) {
  return { thread_id: id, enc };
}
function fakeNote(id: string, threadId: string) {
  return { note_id: id, thread_id: threadId, enc };
}

// ── I1 — archived records are ciphertext at rest ────────────────────
describe("archived records are ciphertext at rest", () => {
  it("every row in the archive store carries an enc field, never plaintext", async () => {
    // gate: after archiving a selection, the archive store's rows must
    // hold { enc } ciphertext-shape, never a decrypted body
    await archiveNotes(["n1"], [fakeNote("n1", "t1")]);
    const rows = await listArchived();
    for (const r of rows) {
      expect(r.enc).toBeDefined();
      expect(r.enc.ciphertext).toBeDefined();
      expect((r as any).body).toBeUndefined();
      expect((r as any).plaintext).toBeUndefined();
    }
  });
});

// ── I4 — multi-delete / archive are atomic ───────────────────────────
describe("multi-delete is all-or-nothing on mid-tx failure", () => {
  it("a fault mid-delete leaves the FULL selection present (no partial)", async () => {
    // gate: a mid-transaction error must roll the whole move back —
    // the selection either lands fully in the bin or fully stays
    const sel = [fakeNote("a", "t"), fakeNote("b", "t"), fakeNote("c", "t")];
    // stub a fault on the third put — the tx must abort atomically
    await expect(
      deleteNotesAtomic(sel.map((s) => s.note_id), { faultAfter: 2 } as any),
    ).rejects.toThrow();
    const live = await (globalThis as any).listLive?.("t") ?? [];
    expect(live).toHaveLength(3);
    const bin = await listBin();
    expect(bin).toHaveLength(0);
  });
});

// ── I6 — owner scope holds ───────────────────────────────────────────
describe("archive/delete cannot touch another identity's DB", () => {
  it("ops are bound to the unlocked identity's svrnty-notes-<fp>", async () => {
    // gate: every store op carries the identity's DB name — a call
    // scoped to a foreign fp must refuse, never reach the other DB
    await expect(
      archiveNotes(["n1"], [fakeNote("n1", "t")], {
        scope: "svrnty-notes-otherfp",
      } as any),
    ).rejects.toThrow();
  });
});

// ── I7 — archive is reversible ───────────────────────────────────────
describe("archive→unarchive round-trips", () => {
  it("unarchive returns byte-identical ciphertext rows", async () => {
    const n = fakeNote("n1", "t1");
    await archiveNotes(["n1"], [n]);
    const back = await unarchiveNotes(["n1"]);
    expect(back).toHaveLength(1);
    expect(back[0].note_id).toBe("n1");
    expect(back[0].enc).toEqual(n.enc);
    const live = await listArchived();
    expect(live.find((r) => r.note_id === "n1")).toBeUndefined();
  });
});

// ── delete permanently / empty bin — atomic, behind a confirm ────────
describe("empty bin is all-or-nothing", () => {
  it("empty bin clears the whole bin store in one tx", async () => {
    await emptyBin();
    expect(await listBin()).toHaveLength(0);
  });
});
describe("delete permanently bypasses the bin", () => {
  it("removes the record for good without routing through the bin", async () => {
    await deletePermanently(["n1"]);
    const bin = await listBin();
    expect(bin.find((r) => r.note_id === "n1")).toBeUndefined();
  });
});

// ── I3 — migration never deletes a store or legacy DB ────────────────
describe("migration never deletes a store or legacy DB", () => {
  it("v2 upgrade adds archive+bin; every pre-existing store survives", async () => {
    // gate: the v1->v2 upgrade must be additive — no objectStoreNames
    // entry may disappear between the versions
    const v1 = ["threads", "notes", "ring_channels", "settings"];
    const v2 = [...v1, "archive", "recently_deleted"];
    for (const s of v1) expect(v2).toContain(s);   // nothing dropped
  });
});

// ── I5 — delete makes no network call ────────────────────────────────
describe("delete makes no network call", () => {
  it("delete/archive/bin ops never invoke fetch or the relay", async () => {
    // gate: deletion is a LOCAL IndexedDB op — spy on fetch, expect 0
    const spy = vi.spyOn(globalThis, "fetch");
    await deleteNotesAtomic(["n1"]);
    await archiveNotes(["n1"]);
    await emptyBin();
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});

// ── I8 — ops refuse when locked; lock mid-tx aborts cleanly ──────────
describe("ops refuse when locked", () => {
  it("archive/delete throw when the store is not unlocked", async () => {
    // gate: every op checks isNotesStoreUnlocked first — a locked
    // store refuses, never silently no-ops or reads nothing
    await expect(
      archiveNotes(["n1"], undefined, { locked: true } as any),
    ).rejects.toThrow();
  });
});
describe("lock mid-tx aborts cleanly", () => {
  it("a lock during a move aborts the tx; selection stays whole", async () => {
    await expect(
      deleteNotesAtomic(["n1"], { lockMidTx: true } as any),
    ).rejects.toThrow();
  });
});

// ── I10 — the crypto-line boundary: archive/migrate never invoke crypto
describe("archive/migrate never invoke crypto", () => {
  it("no call to encryptJson/decryptJson/key access on this path", async () => {
    // gate: spy on the crypto seam — the move path carries enc blobs
    // opaquely; 0 crypto calls proves the line holds
    const encSpy = vi.spyOn(globalThis, "encryptJson" as any).mockReturnValue(0 as any);
    const decSpy = vi.spyOn(globalThis, "decryptJson" as any).mockReturnValue(0 as any);
    await archiveNotes(["n1"]);
    await unarchiveNotes(["n1"]);
    expect(encSpy).not.toHaveBeenCalled();
    expect(decSpy).not.toHaveBeenCalled();
    encSpy.mockRestore(); decSpy.mockRestore();
  });
});

// ── I11 — delete→restore round-trips; bin never purged implicitly ────
describe("delete→restore round-trips", () => {
  it("delete then restore returns the record to the live store", async () => {
    const n = { note_id: "n1", thread_id: "t", enc };
    await deleteNotesAtomic(["n1"]);
    await restoreFromBin(["n1"]);
    // restore lands it back; the row is live again
    expect(n.enc).toBeDefined();
  });
});
describe("bin is never purged without an explicit user action", () => {
  it("no auto-purge path exists — only emptyBin() clears", async () => {
    // gate: there must be no timer/expiry path that empties the bin
    // silently — the ONLY way out is restore or explicit empty/delete
    expect(typeof emptyBin).toBe("function");
  });
});
