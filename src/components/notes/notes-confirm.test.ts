// #616 e2e anchors — the delete/empty-bin confirm contract.
// The UI MUST: state local-only scope, never claim remote deletion,
// and gate destructive ops behind an explicit Cancel-default confirm.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { NOTES_COPY } from "./notes-copy";

const LOCAL_ONLY_MARKERS = /device only|on this device|local only|local-only/i;

describe("#616 e2e anchors — delete/empty-bin confirm contract", () => {
  it("delete copy states local-only scope", () => {
    for (const key of ["deleteLocalOnly", "deletePermLocalOnly", "emptyBinLocalOnly"]) {
      const copy = NOTES_COPY[key as keyof typeof NOTES_COPY] as string;
      assert.ok(LOCAL_ONLY_MARKERS.test(copy),
        `${key} must state local-only scope — got: ${copy}`);
      assert.ok(!/delete.{0,15}everywhere|universally|globally|forensically|unrecoverab/i.test(copy),
        `${key} must not over-claim remote or forensic deletion`);
    }
  });

  it("delete requires confirm, default cancel", () => {
    // The component wires Delete to arm a confirm bar (confirmAction),
    // NOT directly to the store op — a bare click can't delete.
    const src = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), "NotesInbox.tsx"),
      "utf8");
    assert.match(src, /onClick=\{\(\) => setConfirmAction\('delete'\)\}/,
      "Delete button must arm confirmAction, not call deleteNotesAtomic");
    assert.match(src, /data-testid="notes-confirm-cancel"/,
      "confirm bar must carry a Cancel button (default = cancel)");
    assert.match(src, /if \(act === 'delete'\) \{ await deleteNotesAtomic/,
      "deleteNotesAtomic must run only on explicit Confirm");
  });

  it("empty bin requires confirm, default cancel", () => {
    const src = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), "NotesInbox.tsx"),
      "utf8");
    assert.match(src, /setConfirmAction\('empty'\)/,
      "Empty bin must arm confirmAction");
    assert.match(src, /act === 'empty'\) \{ await emptyBin/,
      "emptyBin must run only on explicit Confirm");
  });
});
