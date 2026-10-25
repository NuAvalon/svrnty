// #616 e2e anchors — the delete/empty-bin confirm contract.
// The UI MUST: state local-only scope, never claim remote deletion,
// and gate destructive ops behind an explicit Cancel-default confirm.
// The BEHAVIORAL half of this contract (arm → cancel → nothing deleted,
// confirm → op runs) is exercised by real Playwright in
// e2e/message-management.spec.ts — source-regex anchors live nowhere.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
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
});
