// src/lib/sync/event-presence-freeze.test.ts: the one Freeze test that cannot be written yet.
//
// Freeze spec test 15: a frozen contact is ABSENT BOTH WAYS for event presence. Nothing is sealed to them (the emit side skips a frozen contact) and their own presence is
// dropped on arrival, before any screen (the receive side), so freezing someone does not tell them, or show you, whether the other is around.
//
// There is no event-presence code on dev: no emit seam and no receive path exist for this to attach to (the only "visibility" branch is the consent-tier one, a
// different feature). Presence v1 is a copy spec only (event_mode_presence_lines_v1, dd8769789f96). So this test is registered SKIPPED, with the reason below, and it
// lands WITH presence's own emit seam. Event presence cannot ship without it: it is on the launch gate list.
//
// Run: npx tsx --test src/lib/sync/event-presence-freeze.test.ts   (reports 1 skipped)
import { test } from 'node:test';

test(
  'FREEZE-15 a frozen contact is absent both ways for event presence: nothing is sealed to them, and their presence is dropped on arrival before any screen',
  { skip: 'pends with event presence v1 (dd8769789f96): there is no event-presence code on dev to attach this to. Event presence cannot ship without this test.' },
  () => {},
);
