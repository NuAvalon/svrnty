# PSI piece A (the HTTP client for /trust/beacon): contract v2 = v1 + instant removal
Apollo, 2026-11-09, clock ~13:00Z. Piece A is still UNBUILT. This says what it must do; it builds nothing.
Base: contract v1, sha256 prefix 0e80c83b794a562d (the text Mneme holds, in Athena's note). EVERYTHING in v1 sections 1-4 stands unless a row below says otherwise. Sources: Flint's instant-removal design (task:588 #6167, #6174), my break of it (#6170), the pre-filing read (#6179), and the merged server (beacon_centurion.py at #440 13caa0f2). Read, not run: nothing in this file was executed.

## 0. Edits to v1 (replace these, keep the rest)
- v1 s3 rule 4 ("re-deposit times come from scheduleRedeposit") now covers RENEWAL only. The FIRST deposit for a pair happens AT THE TAP (s1 below), not on a schedule.
- v1 s5 "Epoch length": Peter said weekly, biweekly or monthly, NOT daily; not yet picked. Do not touch EPOCH_SECONDS. Nothing here depends on the value.
- NEW FACT the client must assume: the server expires NOTHING. poll and withdraw look a row up by (H_e, N) with no open-epoch check, so a closed epoch's MATCH is still answered. "Old matches fade" is CLIENT policy: look only at the current epoch's slot (and an adjacent epoch inside the 600 s window).
- NEW FACT: a deposit can be made for cur+1 during the last 600 s of an epoch (open_epochs), so a match for e+1 can form before e+1 starts. NO pre-filing beyond that window is in this contract (rejected: matched future rows cannot be withdrawn, the open-epoch cap is shared across epochs).
- v1 s5 "E's gate ... block-after-trust stops deposits/polls/withdraw" is now made precise by s2 (the latch).

## 1. Deposit at the tap
Tapping Trust starts the deposit now (behind the one-proof-at-a-time mutex of v1 s3.1), not at a scheduled time. Matching forms in the transaction of the SECOND deposit, so the second person's tap is what makes it instant; the first person's next poll sees it.

## 2. The latch (removal at the tap, local, instant)
A latch is a local, durable "this pair is removed" record. Piece A does NOT own its storage (new-files-only fence): it is injected as a port, `LatchPort { isLatched(pairId): Promise<boolean> }`, and the removal action is `removeAtTap(pairId)`. `pairId` is the DURABLE id, never the current fingerprint (rotation changes the fingerprint).
L1. `removeAtTap` writes the latch FIRST and durably, THEN does anything on the network.
L2. The latch is read (a) immediately before the `fetch` of every deposit, AFTER proving finishes (a proof takes seconds; a tap during proving must end with nothing sent); (b) AFTER every poll/withdraw response arrives, before the answer is applied (a poll sent before the tap must not flip the pair back).
L3. A latched pair is skipped by every scheduled action: renewal deposit, poll, and any deposit in the cur+1 window.
L4. ONE function, `matchState(pairId)`, is the only way any consumer learns of a match, and it applies the latch (MATCH + latched = "none"). The raw poll answer never leaves piece A. A static test pins that no other export returns the raw answer. Consumers to cover: the UI label, the send gate, receipts, the re-deposit scheduler.
L5. Two latch SOURCES: local (my own Remove or Block) and remote (an un-trust note I received). A remote re-trust clears ONLY the remote latch. A local latch is cleared only by my own Trust tap.
L6. A removal that runs OFFLINE leaves the pair's standing unmatched rows live. `removeAtTap` also queues a durable pending-withdraw entry per standing row (current epoch, and the adjacent epoch if a deposit exists there), keeps that row's one-time seed until the withdraw is CONFIRMED (answers `withdrawn` or `match`) or the epoch has closed, and retries with backoff. A withdraw answered `match` is INERT (the row stays matched) and is NOT an error: it sets `observedMatch` (s3).
L7. After a seed-only restore there is no latch and the server may still answer MATCH. FAIL CLOSED: piece A makes no deposit and no poll for any pair until the owner confirms that pair (`PairConfirmedPort.isConfirmed(pairId)`). Visible cost; the line is Hypatia's (draft #6176).
L8. Remove-then-remake in the SAME epoch is impossible if the first row was withdrawn unmatched (`withdrawn` is spent for the epoch, v1 s2): the circuit gives one slot per pair per epoch and one nullifier per member per slot. A re-trust tap after an unmatched removal therefore waits for the next epoch; the UI must not promise otherwise. (If the first row was MATCHED, the row still stands and the re-trust is immediate.) A per-attempt salt would need a circuit change, a new R5 and a new pin: PETER'S decision, not in this contract.

## 3. The un-trust note (NOT piece A; its own piece, Flint reviews)
Piece A only RETURNS `observedMatch: boolean` from `removeAtTap`: true iff a poll ever answered `match` for the pair OR the withdraw answered `match` (Flint #6174 ruled the latter counts). Rules for the note layer, recorded here so the line is drawn once:
N1. Send a note only for Untrust, only when `observedMatch`. Never for Block. Never for a pair with no observed match.
N2. The note is signed and sealed over the existing mailbox. It carries the pair (durable ids), the signed epoch e, and a counter. Order is (epoch, counter) lexicographic. The receiver accepts only the current epoch or an epoch inside the 600 s window, and keeps a per-pair floor.
N3. A valid newer note sets (un-trust) or clears (re-trust) the REMOTE latch only (L5).
N4. Residuals to state: the relay can withhold the note (the other view stays stale until they next renew); delete-then-re-add of a contact inside one epoch loses the floor.

## 4. Tests piece A adds (red first), in addition to v1 s4
1. Tap Remove while a poll is in flight; the answer is MATCH; the state ends "removed" (L2b).
2. Tap Remove while the proof is running; NOTHING is sent (count of fetches = 0) (L2a).
3. A latched pair: no deposit, no poll in the current epoch, in the cur+1 window, or at renewal (L3).
4. `matchState` hides MATCH behind a latch; a static test that no other export returns the raw answer (L4).
5. A remote re-trust does not clear a local latch (L5).
6. Remove while offline: the withdraw is queued, retried, the seed is kept until confirmed, and dropped after confirmation or epoch close (L6). A withdraw answered `match` returns `observedMatch=true` and is not an error.
7. After restore with no confirmation: zero requests for every pair (L7).
8. `removeAtTap` before any observed match returns `observedMatch=false`.
9. Two taps (Trust, Remove) during one proof: the mutex serializes, the second proof is not `prove-failed`, and the final state is removed.

## 5. Open, not decided here
Epoch length (Peter). Worker policy at wiring (Flint, #447). Same-epoch remake (L8, Peter). Where the latch lives in the vault and the note transport (their own pieces; the line is drawn above: piece A takes ports and returns `observedMatch`). Hypatia's copy for L7 and for L8's "next epoch".

## 6. What I did NOT do
No code and no run. I did not read #792 again. I measured nothing on a phone. The ~7 s proof time is from v1 (Node), phones unmeasured.
