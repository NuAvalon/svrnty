// src/lib/trust/block-latch.ts: Block and Remove set the beacon LATCH; a restore rebuilds it; a latch whose person is not in the suppression record is repaired.
// DARK: nothing outside tests imports this yet (the screens are wired in a later step of the same PR), and no function here touches the wire. Every port is injected, so this is
// unit-tested without IndexedDB and without the beacon client (type-only import below: nothing from the dark module is loaded).
//
// The orders. A step that fails leaves the EARLIER steps in place (a tightening is never rolled back) and writes none of the LATER ones:
//   Remove:  record the removal  ->  latch  ->  removeContact          (a Remove that leaves no durable id is the loss the removed list exists to stop, so the record is first and throws)
//   Block:   latch  ->  block flag  ->  AWAITED suppression write      (the latch is the write that stops deposits, so it goes first)
//   Unblock: flag  ->  suppression entry removed; the latch is NOT touched (a later Trust tap clears its own local latch).
import type { LatchPort } from '@/lib/crypto/beacon-client';
import type { BlockSuppressionOutcome, BlockSuppressionResult } from '@/lib/trust/block-suppression';
import { suppressPerson, type SuppressionRecord } from '@/lib/trust/suppression';
import type { Update } from '@/lib/trust/suppression-restore';

const DURABLE_ID = /^[0-9a-f]{64}$/; // a canonical fingerprint: 64 lowercase hex (suppression.ts)
const norm = (id: string | null | undefined): string => (id ?? '').trim().toLowerCase();

/** Thrown by a screen AFTER it has refreshed, when the Block's suppression write did not finish (the latch and the flag are in place). The screen's existing catch words it as a failed Block. */
export class BlockUnfinishedError extends Error {
  readonly code = 'block-unfinished' as const;
  constructor() { super('block unfinished: the suppression record write did not finish'); }
}

/** Thrown before a sealed export when a blocked contact could not be added to the suppression record: the export must REFUSE (no file), never ship a backup that silently lacks a block. */
export class BlocksIncompleteError extends Error {
  readonly code = 'blocks-incomplete' as const;
  constructor() { super('export refused: the suppression record could not be completed'); }
}

type PairIdFor = (durableId: string) => Promise<string>;
type LatchSetter = Pick<LatchPort, 'setLatched'>;
type LatchReader = Pick<LatchPort, 'kindOf'>;

export async function removeWithLatch(a: {
  durableId: string;
  pairIdFor: PairIdFor;
  latch: LatchSetter;
  /** THROWS when the removal cannot be recorded (an unreadable list, a full list, a malformed id): then nothing else is written. */
  recordRemoved: (durableId: string) => Promise<void>;
  removeContactRecord: () => Promise<void>;
}): Promise<void> {
  const id = norm(a.durableId);
  // A keyless or legacy contact (no canonical 64-hex fingerprint) has no beacon pair and no durable id to record: Remove must still delete it (refusing would leave a contact nobody can remove).
  if (!DURABLE_ID.test(id)) {
    await a.removeContactRecord();
    return;
  }
  await a.recordRemoved(id); // 1: the removed list (a restore rebuilds the latch from it; a removed contact leaves no row to rebuild from)
  await a.latch.setLatched(await a.pairIdFor(id), 'local'); // 2: stops every wire action for the pair
  await a.removeContactRecord(); // 3: only now is the contact deleted
}

export interface BlockLatchResult {
  /** False when a suppression write on a READABLE record failed ('skipped-error'; the latch and the flag are already in place): the person is told "the block didn't finish" and the repair completes it. */
  finished: boolean;
  suppression: BlockSuppressionOutcome;
}

export async function blockWithLatch(a: {
  peerDurableId: string | null | undefined;
  pairIdFor: PairIdFor;
  latch: LatchSetter;
  writeBlockFlag: () => Promise<void>;
  applySuppression: () => Promise<BlockSuppressionResult>;
}): Promise<BlockLatchResult> {
  const id = norm(a.peerDurableId);
  // A keyless contact has no canonical fingerprint, so there is no beacon pair to latch: the flag below is still written (same as applyBlockSuppression's 'no-durable-id').
  if (DURABLE_ID.test(id)) await a.latch.setLatched(await a.pairIdFor(id), 'local'); // 1
  await a.writeBlockFlag(); // 2
  const s = await a.applySuppression(); // 3: awaited (it was fire-and-forget); never throws, its outcome says whether it finished
  // Only a failed WRITE on a record that reads fine leaves the person out of it ('skipped-error'): that is "unfinished". 'skipped-fail-closed' (the record is absent or unreadable) is not: the emit
  // callsite reads a null record as suppress-EVERYONE, so the person is covered (over-dark) and a backup shows the left-out notice. On a tree where the genesis init is not wired every identity
  // has no record yet, and calling that "unfinished" would raise a false alarm on every Block (proved in a real browser: e2e/block-latch-idb.spec.ts).
  return { finished: s.outcome !== 'skipped-error', suppression: s.outcome };
}

export async function unblockKeepingLatch(a: {
  writeBlockFlag: () => Promise<void>;
  applySuppression: () => Promise<BlockSuppressionResult>;
}): Promise<{ suppression: BlockSuppressionOutcome }> {
  await a.writeBlockFlag();
  const s = await a.applySuppression();
  return { suppression: s.outcome }; // no latch port in this signature on purpose: Unblock cannot clear one
}

export type RepairOutcome =
  | 'nothing-to-repair'
  | 'repaired' // at least one blocked contact was added to the record
  | 'unreadable' // the record is unreadable OR absent: never written (absent reads as "suppress everyone", a person list from nothing would be LOOSER); the existing left-out notice covers it
  | 'error'; // the write failed: the export must REFUSE on this

/**
 * Repair, forward pass: a contact whose BLOCKED FLAG is set but who is not in the suppression record is ADDED to it, atomically (exactly state B3: the flag was written, the
 * record write did not finish). The predicate is the FLAG, never the latch: the latch is not evidence of intent (Unblock leaves it, a once-Removed contact who was re-added still has it), and
 * keying on it would silently re-write a block the person reversed. B2 (latch, no flag) gets no repair: the person was told "Block failed". It only ever adds (global, groups and
 * other persons are untouched). Runs on app start AND before every export.
 */
export async function repairBlockedButUnsuppressed(a: {
  contacts: () => Promise<Array<{ durableId: string; blocked: boolean }>>;
  updateSuppression: Update<SuppressionRecord>;
}): Promise<{ outcome: RepairOutcome; added: number }> {
  try {
    const blocked: string[] = [];
    for (const c of await a.contacts()) {
      const id = norm(c.durableId);
      if (c.blocked === true && DURABLE_ID.test(id)) blocked.push(id);
    }
    if (blocked.length === 0) return { outcome: 'nothing-to-repair', added: 0 };
    return await a.updateSuppression<{ outcome: RepairOutcome; added: number }>((held) => {
      if (held.state !== 'ok') return { result: { outcome: 'unreadable', added: 0 } };
      let next = held.value;
      let added = 0;
      for (const id of blocked) {
        const n = suppressPerson(next, id); // the SAME reference when the person is already there
        if (n !== next) { next = n; added += 1; }
      }
      return added === 0 ? { result: { outcome: 'nothing-to-repair', added: 0 } } : { write: next, result: { outcome: 'repaired', added } };
    });
  } catch {
    return { outcome: 'error', added: 0 };
  }
}

export type RelatchOutcome = 'nothing-to-do' | 'relatched' | 'partial' | 'unreadable';

/**
 * Repair, reverse pass, at app start / unlock: every id in the suppression record's persons and in the removed list that is NOT latched is latched (tighten
 * only, fail closed). This is what makes a crash between a restore's record write and its latch rebuild safe, and what latches the blocks made before this existed. Two rules:
 *  - an id that already has ANY latch (removed or frozen) is left alone;
 *  - a REMOVED id whose contact is IN THE BOOK is skipped: the removed list is append-only, so a contact who was Removed, re-added and then Trusted (a Trust tap clears its own latch) is still
 *    on the list, and latching them again at every start would silently undo the person's own Trust tap. The BOOK, not the list, governs a contact who is present. Record PERSONS keep
 *    relatching (a blocked person cannot be trust-tapped while blocked; Unblock removes the record entry first).
 * `null` from a reader = unreadable: that side is skipped and the outcome is 'partial'; both record and list unreadable = 'unreadable'. An unreadable BOOK counts as empty (the tighter side: the
 * removed ids are latched) and is counted. Counts only, never an id.
 */
export async function relatchFromRecord(a: {
  readPersons: () => Promise<string[] | null>;
  readRemoved: () => Promise<string[] | null>;
  /** The durable ids of the contacts in the book right now. */
  readBookIds: () => Promise<string[] | null>;
  pairIdFor: PairIdFor;
  latch: LatchReader & LatchSetter;
}): Promise<{ outcome: RelatchOutcome; latched: number; failed: number }> {
  const persons = await a.readPersons().catch(() => null);
  const removed = await a.readRemoved().catch(() => null);
  if (persons === null && removed === null) return { outcome: 'unreadable', latched: 0, failed: 0 };
  const book = await a.readBookIds().catch(() => null);
  let failed = (persons === null || removed === null ? 1 : 0) + (book === null ? 1 : 0); // an unreadable side or book: counted, the rest still runs
  const unlatchedOf = async (list: string[]): Promise<string[]> => {
    const out: string[] = [];
    for (const raw of list) {
      const id = norm(raw);
      if (!DURABLE_ID.test(id)) { failed += 1; continue; }
      try {
        if ((await a.latch.kindOf(await a.pairIdFor(id), 'local')) === null) out.push(id);
      } catch {
        failed += 1;
      }
    }
    return out;
  };
  const r = await rebuildLatchesFromCarry({
    persons: await unlatchedOf(persons ?? []),
    removed: await unlatchedOf(removed ?? []),
    bookIds: book ?? [],
    pairIdFor: a.pairIdFor,
    latch: a.latch,
  });
  failed += r.failed;
  if (failed > 0) return { outcome: 'partial', latched: r.latched, failed };
  return { outcome: r.latched > 0 ? 'relatched' : 'nothing-to-do', latched: r.latched, failed: 0 };
}

/**
 * Restore: latch every person in the (merged) suppression record AND every removed id, each once, EXCEPT a removed id whose contact is in the book (the book, not the
 * append-only list, governs a contact who is present; a person always latches). One failure never stops the others (as tight as possible), and the report is not ok when any failed;
 * it carries COUNTS only, never an id.
 */
export async function rebuildLatchesFromCarry(a: {
  persons: string[];
  removed: string[];
  /** The durable ids of the contacts in the book (after the restore has put them back). */
  bookIds: string[];
  pairIdFor: PairIdFor;
  latch: LatchSetter;
}): Promise<{ ok: boolean; latched: number; failed: number }> {
  const inBook = new Set(a.bookIds.map(norm));
  const ids = new Set<string>();
  let failed = 0;
  for (const raw of a.persons) {
    const id = norm(raw);
    if (DURABLE_ID.test(id)) ids.add(id);
    else failed += 1;
  }
  for (const raw of a.removed) {
    const id = norm(raw);
    if (!DURABLE_ID.test(id)) failed += 1;
    else if (!inBook.has(id)) ids.add(id); // a removed contact who is back in the book follows Block / Trust, not the list
  }
  let latched = 0;
  for (const id of ids) {
    try {
      await a.latch.setLatched(await a.pairIdFor(id), 'local');
      latched += 1;
    } catch {
      failed += 1;
    }
  }
  return { ok: failed === 0, latched, failed };
}
