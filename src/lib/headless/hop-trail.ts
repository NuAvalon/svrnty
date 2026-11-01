// src/lib/headless/hop-trail.ts
//
// Layer 3: the HOP TRAIL (spec 65bac8aa §Layer 3; Flint #189024 + C4 boundaries; Hypatia claims review 6139992d).
// A LOCAL record of how far each agent send or poll got, so a stalled note takes minutes to place, not hours.
// Row format = the Weft's ({ts, hop, note_id} JSONL), so a human can read two fleets' LOCAL files side by side.
// We adopt the FORMAT only, never their module: its free caller fields (their dh-intake logs peer=fp) break the rules below.
//
// Binding rules, each enforced here (not by callers):
//  1. LOCAL ONLY: one file in the agent's own dir. No API, no sync, no telemetry; never shipped. Backup exclusion is ops (spec C4).
//  2. ids + timestamps + hop names only: ts (THIS host's write time, UTC), hop (fixed list), note_id / envelope_id (opaque ids),
//     agent (our own name), peer (an agent NAME or the literal 'person'). NO other fields, ever. Never content, keys, tags, or any
//     fingerprint or fingerprint prefix: a hex-looking "name" is refused, a peer we cannot name is OMITTED, never guessed.
//  3. BOUNDED: 14 days, 5 MB; pruned on write. 0600 at birth (umask 077 for the create + fstat check in the same step).
//  4. FAIL-OPEN: a trail fault never wedges a send or a poll. recordHop() never throws; it returns false instead.
//  Per-side truth (Hypatia): sender hops = sealed, deposited, relay-accepted, receipt-verified; receiver hops = polled, opened,
//  persisted, receipt-sent, dropped:<reason>, held:<reason>. `opened` is "decrypted on this host", never "read"/"seen".

import { closeSync, constants, fstatSync, openSync, readFileSync, readSync, renameSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { DEAD_LETTER_REASONS, type DeadLetterReason } from '@/lib/sync/dead-letter';

export const HOP_TRAIL_FILE = 'hop-trail.jsonl';
export const HOP_TRAIL_MAX_AGE_MS = 14 * 24 * 3600 * 1000;
export const HOP_TRAIL_MAX_BYTES = 5 * 1024 * 1024;
const PRUNE_TARGET_BYTES = Math.floor(HOP_TRAIL_MAX_BYTES * 0.8);
const MAX_LINE_BYTES = 512;

export const SENDER_HOPS = ['sealed', 'deposited', 'relay-accepted', 'receipt-verified'] as const;
export const RECEIVER_HOPS = ['polled', 'opened', 'persisted', 'receipt-sent'] as const;
/** held:<reason> = the #720 hold causes (a subset of the dead-letter reasons); dropped:<reason> = DEAD_LETTER_REASONS. Never free text. */
// = HOLDABLE_REASONS (dead-letter.ts): #318 added 'ratchet-desync'. hop-trail.test.ts H10 pins the two lists equal, so a new hold cause can't vanish from the trail.
export const HELD_REASONS = ['missing-key', 'ratchet-local', 'ratchet-desync'] as const;
type HeldReason = (typeof HELD_REASONS)[number];
export type Hop = (typeof SENDER_HOPS)[number] | (typeof RECEIVER_HOPS)[number] | `dropped:${DeadLetterReason}` | `held:${HeldReason}`;
/** The receiver's "decrypted on this host" hop, named HERE so receipt code never spells it: layer 1's N2 pin keeps receipt paths free of
 *  any read/seen/opened literal (a hop is not a receipt code, and nothing renders it as read). */
export const DECRYPTED_HOP: Hop = RECEIVER_HOPS[1];

export interface HopRow {
  ts: string;
  hop: Hop;
  note_id?: string;
  envelope_id?: string;
  agent?: string;
  peer?: string;
}
const ROW_KEYS = ['ts', 'hop', 'note_id', 'envelope_id', 'agent', 'peer'] as const;

const NAME_RE = /^[a-z][a-z0-9_-]{0,31}$/;
const HEXISH_RE = /^[0-9a-f]{6,}$/; // an fp or fp prefix is never a name, whatever a contact record calls it
const ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/; // opaque ids only: no spaces, no slashes, nothing that can carry a sentence
const TS_RE = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/;

export function isHop(h: unknown): h is Hop {
  if (typeof h !== 'string') return false;
  if ((SENDER_HOPS as readonly string[]).includes(h) || (RECEIVER_HOPS as readonly string[]).includes(h)) return true;
  if (h.startsWith('dropped:')) return (DEAD_LETTER_REASONS as readonly string[]).includes(h.slice(8));
  if (h.startsWith('held:')) return (HELD_REASONS as readonly string[]).includes(h.slice(5));
  return false;
}

function validName(s: unknown): s is string {
  return typeof s === 'string' && NAME_RE.test(s) && !HEXISH_RE.test(s);
}

/** The ONLY way a peer label is made: a person (wire ParticipantKind 'human') is always 'person'; an agent is its lowercase name if
 *  that is a valid, non-hex name; otherwise undefined (the row omits peer). Never a fingerprint or prefix. */
export function peerLabel(kind: string | undefined, name: string | undefined): string | undefined {
  if (kind === 'human' || kind === 'person') return 'person';
  if (kind !== 'agent') return undefined;
  const n = typeof name === 'string' ? name.trim().toLowerCase() : undefined;
  return validName(n) ? n : undefined;
}

/** Our own agent name: explicit SVRNTY_AGENT_NAME (validated), never derived from a path. Absent/invalid → the row omits agent. */
export function ownAgentName(env: Record<string, string | undefined> = process.env): string | undefined {
  const n = env.SVRNTY_AGENT_NAME?.trim().toLowerCase();
  return validName(n) ? n : undefined;
}

function buildRow(hop: Hop, ids: { note_id?: string; envelope_id?: string }, peer: string | undefined, agent: string | undefined, now: Date): HopRow | null {
  if (!isHop(hop)) return null;
  const row: HopRow = { ts: now.toISOString(), hop };
  if (ids.note_id !== undefined) {
    if (!ID_RE.test(ids.note_id)) return null;
    row.note_id = ids.note_id;
  }
  if (ids.envelope_id !== undefined) {
    if (!ID_RE.test(ids.envelope_id)) return null;
    row.envelope_id = ids.envelope_id;
  }
  if (!row.note_id && !row.envelope_id) return null;
  if (agent !== undefined && validName(agent)) row.agent = agent;
  if (peer !== undefined) {
    if (peer !== 'person' && !validName(peer)) return null; // a bad peer is a caller bug: write nothing rather than leak it
    row.peer = peer;
  }
  return row;
}

/** Open (or create) the trail for append. Create = umask 077 + 0600 + O_NOFOLLOW; then fstat: a regular file, ours, one link, no
 *  group/other bits. Anything else → null (the write is skipped; we never chmod-repair a file someone else may have planted). */
function openTrail(path: string): number | null {
  const old = process.umask(0o077);
  let fd: number;
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW, 0o600);
  } finally {
    process.umask(old);
  }
  const st = fstatSync(fd);
  const uid = typeof process.getuid === 'function' ? process.getuid() : st.uid;
  if (!st.isFile() || st.uid !== uid || st.nlink !== 1 || (st.mode & 0o077) !== 0) {
    closeSync(fd);
    return null;
  }
  return fd;
}

function headRowTs(path: string): number | null {
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const buf = Buffer.alloc(MAX_LINE_BYTES);
    const n = readSync(fd, buf, 0, MAX_LINE_BYTES, 0);
    const first = buf.subarray(0, n).toString('utf8').split('\n')[0];
    const ts = Date.parse((JSON.parse(first) as { ts?: string }).ts ?? '');
    return Number.isFinite(ts) ? ts : null;
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/** Keep rows younger than 14 days, then the newest that fit in 80% of the size cap. Written to an O_EXCL 0600 temp, renamed over.
 *  A row appended by another process between the read and the rename can be lost: acceptable for a fail-open debugging aid. */
function prune(path: string, nowMs: number): void {
  const keep = readHopTrailRaw(path).filter((r) => nowMs - Date.parse(r.ts) <= HOP_TRAIL_MAX_AGE_MS);
  const lines: string[] = [];
  let bytes = 0;
  for (let i = keep.length - 1; i >= 0; i--) {
    const l = JSON.stringify(keep[i]) + '\n';
    if (bytes + l.length > PRUNE_TARGET_BYTES) break;
    lines.unshift(l);
    bytes += l.length;
  }
  const tmp = `${path}.prune-${process.pid}-${randomBytes(4).toString('hex')}`;
  const old = process.umask(0o077);
  let fd: number;
  try {
    fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  } finally {
    process.umask(old);
  }
  try {
    writeSync(fd, lines.join(''));
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}

/**
 * Append ONE hop row to <dir>/hop-trail.jsonl. dir undefined (FE, tests, a caller without an agent dir) → no trail, returns false.
 * Never throws; returns true only if the row was written.
 */
export function recordHop(
  dir: string | undefined,
  hop: Hop,
  ids: { note_id?: string; envelope_id?: string },
  peer?: string,
  opts: { now?: () => Date; agent?: string } = {},
): boolean {
  if (!dir) return false;
  try {
    const now = (opts.now ?? (() => new Date()))();
    const row = buildRow(hop, ids, peer, opts.agent ?? ownAgentName(), now);
    if (!row) return false;
    const line = JSON.stringify(row) + '\n';
    if (Buffer.byteLength(line) > MAX_LINE_BYTES) return false;
    const path = join(dir, HOP_TRAIL_FILE);
    const fd = openTrail(path);
    if (fd === null) return false;
    let size: number;
    try {
      writeSync(fd, line);
      size = fstatSync(fd).size;
    } finally {
      closeSync(fd);
    }
    const head = headRowTs(path);
    if (size > HOP_TRAIL_MAX_BYTES || (head !== null && now.getTime() - head > HOP_TRAIL_MAX_AGE_MS)) {
      try {
        prune(path, now.getTime());
      } catch {
        /* fail-open: an unpruned trail is bounded again on the next write */
      }
    }
    return true;
  } catch {
    return false;
  }
}

/** Parse the trail: KNOWN keys only (an unknown key is dropped, never displayed), rows with an invalid hop/ts skipped. */
function readHopTrailRaw(path: string): HopRow[] {
  let text: string;
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW); // never read through a planted symlink
    text = readFileSync(fd, 'utf8');
  } catch {
    return [];
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
  const out: HopRow[] = [];
  for (const line of text.split('\n')) {
    if (!line) continue;
    let o: Record<string, unknown>;
    try {
      o = JSON.parse(line) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (!isHop(o.hop) || typeof o.ts !== 'string' || !TS_RE.test(o.ts)) continue;
    const r: Record<string, unknown> = {};
    for (const k of ROW_KEYS) if (typeof o[k] === 'string') r[k] = o[k];
    if (r.peer !== undefined && r.peer !== 'person' && !validName(r.peer)) delete r.peer;
    if (r.agent !== undefined && !validName(r.agent)) delete r.agent;
    out.push(r as unknown as HopRow);
  }
  return out;
}

/** Rows for one note_id or envelope_id, oldest first. */
export function readHopTrail(dir: string, id: string): HopRow[] {
  return readHopTrailRaw(join(dir, HOP_TRAIL_FILE)).filter((r) => r.note_id === id || r.envelope_id === id);
}

/** Hypatia 6139992d wording. Only receipt-verified may say "delivered"; opened is never "read"/"seen"; deposited is never "sent". */
export function renderHop(r: HopRow): string {
  switch (r.hop) {
    case 'sealed':
      return 'sealed on this host';
    case 'deposited':
      return 'deposit requested (not yet confirmed by the relay)';
    case 'relay-accepted':
      return 'on the relay';
    case 'receipt-verified':
      return r.peer && r.peer !== 'person' ? `delivered to ${r.peer}'s app` : r.peer === 'person' ? "delivered to the person's app" : 'delivered (receipt verified)';
    case 'polled':
      return 'listed by the relay';
    case 'opened':
      return 'decrypted on this host';
    case 'persisted':
      return 'stored on this host';
    case 'receipt-sent':
      return 'delivery receipt sent';
    default:
      return r.hop.startsWith('dropped:') ? `dropped on this host (${r.hop.slice(8)})` : `held on this host (${r.hop.slice(5)})`;
  }
}
