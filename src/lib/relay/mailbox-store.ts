// src/lib/relay/mailbox-store.ts
// Return-channel mailbox: a persistent, recipient-keyed DELTA on the single-use dead-drop relay.
// The relay gains a mailbox + poll + ack WITHOUT becoming smart about the social graph
// (joint design §1/§5). It stores ONLY opaque blobs + relay-assigned ids —
// NO sender field, no edge-list (custody I-1). Sender identity + sender_signature live INSIDE the
// E2E-encrypted blob and are verified by the RECIPIENT on consume, never by the relay (§4).
//
// DURABLE (OPT-2): backed by a local SQLite file (node:sqlite, built into Node 22 — zero new dep,
// no native build on the node:22-alpine image) so a process restart no longer drops pending mail.
// Single-node, synchronous API → the public functions keep their exact SYNC signatures and
// custody-I-1 / I-4 semantics; only the storage substrate changes (Redis = scale-later, not now).
// At-rest posture (Flint co-verify): sealed opaque blobs only (no keys), schema carries NO sender /
// no edge (mailbox_id → blobs), ack-delete + TTL keep it ephemeral, DB file is 0600 in a 0700 dir,
// WAL journaling with autocheckpoint. The DB path is a DIRECTORY-mounted persistent volume in prod
// (RELAY_DB_PATH) — a directory mount, never a single-file bind (WAL writes -wal/-shm sidecars).

import { DatabaseSync } from 'node:sqlite';
import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { mailboxConfig } from './mailbox-config';

export interface Envelope {
  /** Relay-assigned (or client-supplied, Apollo retry-dedup contract) unique id — the handle for
   *  ack-delete + client-side dedup. Unique within a mailbox. */
  envelope_id: string;
  /** Opaque payload (≤ maxPayloadBytes). The relay never reads or interprets this. */
  blob: string;
  deposited_at: number;
  expires_at: number;
}

/** Resolve the SQLite path. Prod: a DIRECTORY-mounted persistent volume (RELAY_DB_PATH). Tests:
 *  in-memory (fresh per process; reset between tests via resetMailboxStore). */
function dbPath(): string {
  const p = process.env.RELAY_DB_PATH;
  if (p && p.length > 0) return p;
  // Prod default: an ABSOLUTE path under the mounted persistent-volume directory (/data/relay).
  // Always a real file → no silent in-memory fallback if the env is unset (that would resurrect the
  // exact restart-drops-mail bug OPT-2 closes). Tests opt into ':memory:' via RELAY_DB_PATH
  // explicitly (the test runner does NOT set NODE_ENV).
  return '/data/relay/mailbox.sqlite';
}

let _db: DatabaseSync | undefined;

function db(): DatabaseSync {
  if (_db) return _db;
  const path = dbPath();
  if (path !== ':memory:') {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  }
  const d = new DatabaseSync(path);
  // Durability + concurrent-reader posture; autocheckpoint folds the WAL back periodically.
  d.exec('PRAGMA journal_mode = WAL;');
  d.exec('PRAGMA synchronous = NORMAL;');
  d.exec('PRAGMA wal_autocheckpoint = 1000;');
  // custody I-1 schema: mailbox_id → opaque blobs. NO sender column, NO edge. Composite PK
  // (mailbox_id, envelope_id) so the same client id in two mailboxes never collides, and
  // retry-dedup is scoped to the recipient's mailbox (Apollo's upsert-by-envelope_id contract).
  d.exec(`CREATE TABLE IF NOT EXISTS envelopes (
    mailbox_id   TEXT    NOT NULL,
    envelope_id  TEXT    NOT NULL,
    blob         TEXT    NOT NULL,
    deposited_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    PRIMARY KEY (mailbox_id, envelope_id)
  );`);
  d.exec('CREATE INDEX IF NOT EXISTS idx_mailbox_exp ON envelopes(mailbox_id, expires_at);');
  if (path !== ':memory:') {
    try { chmodSync(path, 0o600); } catch { /* best-effort; dir is 0700 */ }
  }
  _db = d;
  return d;
}

/** Backstop TTL GC (ack-delete is primary): drop expired envelopes. Swept lazily on every access. */
function sweepExpired(now: number): void {
  db().prepare('DELETE FROM envelopes WHERE expires_at <= ?').run(now);
}

/** Test-only reset (replaces the old getMailboxStore().clear()). Truncates all mailboxes. */
export function resetMailboxStore(): void {
  db().exec('DELETE FROM envelopes');
}

/** Test-only: close + drop the connection so the next access reopens from disk — lets a durability
 *  test prove mail survives a simulated process restart (file-backed path only). */
export function __closeDbForTests(): void {
  if (_db) {
    _db.close();
    _db = undefined;
  }
}

export type DepositResult = { ok: true } | { ok: false; status: 400 | 413 | 429 };

/**
 * Deposit one opaque envelope into a mailbox (lazy-create).
 *
 * The OUTCOME is uniform w.r.t. the recipient's mailbox state (I-4 deposit-side, §4): a depositor
 * cannot probe whether R's mailbox exists / is empty / has mail. The ONLY mailbox-state-dependent
 * signal is the at-cap 429 — a bounded I-4 residual: it leaks only the coarse "at-capacity" fact,
 * never who/read-state, and probing it requires filling a stranger's mailbox to cap (itself
 * rate-limited + costly).
 *
 * (400/413 are request-shape errors — about the deposit itself, NOT R's mailbox state.)
 *
 * `clientEnvelopeId` (optional, Apollo retry-dedup contract): when the client supplies a STABLE id,
 * a retry with the same (mailbox, id) is IDEMPOTENT — returns ok:true without a second row and
 * without re-counting against cap. Absent → the relay assigns a random id (legacy callers). The
 * idempotent-OK is uniform with a fresh OK (no read-state leak). [Flint: co-verify the dedup×cap×I-4
 * interaction — a dup-id re-deposit skips the cap check, a negligible UUID-collision residual.]
 */
export function depositEnvelope(
  mailboxId: string,
  blob: string,
  now: number,
  clientEnvelopeId?: string,
): DepositResult {
  const cfg = mailboxConfig();
  if (!mailboxId || typeof mailboxId !== 'string') return { ok: false, status: 400 };
  if (!blob || typeof blob !== 'string') return { ok: false, status: 400 };
  if (blob.length > cfg.maxPayloadBytes) return { ok: false, status: 413 };

  // §5.1 LAUNCH seam (config-driven, NOT built for 9/10): under the svrnty.is nursery profile
  // (cfg.inviteRequired), mailbox CREATION is gated behind an explicit owner-claim carrying an
  // invite_token+chain. A deposit to an as-yet-UNCLAIMED mailbox is still ACCEPTED UNIFORMLY —
  // buffered + TTL'd + unreadable until claimed — and is NEVER rejected: rejecting would reintroduce
  // exactly the occupancy-oracle / silent-drop that the uniform-ack design closes. The demo/family
  // profile (inviteRequired=false, default) lazy-creates on first deposit below. Referenced here so
  // the policy branch reads config, not a literal — the image never forks (Invariant 8).
  void cfg.inviteRequired;

  const d = db();
  sweepExpired(now); // lazy GC on write

  const envId =
    typeof clientEnvelopeId === 'string' && clientEnvelopeId.length > 0
      ? clientEnvelopeId
      : crypto.randomUUID();

  // Retry-dedup (Apollo): a re-deposit of the same (mailbox, envelope_id) is idempotent — already
  // stored + already counted, so return OK without a duplicate row (uniform with a fresh OK).
  const existing = d
    .prepare('SELECT 1 FROM envelopes WHERE mailbox_id = ? AND envelope_id = ?')
    .get(mailboxId, envId);
  if (existing) return { ok: true };

  // Per-mailbox cap → 429 at-cap (documented bounded I-4 residual). Count only the non-expired.
  const row = d
    .prepare('SELECT COUNT(*) AS c FROM envelopes WHERE mailbox_id = ? AND expires_at > ?')
    .get(mailboxId, now) as { c: number };
  if (row.c >= cfg.cap) return { ok: false, status: 429 };

  d.prepare(
    'INSERT INTO envelopes (mailbox_id, envelope_id, blob, deposited_at, expires_at) VALUES (?, ?, ?, ?, ?)',
  ).run(mailboxId, envId, blob, now, now + cfg.envelopeTtlMs);
  return { ok: true };
}

/**
 * Non-destructive poll (owner-only — the route enforces owner-auth BEFORE calling this).
 * Returns the pending envelopes as `{envelope_id, blob}` (oldest first). A never-used mailbox reads
 * as empty (`[]`), indistinguishable to the owner from a drained one — and never reachable by a
 * non-owner at all.
 */
export function pollMailbox(
  mailboxId: string,
  now: number,
): Array<{ envelope_id: string; blob: string }> {
  const d = db();
  sweepExpired(now);
  const rows = d
    .prepare(
      'SELECT envelope_id, blob FROM envelopes WHERE mailbox_id = ? AND expires_at > ? ORDER BY deposited_at ASC, rowid ASC',
    )
    .all(mailboxId, now) as Array<{ envelope_id: string; blob: string }>;
  return rows.map((r) => ({ envelope_id: r.envelope_id, blob: r.blob }));
}

/** Ack-delete (owner-only). Removes the listed ids from the mailbox. Returns the count removed. */
export function ackDelete(mailboxId: string, envelopeIds: string[], now: number): number {
  const d = db();
  sweepExpired(now);
  if (!Array.isArray(envelopeIds) || envelopeIds.length === 0) return 0;
  const placeholders = envelopeIds.map(() => '?').join(',');
  const res = d
    .prepare(
      `DELETE FROM envelopes WHERE mailbox_id = ? AND envelope_id IN (${placeholders})`,
    )
    .run(mailboxId, ...envelopeIds);
  return Number(res.changes);
}
