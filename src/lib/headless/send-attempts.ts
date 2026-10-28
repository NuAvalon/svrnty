// src/lib/headless/send-attempts.ts
// sealed-send-death-001 — the sender-side record the 01:26Z wound was missing.
//
// A sealed note can die BEFORE the relay ever sees it (send threw at seal /
// peer-kem / fetch, or the process was killed mid-flight): the outbound
// HeadlessStore row is only written AFTER the deposit attempt returns, so a
// pre-deposit death leaves NOTHING — no row, no mailbox record, no evidence
// the send was ever attempted. The receiver sees 0 pending and the sender's
// tools have nothing to forensicate on. That is wound-A: a silent death at
// the seam before the wire.
//
// This module is the send-side log: a JSONL of intent+outcome records next
// to the other agent state (send-attempts.jsonl). INTENT is appended BEFORE
// the seal/deposit attempt; OUTCOME after (or on throw). An intent with no
// outcome IS the corpse — the send died mid-flight and the record names
// what it was carrying (peer fp + mailbox_id + resendable body).
//
// Pure module: no crypto, no relay, no store knowledge. It never decides
// anything about a note — it records and pairs. The receiver-land leg
// (ack-vs-land cross-check) is sealed-death-acklie-001's scope; this file
// deliberately stops at what the SENDER can prove.

export interface SendAttempt {
  kind: 'intent' | 'outcome';
  note_id: string;              // sender-chosen; '' when unknowable (raw deposit of a caller blob)
  peer_fp: string;
  mailbox_id: string;           // '' for a local-route hop (no mailbox involved)
  ts: string;                   // ISO
  wire?: string;                // 'sealed' | 'sealed-tr' | 'deposit' | 'route'
  body?: string;                // intent only — resend material, same custody as the store's outbound copy
  stage?: string;               // outcome: SendStage | 'resolve' | 'ratchet' | 'seal' | 'deliver'
  deposited?: boolean;
  error?: string;
  route?: string;               // outcome: the router's chosen route (local / relay)
  reason?: string;
}

export type AttemptState = 'corpse' | 'not-sent' | 'sealed' | 'deposited';

export interface AuditRow {
  note_id: string;
  peer_fp: string;
  mailbox_id: string;
  state: AttemptState;
  wire?: string;
  first_ts?: string;
  last_ts?: string;
  error?: string;
  body?: string;                // carried from the intent for resend tooling
}

const FILE = 'send-attempts.jsonl';

export function attemptsPath(dir: string): string {
  return `${dir.replace(/\/+$/, '')}/${FILE}`;
}

/** Append one record. Tolerates a missing dir file (first send); throws on
 *  real I/O failure — the caller decides whether a logging failure may abort
 *  the send (callers wrap: a dead log never kills the send it describes). */
export function appendAttempt(appendLine: (line: string) => void, rec: SendAttempt): void {
  appendLine(JSON.stringify(rec));
}

/** Parse a JSONL body into records, skipping torn/foreign lines. */
export function parseAttempts(text: string): SendAttempt[] {
  const out: SendAttempt[] = [];
  for (const line of text.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    try {
      const o = JSON.parse(t);
      if (o && (o.kind === 'intent' || o.kind === 'outcome') && typeof o.peer_fp === 'string') {
        out.push(o as SendAttempt);
      }
    } catch { /* torn line — tolerate */ }
  }
  return out;
}

/** Pair intents with outcomes. Rules:
 *  - intent + outcome             → outcome decides: deposited | not-sent | sealed
 *  - intent, no outcome           → 'corpse': the send died between record and result
 *  - outcome with no intent       → still listed (deposit-of-caller-blob / route hop)
 *  - latest outcome wins on re-send of the same note_id
 */
export function auditAttempts(records: SendAttempt[]): AuditRow[] {
  const byId = new Map<string, { intent?: SendAttempt; outcomes: SendAttempt[] }>();
  const unpaired: SendAttempt[] = [];
  for (const r of records) {
    if (r.kind === 'intent') {
      const e = byId.get(r.note_id) ?? { outcomes: [] };
      e.intent = r;
      byId.set(r.note_id, e);
    } else {
      if (r.note_id) {
        const e = byId.get(r.note_id) ?? { outcomes: [] };
        e.outcomes.push(r);
        byId.set(r.note_id, e);
      } else {
        unpaired.push(r);
      }
    }
  }
  const rows: AuditRow[] = [];
  for (const [note_id, e] of byId) {
    const last = e.outcomes[e.outcomes.length - 1];
    const i = e.intent;
    let state: AttemptState;
    if (!last) {
      state = 'corpse';
    } else if (last.deposited === true) {
      state = 'deposited';
    } else if (last.stage === 'seal' && last.deposited !== false) {
      state = 'sealed';
    } else {
      state = 'not-sent';
    }
    rows.push({
      note_id,
      peer_fp: (last ?? i)?.peer_fp ?? '',
      mailbox_id: (last?.mailbox_id || i?.mailbox_id) ?? '',
      state,
      wire: last?.wire ?? i?.wire,
      first_ts: i?.ts ?? last?.ts,
      last_ts: last?.ts ?? i?.ts,
      error: last?.error ?? last?.reason,
      body: i?.body,
    });
  }
  for (const o of unpaired) {
    rows.push({
      note_id: '',
      peer_fp: o.peer_fp,
      mailbox_id: o.mailbox_id,
      state: o.deposited === true ? 'deposited' : 'not-sent',
      wire: o.wire,
      last_ts: o.ts,
      error: o.error ?? o.reason,
    });
  }
  return rows;
}
