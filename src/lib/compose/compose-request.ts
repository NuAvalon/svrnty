// src/lib/compose/compose-request.ts
// Validates an inbound portal sign-request BEFORE the app shows a card or signs anything (spec v0.7 §1/§6/§7/§8). PURE: no I/O, no keys, no clock
// except the `now` the caller passes in.
//
// STRICT BY DESIGN. The object is signed byte for byte, so the app accepts EXACTLY the known fields, all strings, and REFUSES anything else (an
// unknown key could smuggle content into the signed bytes). The app never normalises: a refusal is final and there is no "sign anyway".
//
// Defaults taken from Archie's architect defaults (lane:portal #994) until the owners override: task cost = cost(title)+cost(body) <= 2900 TOTAL;
// refuse issued_at more than 60 s ahead of the phone's clock; one card at a time. ASSUMPTIONS (mine, flagged for Athena/Flint): task `target` uses the
// thread-id charset or the literal "route"; a task's thread is exactly "lane:orch"; `dag_node` uses the thread-id charset; an empty (or all-whitespace)
// body/title is refused (the whitespace check only DECIDES, it never rewrites).
import { COMPOSE_CAP, composeCost, isValidThreadId, mentionsHint, onlySubdivisionFlag, refusedAt, type ComposeKind } from './compose-rules';

export const COMPOSE_ORIGIN = 'noosphere.nuavalon.com';
export const COMPOSE_FLEETS = ['autobots', 'weft'] as const;
export const COMPOSE_PURPOSE: Record<ComposeKind, string> = { post: 'svrnty-loom-post-v1', task: 'svrnty-loom-task-v1' };
export const COMPOSE_TASK_THREAD = 'lane:orch';
/** expires_at - issued_at must be in (0, 5 min]. */
export const COMPOSE_MAX_WINDOW_MS = 5 * 60 * 1000;
/** A request "issued" further ahead than this on the phone's clock is refused (clock skew / replay-prep). */
export const COMPOSE_MAX_FUTURE_SKEW_MS = 60 * 1000;

const POST_FIELDS = ['purpose', 'fleet', 'thread', 'body', 'nonce', 'issued_at', 'expires_at', 'origin'] as const;
const TASK_FIELDS = ['purpose', 'fleet', 'thread', 'title', 'body', 'target', 'nonce', 'issued_at', 'expires_at', 'origin'] as const;
const TASK_OPTIONAL = ['dag_node'] as const;

/** Why a request was refused. The card renders a fixed sentence per code; none of them interpolates request text. */
export type RefusalCode =
  | 'not-an-object'
  | 'unknown-purpose'
  | 'unknown-field'
  | 'missing-field'
  | 'not-a-string'
  | 'bad-fleet'
  | 'bad-origin'
  | 'bad-thread'
  | 'bad-task-thread'
  | 'bad-target'
  | 'bad-dag-node'
  | 'bad-nonce'
  | 'bad-time'
  | 'window-not-forward'
  | 'window-too-long'
  | 'expired'
  | 'issued-in-future'
  | 'empty'
  | 'refused-characters'
  | 'over-cap';

export interface Refusal {
  code: RefusalCode;
  /** The field that failed, when one KNOWN field is at fault (always one of our own field names, never request text). */
  field?: string;
  /** Code-point indices of refused characters (refused-characters only). */
  indices?: number[];
  /** True when the ONLY refused characters are the TAG characters of a subdivision flag (Hypatia #812: lets the card say so honestly). */
  flagAddendum?: boolean;
  /** Computed cost (over-cap only). */
  cost?: number;
}

export interface ValidRequest {
  kind: ComposeKind;
  /** A fresh object holding exactly the signed fields. */
  object: Record<string, string>;
  /** composeCost of what the cap applies to (body for a post; title + body for a task). */
  cost: number;
  /** "@" + a letter appears in the text: show "Mentions don't notify from here yet. Your message is posted as written." */
  mentionsHint: boolean;
}

export type ComposeValidation = { ok: true; request: ValidRequest } | { ok: false; refusal: Refusal };

const refuse = (refusal: Refusal): ComposeValidation => ({ ok: false, refusal });
const ISO_MS_Z = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/** Exact ISO-8601 ms Z, and a real instant (2026-02-31 and the like are refused by the round trip). Returns epoch ms or null. */
function parseInstant(s: string): number | null {
  if (!ISO_MS_Z.test(s)) return null;
  const t = Date.parse(s);
  if (Number.isNaN(t)) return null;
  return new Date(t).toISOString() === s ? t : null;
}

export function validateComposeRequest(raw: unknown, now: Date): ComposeValidation {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return refuse({ code: 'not-an-object' });
  const o = raw as Record<string, unknown>;

  const kind: ComposeKind | null = o.purpose === COMPOSE_PURPOSE.post ? 'post' : o.purpose === COMPOSE_PURPOSE.task ? 'task' : null;
  if (!kind) return refuse({ code: 'unknown-purpose', field: 'purpose' });

  const required: readonly string[] = kind === 'post' ? POST_FIELDS : TASK_FIELDS;
  const allowed = new Set<string>([...required, ...(kind === 'task' ? TASK_OPTIONAL : [])]);
  // The unknown key's NAME is request text: it is deliberately NOT carried in the refusal (the card must never render hostile text).
  for (const k of Object.keys(o)) if (!allowed.has(k)) return refuse({ code: 'unknown-field' });
  for (const k of required) if (!(k in o)) return refuse({ code: 'missing-field', field: k });
  for (const k of Object.keys(o)) if (typeof o[k] !== 'string') return refuse({ code: 'not-a-string', field: k });
  const s = o as Record<string, string>;

  if (!(COMPOSE_FLEETS as readonly string[]).includes(s.fleet)) return refuse({ code: 'bad-fleet', field: 'fleet' });
  if (s.origin !== COMPOSE_ORIGIN) return refuse({ code: 'bad-origin', field: 'origin' });
  if (!isValidThreadId(s.thread)) return refuse({ code: 'bad-thread', field: 'thread' });
  if (kind === 'task') {
    if (s.thread !== COMPOSE_TASK_THREAD) return refuse({ code: 'bad-task-thread', field: 'thread' });
    if (s.target !== 'route' && !isValidThreadId(s.target)) return refuse({ code: 'bad-target', field: 'target' });
    if ('dag_node' in s && !isValidThreadId(s.dag_node)) return refuse({ code: 'bad-dag-node', field: 'dag_node' });
  }
  if (!/^[0-9a-f]{32}$/.test(s.nonce)) return refuse({ code: 'bad-nonce', field: 'nonce' });

  const issued = parseInstant(s.issued_at);
  if (issued === null) return refuse({ code: 'bad-time', field: 'issued_at' });
  const expires = parseInstant(s.expires_at);
  if (expires === null) return refuse({ code: 'bad-time', field: 'expires_at' });
  if (expires <= issued) return refuse({ code: 'window-not-forward', field: 'expires_at' });
  if (expires - issued > COMPOSE_MAX_WINDOW_MS) return refuse({ code: 'window-too-long', field: 'expires_at' });
  const t = now.getTime();
  if (expires <= t) return refuse({ code: 'expired', field: 'expires_at' });
  if (issued > t + COMPOSE_MAX_FUTURE_SKEW_MS) return refuse({ code: 'issued-in-future', field: 'issued_at' });

  // Free text: the refusal set applies to every text field, and it is FINAL (no strip, no normalise).
  const textFields = kind === 'task' ? ['title', 'body'] : ['body'];
  for (const f of textFields) {
    if (s[f].trim() === '') return refuse({ code: 'empty', field: f });
    const indices = refusedAt(s[f]);
    if (indices.length > 0) return refuse({ code: 'refused-characters', field: f, indices, flagAddendum: onlySubdivisionFlag(s[f]) });
  }

  const cost = textFields.reduce((n, f) => n + composeCost(s[f]), 0);
  if (cost > COMPOSE_CAP) return refuse({ code: 'over-cap', cost });

  const object: Record<string, string> = {};
  for (const k of Object.keys(s)) object[k] = s[k];
  return { ok: true, request: { kind, object, cost, mentionsHint: textFields.some((f) => mentionsHint(s[f])) } };
}
