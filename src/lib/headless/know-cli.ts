// src/lib/headless/know-cli.ts
//
// The command-line side of the headless KNOW seats (S53 follow-up): the guards, the run report and the consent step
// a dev dogfood run needs on top of know-psi.ts. Pure functions with every effect injected, so each rule is
// tested without a network, a clock or a real directory. scripts/devin-know.ts is only the thin wiring around them.
//
// DEV ONLY, THROWAWAY ONLY. Nothing here names a satellite: the target is know-psi's fixed DEV_SATELLITE_URL, and every
// function that acts on a seat refuses an artifact that is not a throwaway before it signs or sends anything.
//
// HEADLESS-ONLY (type-imports HeadlessStore): never import into the browser bundle.

import type { SerializedMintArtifact } from '@/lib/identity/headless-mint';
import { addAllowedSender, allowedRowShouldExist } from '@/lib/sync/allowed-sync';
import type { HeadlessStore, HeadlessContact } from './headless-store';
import { DEV_SATELLITE_URL } from './know-psi';

export class KnowCliGuardError extends Error {
  constructor(what: string) {
    super(`know-cli: refused: ${what}`);
    this.name = 'KnowCliGuardError';
  }
}

const FP_RE = /^[0-9a-f]{8,128}$/; // lowercase hex, the satellite's own bounds (8..128): the value goes into a URL path
const p8 = (fp: string): string => fp.slice(0, 8);

// ── seat home guards ─────────────────────────────────────────────────────────

/**
 * The seat directory comes from SVRNTY_AGENT_DIR and nowhere else. Unset, empty or relative refuses: scripts/devin-comm.ts
 * falls back to a shared sandbox directory when the variable is unset, and these commands must never run against that.
 */
export function agentHomeFromEnv(env: Record<string, string | undefined>): string {
  const v = env.SVRNTY_AGENT_DIR;
  if (typeof v !== 'string' || v === '') throw new KnowCliGuardError('SVRNTY_AGENT_DIR is not set (no fallback directory is used)');
  if (!v.startsWith('/')) throw new KnowCliGuardError('SVRNTY_AGENT_DIR must be an absolute path');
  return v.replace(/\/+$/, '') || '/';
}

const DIR_FLAG = /^--(agent-dir|dir|home|seat-dir|svrnty-agent-dir)(=|$)/;

/** A seat directory is never taken from the command line (it would sit in process listings and shell history). */
export function refuseDirInArgv(argv: readonly string[]): void {
  for (const a of argv) if (DIR_FLAG.test(a)) throw new KnowCliGuardError('a seat directory is never taken from the command line');
}

export interface StatLike {
  isDirectory(): boolean;
  isFile(): boolean;
  uid: number;
  mode: number;
}
export interface FsProbe {
  lstat(path: string): StatLike;
}

/** Only a throwaway artifact is ever driven. `=== true` on purpose: missing, 'true' and 1 all refuse. */
export function assertThrowaway(artifact: unknown): asserts artifact is SerializedMintArtifact {
  if ((artifact as { throwaway?: unknown } | null)?.throwaway !== true) {
    throw new KnowCliGuardError('this identity is not a throwaway (a real identity is never driven by these commands)');
  }
}

function statOrRefuse(fsx: FsProbe, path: string, what: string): StatLike {
  try {
    return fsx.lstat(path);
  } catch {
    throw new KnowCliGuardError(`${what} is missing or unreadable`);
  }
}

/**
 * The seat home must be a real directory (not a symlink) owned by the caller with no group/other permission, holding a
 * real file mint.json with the same rules, whose artifact is a throwaway. lstat, never stat: lstat reports a symlink as neither a
 * directory nor a file, so a link is refused, not followed (tests/know-cli.test.ts proves it on a real directory).
 */
export function assertSeatHome(dir: string, artifact: unknown, fsx: FsProbe, uid: number): void {
  const d = statOrRefuse(fsx, dir, 'the seat directory');
  if (!d.isDirectory()) throw new KnowCliGuardError('the seat directory is not a real directory (a symlink is refused)');
  if (d.uid !== uid) throw new KnowCliGuardError('the seat directory is not owned by the caller');
  if ((d.mode & 0o077) !== 0) throw new KnowCliGuardError('the seat directory has group or other permissions');
  const m = statOrRefuse(fsx, `${dir}/mint.json`, 'mint.json');
  if (!m.isFile()) throw new KnowCliGuardError('mint.json is not a real file (a symlink is refused)');
  if (m.uid !== uid) throw new KnowCliGuardError('mint.json is not owned by the caller');
  if ((m.mode & 0o077) !== 0) throw new KnowCliGuardError('mint.json has group or other permissions');
  assertThrowaway(artifact);
}

// ── report ───────────────────────────────────────────────────────────────────

export interface KnowReportRow {
  peer: string; // 8-hex prefix
  consented: boolean; // THIS seat's own consent flag
  mutual: boolean; // consented AND the sync core completed an exchange at or after --since
  disclosed: number; // size of the disclosed circle (a count, never the members)
}
export interface KnowReport {
  since: string;
  rows: KnowReportRow[];
  counts: { contacts: number; consented: number; mutual: number };
}

const syncMs = (c: HeadlessContact): number => {
  const ls = c.mutual?.last_sync;
  return typeof ls === 'string' && ls !== '' ? Date.parse(ls) : NaN;
};

/**
 * What a run may publish: 8-hex prefixes, two flags and counts. "mutual" means this seat consented and the sync core's own
 * completion marker (mutual.last_sync, written only when an exchange finished) is at or after `since`, so a marker left by
 * an earlier run never counts. `since` is required: without it a stale marker cannot be told from a fresh one.
 */
export function buildKnowReport(store: Pick<HeadlessStore, 'listContacts'>, since: unknown): KnowReport {
  const sinceMs = typeof since === 'string' ? Date.parse(since) : NaN;
  if (!Number.isFinite(sinceMs)) throw new KnowCliGuardError('--since is required and must be a timestamp');
  const all = store.listContacts();
  const rows: KnowReportRow[] = [];
  let consentedN = 0;
  let mutualN = 0;
  for (const c of all) {
    const consented = c.open_visibility === true;
    const ms = syncMs(c);
    const completed = Number.isFinite(ms) && ms >= sinceMs;
    const mutual = consented && completed;
    const disclosed = Array.isArray(c.disclosed_circle) ? (c.disclosed_circle as unknown[]).filter((x) => typeof x === 'string').length : 0;
    if (consented) consentedN++;
    if (mutual) mutualN++;
    if (consented || completed || disclosed > 0) rows.push({ peer: p8(c.fingerprint), consented, mutual, disclosed });
  }
  rows.sort((a, b) => a.peer.localeCompare(b.peer));
  return { since: new Date(sinceMs).toISOString(), rows, counts: { contacts: all.length, consented: consentedN, mutual: mutualN } };
}

// ── know-on ──────────────────────────────────────────────────────────────────

export interface KnowOnDeps {
  addAllowedSender?: typeof addAllowedSender;
  fetchImpl?: typeof fetch;
}
export type KnowOnResult = {
  ok: boolean;
  peer: string;
  reason?: 'unknown-contact' | 'self' | 'blocked' | 'private' | 'relay-refused';
};

const seedOf = (a: SerializedMintArtifact): Uint8Array => {
  const seed = new Uint8Array(Buffer.from(a?.private?.ed25519_seed ?? '', 'base64'));
  if (seed.length !== 32) throw new KnowCliGuardError('the seat has no usable signing seed');
  return seed;
};

/**
 * Consent to one peer: put the owner-signed allowed row on the dev satellite FIRST, and only when it was accepted record
 * the consent flag locally. A refused or failed row leaves no flag behind, so the report does not say "consented" for a
 * row the satellite does not hold. A blocked, private, unknown or own contact makes no request at all.
 */
export async function knowOn(
  artifact: SerializedMintArtifact,
  store: Pick<HeadlessStore, 'listContacts' | 'updateContact'>,
  peerFp: string,
  deps: KnowOnDeps = {},
): Promise<KnowOnResult> {
  assertThrowaway(artifact);
  if (typeof peerFp !== 'string' || !FP_RE.test(peerFp)) throw new KnowCliGuardError('the peer fingerprint is not lowercase hex');
  const ownerFp = artifact.public.durable_id;
  const peer = p8(peerFp);
  if (peerFp === ownerFp) return { ok: false, peer, reason: 'self' };
  const c = store.listContacts().find((x) => x.fingerprint === peerFp);
  if (!c) return { ok: false, peer, reason: 'unknown-contact' };
  const blocked = Boolean(c.blocked || (c.metadata as { blocked?: unknown } | undefined)?.blocked);
  const priv = Boolean(c.per_contact_private);
  if (!allowedRowShouldExist({ trusted: c.trusted === true, openVisibility: true, blocked, perContactPrivate: priv })) {
    return { ok: false, peer, reason: blocked ? 'blocked' : 'private' };
  }
  const add = deps.addAllowedSender ?? addAllowedSender;
  let accepted = false;
  try {
    accepted = await add({
      ownerFp,
      senderFp: peerFp,
      seed: seedOf(artifact),
      base: `${DEV_SATELLITE_URL}/allowed`,
      ...(deps.fetchImpl ? { fetchImpl: deps.fetchImpl } : {}),
    });
  } catch {
    accepted = false;
  }
  if (!accepted) return { ok: false, peer, reason: 'relay-refused' };
  store.updateContact(c.id, { open_visibility: true });
  return { ok: true, peer };
}
