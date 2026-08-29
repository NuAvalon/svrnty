// CUR-2 / L1c — owner method-revision log + restore-previous seam (UI glass).
// ⛔ Flint owns signed monotonic ContactUpdateEnvelope + per-peer encrypt.
// Cursor may append local drafts and render history; never invent signatures
// or roll version backward on the wire (receivers reject stale-version).

export type MethodKind = 'email' | 'phone' | 'signal' | 'site' | 'name' | 'note';

export type MethodRevisionStatus = 'local-only' | 'queued-stub';

export interface MethodRevision {
  id: string;
  /** Local monotonic counter for this owner's log (UI). Wire version is Flint's. */
  localVersion: number;
  created_at: string;
  kind: MethodKind;
  value: string;
  /** Prior value this revision replaced (for one-tap restore). */
  previousValue?: string;
  /** Peers chosen to notify on this send (audience). Empty = local draft only. */
  recipientFingerprints: string[];
  status: MethodRevisionStatus;
  note?: string;
}

export type RestorePreviousResult =
  | {
      ok: true;
      restored: MethodRevision;
      message: string;
    }
  | {
      ok: false;
      reason: 'no-previous' | 'signing-not-live' | 'empty-log';
      message: string;
    };

const STORAGE_PREFIX = 'svrnty.method-history.v1:';

function storageKey(ownerFingerprint: string): string {
  return `${STORAGE_PREFIX}${ownerFingerprint}`;
}

function safeParse(raw: string | null): MethodRevision[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as MethodRevision[];
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (r) =>
        r &&
        typeof r.id === 'string' &&
        typeof r.localVersion === 'number' &&
        typeof r.kind === 'string' &&
        typeof r.value === 'string'
    );
  } catch {
    return [];
  }
}

/** Load owner method-revision log (newest last). */
export function loadMethodHistory(ownerFingerprint: string): MethodRevision[] {
  if (typeof localStorage === 'undefined' || !ownerFingerprint) return [];
  return safeParse(localStorage.getItem(storageKey(ownerFingerprint)));
}

export function saveMethodHistory(
  ownerFingerprint: string,
  revisions: MethodRevision[]
): void {
  if (typeof localStorage === 'undefined' || !ownerFingerprint) return;
  localStorage.setItem(storageKey(ownerFingerprint), JSON.stringify(revisions));
}

export function nextLocalVersion(revisions: MethodRevision[]): number {
  let max = 0;
  for (const r of revisions) if (r.localVersion > max) max = r.localVersion;
  return max + 1;
}

/** Append a local draft revision (does not transmit). */
export function appendMethodRevision(
  ownerFingerprint: string,
  input: {
    kind: MethodKind;
    value: string;
    previousValue?: string;
    recipientFingerprints?: string[];
    note?: string;
  }
): MethodRevision {
  const list = loadMethodHistory(ownerFingerprint);
  const rev: MethodRevision = {
    id: `rev_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
    localVersion: nextLocalVersion(list),
    created_at: new Date().toISOString(),
    kind: input.kind,
    value: input.value.trim(),
    previousValue: input.previousValue,
    recipientFingerprints: input.recipientFingerprints ?? [],
    status: 'local-only',
    note: input.note,
  };
  list.push(rev);
  saveMethodHistory(ownerFingerprint, list);
  return rev;
}

/** Revisions that notified (or would notify) a given peer — for contact-sheet filter. */
export function revisionsForPeer(
  revisions: MethodRevision[],
  peerFingerprint: string
): MethodRevision[] {
  if (!peerFingerprint) return revisions;
  const hit = revisions.filter((r) =>
    r.recipientFingerprints.includes(peerFingerprint)
  );
  // If nothing was audience-tagged yet, show full owner log (honest empty→full).
  return hit.length > 0 ? hit : revisions;
}

/**
 * One-tap restore-previous: append a NEW local revision that re-applies the
 * prior value. Does NOT sign or deposit — Flint replaces the stub body.
 *
 * Constitutional: never decreases wire version; restore = next higher revision
 * with prior field values (receivers reject rollback).
 */
export async function requestRestorePrevious(args: {
  ownerFingerprint: string;
  /** Revision to restore toward (uses its previousValue, or the prior log entry). */
  revisionId: string;
}): Promise<RestorePreviousResult> {
  const list = loadMethodHistory(args.ownerFingerprint);
  if (list.length === 0) {
    return {
      ok: false,
      reason: 'empty-log',
      message: 'No method revisions yet — revise a contact method first.',
    };
  }
  const idx = list.findIndex((r) => r.id === args.revisionId);
  if (idx < 0) {
    return {
      ok: false,
      reason: 'no-previous',
      message: 'That revision is not in your local history.',
    };
  }
  const target = list[idx];
  const prior =
    target.previousValue !== undefined
      ? target.previousValue
      : idx > 0
        ? list[idx - 1].value
        : undefined;
  if (prior === undefined) {
    return {
      ok: false,
      reason: 'no-previous',
      message: 'No earlier value to restore for this revision.',
    };
  }

  // Local draft of the correction (UI glass).
  appendMethodRevision(args.ownerFingerprint, {
    kind: target.kind,
    value: prior,
    previousValue: target.value,
    recipientFingerprints: target.recipientFingerprints,
    note: `Restore previous (from local v${target.localVersion})`,
  });

  // ⛔ Flint: sign ContactUpdateEnvelope at wire version+1 + encrypt-to-audience.
  return {
    ok: false,
    reason: 'signing-not-live',
    message:
      'Restored locally as a draft. Signed broadcast is not live yet — Flint owns monotonic sign + deposit.',
  };
}

/** Latest revision in the log (for “current” badge). */
export function latestRevision(
  revisions: MethodRevision[]
): MethodRevision | null {
  if (revisions.length === 0) return null;
  return revisions[revisions.length - 1];
}

export function summarizeRevision(r: MethodRevision): string {
  const val = r.value.length > 36 ? `${r.value.slice(0, 34)}…` : r.value;
  return `${r.kind}: ${val || '(empty)'}`;
}

/** Seed 2 local demo revisions when the log is empty (Trust Map sample / UI lab). */
export function seedDemoMethodHistory(
  ownerFingerprint: string,
  peerFingerprint?: string
): boolean {
  const existing = loadMethodHistory(ownerFingerprint);
  if (existing.length > 0) return false;
  const recipients = peerFingerprint ? [peerFingerprint] : [];
  appendMethodRevision(ownerFingerprint, {
    kind: 'email',
    value: 'before@example.invalid',
    recipientFingerprints: recipients,
    note: 'Demo revision (local only — not sent)',
  });
  appendMethodRevision(ownerFingerprint, {
    kind: 'email',
    value: 'after@example.invalid',
    previousValue: 'before@example.invalid',
    recipientFingerprints: recipients,
    note: 'Demo revision (local only — not sent)',
  });
  return true;
}
