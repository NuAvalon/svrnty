/**
 * CUR-5 — L3 trust / untrust / remove / block seam (UI → fleet).
 *
 * ⛔ Relay-auth + signal deposit (vouch / break / block mute) are owned outside this module.
 * This module is the UI contract + local apply helpers only.
 * Do NOT invent crypto, visibility gates, or wire formats here.
 */

export type TrustActionKind = 'trust' | 'break' | 'remove' | 'block' | 'unblock';

export type TrustActionTarget = {
  id: string;
  fingerprint: string;
  name: string;
  trusted: boolean;
  /** Local-only owner flag — never publish on the wire. */
  blocked?: boolean;
  /** Owner-local verify prereq — not a public badge. */
  ownerVerified?: boolean;
};

export type TrustActionCopy = {
  title: string;
  body: string;
  confirmLabel: string;
  cancelLabel: string;
  danger: boolean;
  /** Optional free-text reason (break only) — local audit; wire reason = fleet. */
  reasonOptional: boolean;
  reasonPlaceholder?: string;
};

/** Bound + strip control chars for display names in confirm copy (I-10a). */
export function safeDisplayName(raw: string, max = 64): string {
  const stripped = raw
    .normalize('NFC')
    .replace(/[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/g, '')
    .trim();
  if (!stripped) return 'this contact';
  return stripped.length > max ? `${stripped.slice(0, max)}…` : stripped;
}

/**
 * Claim-honest confirm copy (review wording before treating as final).
 * Says only what this UI does today: local book mutation. Wire notify = fleet stub.
 */
export function getTrustActionCopy(
  kind: TrustActionKind,
  target: TrustActionTarget
): TrustActionCopy {
  const name = safeDisplayName(target.name);

  switch (kind) {
    case 'trust':
      return {
        title: `Trust ${name}?`,
        body:
          'Trust only exists if it is mutual. On this device they become trusted when you Trust them — a one-way mark is not a covalent bond until they Trust you too. You already verified this is the person you mean (private to you). Notifying them on the wire is fleet-owned and not sent from this confirm yet.',
        confirmLabel: 'Trust',
        cancelLabel: 'Cancel',
        danger: false,
        reasonOptional: false,
      };
    case 'break':
      return {
        title: `Break trust with ${name}?`,
        body:
          'They drop to known on your device — still in your book, no longer trusted. A break is meant to be visible to both sides once signals sync; this confirm only updates your local book today.',
        confirmLabel: 'Break trust',
        cancelLabel: 'Cancel',
        danger: true,
        reasonOptional: true,
        reasonPlaceholder: 'Optional note for your local history (never shared automatically)',
      };
    case 'remove':
      return {
        title: `Remove ${name}?`,
        body:
          'Removes them from your local contacts and Galaxy. This does not notify them. You can re-add later if you exchange keys again.',
        confirmLabel: 'Remove',
        cancelLabel: 'Cancel',
        danger: true,
        reasonOptional: false,
      };
    case 'block':
      return {
        title: `Block ${name}?`,
        body:
          'Local only: they leave your Galaxy and inbound offers from them stay quiet on this device. The relay stays blind — blocking is not a server ban. Unblock anytime from Contacts.',
        confirmLabel: 'Block',
        cancelLabel: 'Cancel',
        danger: true,
        reasonOptional: false,
      };
    case 'unblock':
      return {
        title: `Unblock ${name}?`,
        body:
          'They return to your local book as known (not trusted). Trust is still yours to grant.',
        confirmLabel: 'Unblock',
        cancelLabel: 'Cancel',
        danger: false,
        reasonOptional: false,
      };
  }
}

export type TrustActionLocalPatch =
  | {
      kind: 'trust';
      trusted: true;
      trust_level: 'trusted';
      trusted_since: string;
      verified_at: string;
    }
  | {
      kind: 'break';
      trusted: false;
      trust_level: 'unverified';
      trusted_since: null;
      reason?: string;
    }
  | {
      kind: 'block';
      blocked: true;
      /** Block also clears local Trust — binary trust, no half-states. */
      trusted: false;
      trust_level: 'unverified';
      trusted_since: null;
    }
  | {
      kind: 'unblock';
      blocked: false;
    }
  | { kind: 'remove' };

export type TrustActionApplyResult =
  | {
      ok: true;
      kind: TrustActionKind;
      local: 'applied';
      /** Honest: relay/signal path not live from this UI. */
      wire: 'stub-not-live';
      message: string;
    }
  | {
      ok: false;
      reason: string;
      message: string;
    };

export type TrustActionApplyDeps = {
  /** Persist local contact mutation (fleet client-store / page handler). */
  applyLocal: (patch: TrustActionLocalPatch) => Promise<void>;
};

function buildLocalPatch(
  kind: TrustActionKind,
  reason?: string
): TrustActionLocalPatch {
  const now = new Date().toISOString();
  switch (kind) {
    case 'trust':
      return {
        kind: 'trust',
        trusted: true,
        trust_level: 'trusted',
        trusted_since: now,
        verified_at: now,
      };
    case 'break':
      return {
        kind: 'break',
        trusted: false,
        trust_level: 'unverified',
        trusted_since: null,
        reason: reason?.trim() || undefined,
      };
    case 'block':
      return {
        kind: 'block',
        blocked: true,
        trusted: false,
        trust_level: 'unverified',
        trusted_since: null,
      };
    case 'unblock':
      return { kind: 'unblock', blocked: false };
    case 'remove':
      return { kind: 'remove' };
  }
}

/**
 * Apply a confirmed trust action locally. Wire notify stays stubbed.
 */
export async function applyTrustAction(
  kind: TrustActionKind,
  target: TrustActionTarget,
  deps: TrustActionApplyDeps,
  opts?: { reason?: string }
): Promise<TrustActionApplyResult> {
  if (!target.id) {
    return {
      ok: false,
      reason: 'missing-id',
      message: 'This contact has no local id — cannot update.',
    };
  }

  if (kind === 'trust' && target.trusted) {
    return {
      ok: false,
      reason: 'already-trusted',
      message: 'Already trusted on this device.',
    };
  }
  if (kind === 'trust' && !target.ownerVerified) {
    return {
      ok: false,
      reason: 'need-verify',
      message:
        'Verify this is the person you mean (in person or another channel) before you Trust. That check stays on this device — nobody else sees it.',
    };
  }
  if (kind === 'break' && !target.trusted) {
    return {
      ok: false,
      reason: 'not-trusted',
      message: 'Not trusted — nothing to break.',
    };
  }
  if (kind === 'block' && target.blocked) {
    return {
      ok: false,
      reason: 'already-blocked',
      message: 'Already blocked on this device.',
    };
  }
  if (kind === 'unblock' && !target.blocked) {
    return {
      ok: false,
      reason: 'not-blocked',
      message: 'Not blocked.',
    };
  }

  try {
    await deps.applyLocal(buildLocalPatch(kind, opts?.reason));
  } catch (err) {
    return {
      ok: false,
      reason: 'local-failed',
      message: err instanceof Error ? err.message : 'Local update failed.',
    };
  }

  const name = safeDisplayName(target.name);
  const messages: Record<TrustActionKind, string> = {
    trust: `Trusted ${name} on this device.`,
    break: `Trust broken with ${name} — still known locally.`,
    remove: `Removed ${name} from this device.`,
    block: `Blocked ${name} on this device.`,
    unblock: `Unblocked ${name} — known again.`,
  };

  return {
    ok: true,
    kind,
    local: 'applied',
    wire: 'stub-not-live',
    message: messages[kind],
  };
}

/** Read local blocked flag from open-bag contact / edge shapes. */
export function isContactBlocked(record: {
  blocked?: boolean;
  metadata?: { blocked?: boolean };
}): boolean {
  return !!(record.blocked || record.metadata?.blocked);
}
