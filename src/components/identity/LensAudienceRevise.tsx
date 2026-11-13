'use client';

/**
 * Lenses v1.3 — the Revise view (contract R3/R6): each recipient's lens, with a warning before
 * widening. Render-glass only: the grant store, the wire and the send live in src/lib/lenses/* —
 * this component renders plans and collects PER-RECIPIENT confirms. There is deliberately NO
 * select-all for widening: group selection can only propose plans; every widening plan needs its
 * own explicit confirm (R3).
 *
 * Copy is the contract's exact strings (lens-copy.ts): the widening warning names the recipient
 * and the method; the narrowing note says they keep what they have; the explainer says anyone can
 * pass a card on. No copy here claims a lens takes anything back.
 */

import { useMemo, useState, type CSSProperties } from 'react';
import { solarEmber as E } from '../recovery/solar-ember';
import type { OwnerCardBag } from './owner-card';
import { methodKindLabel } from './owner-card';
import type { LensGrantBook } from '../../lib/lenses/lens-grants';
import { planLensReassign, plansNeedingConfirm, type LensReassignPlan } from '../../lib/lenses/lens-plan';
import { lensForSend } from '../../lib/lenses/lens-send';
import { LENS_EXPLAINER, lensNarrowingNote, lensWideningWarning } from '../../lib/lenses/lens-copy';

export type LensAudienceContact = {
  fingerprint: string;
  name: string;
};

export type LensAudienceReviseProps = {
  contacts: LensAudienceContact[];
  bag: OwnerCardBag;
  book: LensGrantBook;
  /** Persist ONE recipient's confirmed plan — the caller applies `commitReassignPlan(book, plan)`
   *  (lens assignment + the confirmed widening keys recorded into their sent set), then sends. */
  onAssign: (plan: LensReassignPlan) => void | Promise<void>;
  /** Recipients whose payload is held (R7): they have not shown they can take lens payloads. */
  heldFingerprints?: string[];
  onClose?: () => void;
};

export function LensAudienceRevise({ contacts, bag, book, onAssign, heldFingerprints, onClose }: LensAudienceReviseProps) {
  const held = useMemo(() => new Set((heldFingerprints ?? []).map((f) => f.toLowerCase())), [heldFingerprints]);
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [confirming, setConfirming] = useState<LensReassignPlan | null>(null);
  const [busy, setBusy] = useState(false);

  const pick = (fp: string, lensId: string) => setDraft((d) => ({ ...d, [fp]: lensId }));

  const planFor = (fp: string): LensReassignPlan | null => {
    const to = draft[fp];
    if (to === undefined) return null;
    return planLensReassign(bag, book, fp, to === '' ? null : to);
  };

  const commit = async (plan: LensReassignPlan) => {
    setBusy(true);
    try {
      await onAssign(plan);
      setDraft((d) => {
        const next = { ...d };
        delete next[plan.fingerprint];
        return next;
      });
    } finally {
      setBusy(false);
      setConfirming(null);
    }
  };

  const apply = (fp: string) => {
    const plan = planFor(fp);
    if (!plan) return;
    // R3: a widening is confirmed PER RECIPIENT — never silently, never by a batch control.
    if (plan.widening) setConfirming(plan);
    else void commit(plan);
  };

  const pendingWidens = plansNeedingConfirm(
    Object.keys(draft).map((fp) => planFor(fp)).filter((p): p is LensReassignPlan => !!p),
  ).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, fontFamily: E.fontSans }}>
      <p style={{ margin: 0, fontSize: 11, color: E.dim, lineHeight: 1.5 }}>{LENS_EXPLAINER}</p>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {contacts.map((c) => {
          const fp = c.fingerprint.toLowerCase();
          const current = lensForSend(bag, book, fp);
          const plan = planFor(fp);
          const narrowed = plan && !plan.widening && plan.removed.length > 0;
          return (
            <div
              key={fp}
              data-testid={`lens-row-${fp.slice(0, 12)}`}
              style={{
                border: `1px solid ${E.border}`,
                borderRadius: 10,
                padding: '10px 12px',
                background: E.inputBg,
                display: 'flex',
                flexDirection: 'column',
                gap: 6,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, justifyContent: 'space-between' }}>
                <span style={{ fontSize: 13, color: E.text, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {c.name || 'Unnamed'}
                  {held.has(fp) ? (
                    <span
                      style={{ marginLeft: 8, fontSize: 10, color: E.dim }}
                      title={`${c.name ? `${c.name}'s app` : 'Their app'} hasn't shown it can receive this yet.`}
                    >
                      · not sent yet
                    </span>
                  ) : null}
                </span>
                <select
                  aria-label={`Lens for ${c.name || fp.slice(0, 12)}`}
                  value={draft[fp] ?? current?.id ?? ''}
                  onChange={(ev) => pick(fp, ev.target.value)}
                  style={{
                    background: E.inputBg,
                    border: `1px solid ${E.border}`,
                    borderRadius: 8,
                    color: E.text,
                    fontSize: 12,
                    padding: '4px 8px',
                  }}
                >
                  {/* R2: a recipient with no record shows the explicit no-face option — never a
                      guessed face; assigning one plans a widening on every method it would send. */}
                  <option value="">· none given ·</option>
                  {bag.lenses.map((l) => (
                    <option key={l.id} value={l.id}>
                      {l.name}
                      {l.id === bag.defaultLensId ? ' · default' : ''}
                    </option>
                  ))}
                </select>
              </div>

              {plan ? (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                  <span style={{ fontSize: 11, color: plan.widening ? E.accent : E.dim, lineHeight: 1.4 }}>
                    {plan.widening
                      ? `${plan.added.length} method${plan.added.length === 1 ? '' : 's'} they don't have yet`
                      : narrowed
                        ? lensNarrowingNote(c.name || 'They')
                        : 'Same methods — no change in what they see.'}
                  </span>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => apply(fp)}
                    style={{ ...ghostBtn, color: plan.widening ? E.accent : E.muted }}
                  >
                    Apply
                  </button>
                </div>
              ) : null}
            </div>
          );
        })}
      </div>

      {confirming ? (
        <div
          role="alertdialog"
          aria-label="Confirm widening"
          style={{ border: `1px solid ${E.borderLit}`, borderRadius: 12, padding: 12, background: 'color-mix(in srgb, var(--se-accent) 8%, transparent)' }}
        >
          <p style={{ margin: '0 0 8px', fontSize: 12, color: E.text, lineHeight: 1.5 }}>
            {confirming.added.map((m) => lensWideningWarning(nameOf(contacts, confirming.fingerprint), labelOf(m.kind))).join(' ')}
          </p>
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button type="button" onClick={() => setConfirming(null)} style={ghostBtn}>
              Back
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => void commit(confirming)}
              style={{ ...ghostBtn, color: E.accent, border: `1px solid ${E.borderLit}` }}
            >
              Send it
            </button>
          </div>
        </div>
      ) : null}

      {pendingWidens > 0 && !confirming ? (
        <p style={{ margin: 0, fontSize: 10, color: E.dim }}>
          {pendingWidens} change{pendingWidens === 1 ? '' : 's'} will ask before sending.
        </p>
      ) : null}

      {onClose ? (
        <button type="button" onClick={onClose} style={{ ...ghostBtn, alignSelf: 'flex-end' }}>
          Close
        </button>
      ) : null}
    </div>
  );
}

function nameOf(contacts: LensAudienceContact[], fp: string): string {
  return contacts.find((c) => c.fingerprint.toLowerCase() === fp.toLowerCase())?.name || 'them';
}

function labelOf(kind: string): string {
  // OwnerMethodKind labels; an unknown kind renders its raw kind (bounded wire value).
  return methodKindLabel(kind as Parameters<typeof methodKindLabel>[0]);
}

const ghostBtn: CSSProperties = {
  background: 'transparent',
  border: `1px solid ${E.border}`,
  color: E.muted,
  borderRadius: 8,
  padding: '4px 10px',
  fontSize: 11,
  cursor: 'pointer',
};
