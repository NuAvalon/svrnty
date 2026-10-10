'use client';

/**
 * CUR-5 — Solar Ember confirm dialog for trust / break / remove / block.
 * Pure UI glass — mutations go through applyTrustAction + parent deps.
 */

import React, { useEffect, useState } from 'react';
import { solarEmber as E, solarGlass } from '@/components/recovery/solar-ember';
import {
  getTrustActionCopy,
  type TrustActionKind,
  type TrustActionTarget,
} from './trust-actions';

export type TrustActionConfirmDialogProps = {
  open: boolean;
  kind: TrustActionKind | null;
  target: TrustActionTarget | null;
  busy?: boolean;
  onCancel: () => void;
  onConfirm: (opts: { reason?: string }) => void | Promise<void>;
};

export function TrustActionConfirmDialog({
  open,
  kind,
  target,
  busy = false,
  onCancel,
  onConfirm,
}: TrustActionConfirmDialogProps) {
  const [reason, setReason] = useState('');

  useEffect(() => {
    if (open) setReason('');
  }, [open, kind, target?.id]);

  if (!open || !kind || !target) return null;

  const copy = getTrustActionCopy(kind, target);

  return (
    <div
      role="presentation"
      data-testid="trust-action-confirm-overlay"
      onClick={onCancel}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 80,
        background: 'rgba(8, 5, 3, 0.72)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 16,
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="trust-action-confirm-title"
        data-testid="trust-action-confirm"
        data-action-kind={kind}
        onClick={(e) => e.stopPropagation()}
        style={{
          ...solarGlass,
          width: '100%',
          maxWidth: 420,
          padding: '22px 22px 18px',
          color: E.text,
          fontFamily: E.fontSans,
        }}
      >
        <h2
          id="trust-action-confirm-title"
          style={{
            margin: 0,
            fontSize: 18,
            fontWeight: 600,
            color: E.text,
            letterSpacing: '0.01em',
          }}
        >
          {copy.title}
        </h2>
        <p
          style={{
            margin: '12px 0 0',
            fontSize: 13,
            lineHeight: 1.55,
            color: E.muted,
          }}
        >
          {copy.body}
        </p>

        {copy.reasonOptional && (
          <label
            style={{
              display: 'block',
              marginTop: 16,
              fontSize: 12,
              color: E.dim,
            }}
          >
            Local note (optional)
            <textarea
              data-testid="trust-action-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value.slice(0, 280))}
              placeholder={copy.reasonPlaceholder}
              rows={3}
              disabled={busy}
              style={{
                display: 'block',
                width: '100%',
                marginTop: 6,
                boxSizing: 'border-box',
                resize: 'vertical',
                background: E.inputBg,
                border: `1px solid ${E.border}`,
                borderRadius: 8,
                padding: '8px 10px',
                color: E.text,
                fontFamily: E.fontSans,
                fontSize: 13,
              }}
            />
          </label>
        )}

        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
            gap: 8,
            marginTop: 20,
            flexWrap: 'wrap',
          }}
        >
          <button
            type="button"
            data-testid="trust-action-cancel"
            onClick={onCancel}
            disabled={busy}
            style={btnStyle(false, false)}
          >
            {copy.cancelLabel}
          </button>
          <button
            type="button"
            data-testid="trust-action-confirm-btn"
            onClick={() => void onConfirm({ reason: reason.trim() || undefined })}
            disabled={busy}
            style={btnStyle(true, copy.danger)}
          >
            {busy ? '…' : copy.confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

function btnStyle(primary: boolean, danger: boolean): React.CSSProperties {
  return {
    fontSize: 13,
    fontFamily: E.fontSans,
    fontWeight: primary ? 600 : 400,
    padding: '8px 14px',
    borderRadius: 8,
    border: `1px solid ${danger ? E.danger : E.borderLit}`,
    background: primary
      ? danger
        ? 'color-mix(in srgb, var(--se-danger) 16%, transparent)'
        : 'color-mix(in srgb, var(--se-accent) 14%, transparent)'
      : 'transparent',
    color: danger ? E.danger : E.accent,
    cursor: 'pointer',
    letterSpacing: primary ? '0.04em' : undefined,
    opacity: 1,
  };
}
