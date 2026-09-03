'use client';

// CUR-2 — version-history + one-tap restore-previous chrome (Solar Ember).
// Signing / deposit stay stubbed.

import React, { useMemo, useState } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import {
  type MethodRevision,
  latestRevision,
  requestRestorePrevious,
  summarizeRevision,
} from './method-history';

export function MethodHistoryPanel({
  ownerFingerprint,
  peerFingerprint,
  revisions,
  peerWireVersion,
  onHistoryChange,
}: {
  ownerFingerprint: string;
  peerFingerprint?: string;
  revisions: MethodRevision[];
  /** Peer's last accepted wire version (bookkeeping) — display only. */
  peerWireVersion?: number | null;
  onHistoryChange?: () => void;
}) {
  const [status, setStatus] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const ordered = useMemo(
    () => [...revisions].sort((a, b) => b.localVersion - a.localVersion),
    [revisions]
  );
  const current = latestRevision(revisions);

  const restore = async (revisionId: string) => {
    setBusyId(revisionId);
    setStatus(null);
    try {
      const result = await requestRestorePrevious({
        ownerFingerprint,
        revisionId,
      });
      setStatus(result.message);
      onHistoryChange?.();
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div
      style={{
        fontSize: 12,
        color: E.muted,
        padding: 12,
        borderRadius: 8,
        border: `1px solid ${E.border}`,
        background: 'color-mix(in srgb, var(--se-accent) 5%, transparent)',
        display: 'flex',
        flexDirection: 'column',
        gap: 10,
      }}
    >
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'baseline' }}>
        <strong style={{ color: E.text, fontWeight: 600, fontSize: 13 }}>
          Version history
        </strong>
        {current ? (
          <span style={{ color: E.accent, fontFamily: E.fontMono, fontSize: 11 }}>
            local v{current.localVersion}
          </span>
        ) : (
          <span style={{ fontSize: 11 }}>no local revisions yet</span>
        )}
        {typeof peerWireVersion === 'number' && peerWireVersion > 0 && (
          <span style={{ fontSize: 11, color: E.dim }}>
            peer card wire v{peerWireVersion}
          </span>
        )}
      </div>

      <p style={{ margin: 0, lineHeight: 1.45, fontSize: 11 }}>
        Correct or retract a method update here. Restore writes a{' '}
        <em style={{ color: E.text, fontStyle: 'normal' }}>new</em> local
        revision with the prior value — never rolls a wire version backward.
        {peerFingerprint
          ? ' Showing your log (filtered to this peer when audience-tagged).'
          : null}
      </p>

      {ordered.length === 0 ? (
        <p style={{ margin: 0, fontSize: 11, color: E.dim }}>
          Empty. After you revise a contact method (and optionally notify peers),
          revisions appear here for one-tap restore.
        </p>
      ) : (
        <ul
          style={{
            listStyle: 'none',
            margin: 0,
            padding: 0,
            display: 'flex',
            flexDirection: 'column',
            gap: 8,
            maxHeight: 220,
            overflowY: 'auto',
          }}
        >
          {ordered.map((r, i) => (
            <li
              key={r.id}
              style={{
                padding: '8px 10px',
                borderRadius: 6,
                border: `1px solid ${i === 0 ? E.borderLit : E.border}`,
                background: 'color-mix(in srgb, var(--se-surface-solid) 80%, transparent)',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  gap: 8,
                  alignItems: 'center',
                }}
              >
                <span style={{ color: E.text, fontFamily: E.fontMono, fontSize: 11 }}>
                  v{r.localVersion}
                  {i === 0 ? ' · current' : ''}
                </span>
                <span style={{ fontSize: 10, color: E.dim }}>
                  {r.status === 'local-only' ? 'local draft' : r.status}
                </span>
              </div>
              <div style={{ marginTop: 4, color: E.muted, lineHeight: 1.4 }}>
                {summarizeRevision(r)}
              </div>
              {r.note && (
                <div style={{ marginTop: 2, fontSize: 10, color: E.dim }}>{r.note}</div>
              )}
              <div style={{ marginTop: 6, fontSize: 10, color: E.dim }}>
                {new Date(r.created_at).toLocaleString()}
                {r.recipientFingerprints.length > 0
                  ? ` · notify ${r.recipientFingerprints.length}`
                  : ' · no audience'}
              </div>
              {(r.previousValue !== undefined || i < ordered.length - 1) && (
                <button
                  type="button"
                  disabled={busyId === r.id}
                  onClick={() => void restore(r.id)}
                  style={{
                    marginTop: 8,
                    fontSize: 11,
                    padding: '5px 10px',
                    borderRadius: 6,
                    border: `1px solid ${E.borderLit}`,
                    background: 'color-mix(in srgb, var(--se-accent) 14%, transparent)',
                    color: E.accent,
                    cursor: busyId === r.id ? 'wait' : 'pointer',
                    opacity: busyId === r.id ? 0.6 : 1,
                  }}
                >
                  {busyId === r.id ? '…' : 'Restore previous'}
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      {status && (
        <p
          style={{
            margin: 0,
            fontSize: 11,
            lineHeight: 1.45,
            color: status.includes('not live') ? E.accent2 : E.muted,
          }}
          role="status"
        >
          {status}
        </p>
      )}
    </div>
  );
}
