'use client';

/**
 * Gate list + admit sheet.
 * Grow hosts a compact list. Galaxy hosts a searchable overlay over the lattice.
 * Arrivals are not Galaxy stars until Admit.
 */

import { useEffect, useMemo, useState, type CSSProperties } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import {
  GATE_COPY,
  admitGateArrival,
  dismissGateArrival,
  matchGateQuery,
  parseTagList,
} from '@/lib/trust/grow-gate';
import { formatFingerprintForVerify, TRUST_RECIPE_COPY } from '@/lib/trust/trust-recipe';
import { loadGateArrivals, type GateArrival } from '@/lib/identity/client-store';
import { subscribeContactChanges } from '@/lib/contacts/contact-events';

type Props = {
  ownerFp: string;
  /** Galaxy overlay vs Grow inset. */
  variant?: 'grow' | 'overlay';
  onClose?: () => void;
  /** Fired after a successful admit so Galaxy can ignite the new star. */
  onAdmitted?: (fingerprint: string) => void;
};

const fieldStyle: CSSProperties = {
  marginTop: 6,
  width: '100%',
  background: E.inputBg,
  border: `1px solid ${E.border}`,
  borderRadius: 8,
  color: E.text,
  padding: '10px 12px',
  fontFamily: E.fontSans,
  fontSize: 13,
};

const btnStyle = (primary?: boolean): CSSProperties => ({
  width: '100%',
  padding: '10px 14px',
  borderRadius: 8,
  border: `1px solid ${primary ? E.borderLit : E.border}`,
  background: primary ? 'color-mix(in srgb, var(--se-accent) 12%, transparent)' : 'transparent',
  color: E.text,
  cursor: 'pointer',
  fontFamily: E.fontSans,
  fontSize: 13,
});

export function GrowGatePanel({ ownerFp, variant = 'grow', onClose, onAdmitted }: Props) {
  const [arrivals, setArrivals] = useState<GateArrival[]>([]);
  const [focus, setFocus] = useState<GateArrival | null>(null);
  const [query, setQuery] = useState('');
  const [name, setName] = useState('');
  const [tags, setTags] = useState('');
  const [notes, setNotes] = useState('');
  const [verify, setVerify] = useState<'none' | 'in_person' | 'other_channel'>('none');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    try {
      const list = await loadGateArrivals(ownerFp);
      setArrivals(list);
    } catch {
      /* non-fatal */
    }
  };

  useEffect(() => {
    void refresh();
    return subscribeContactChanges(() => {
      void refresh();
    });
  }, [ownerFp]);

  const visible = useMemo(
    () => arrivals.filter((a) => matchGateQuery(a, query)),
    [arrivals, query],
  );

  const openAdmit = (a: GateArrival) => {
    setFocus(a);
    setName(a.displayName);
    setTags('');
    setNotes('');
    setVerify(a.mintChannel === 'in_person' ? 'in_person' : 'none');
    setError(null);
  };

  const onAdmit = async () => {
    if (!focus || busy) return;
    setBusy(true);
    setError(null);
    try {
      const fp = focus.fingerprint;
      await admitGateArrival(ownerFp, focus, {
        name,
        tags: parseTagList(tags),
        notes,
        verify: verify === 'none' ? null : verify,
      });
      setFocus(null);
      await refresh();
      onAdmitted?.(fp);
      onClose?.();
    } catch (e: any) {
      setError(e?.message || 'Could not admit them.');
    } finally {
      setBusy(false);
    }
  };

  const onDismiss = async () => {
    if (!focus || busy) return;
    setBusy(true);
    try {
      await dismissGateArrival(ownerFp, focus.fingerprint);
      setFocus(null);
      await refresh();
    } catch (e: any) {
      setError(e?.message || 'Could not dismiss.');
    } finally {
      setBusy(false);
    }
  };

  const shellStyle: CSSProperties =
    variant === 'overlay'
      ? {
          position: 'absolute',
          inset: 8,
          zIndex: 12,
          overflowY: 'auto',
          background: 'color-mix(in srgb, var(--se-bg) 94%, transparent)',
          border: `1px solid ${E.borderLit}`,
          borderRadius: 14,
          padding: 16,
          boxShadow: '0 0 32px rgba(249,168,37,.1)',
        }
      : {
          marginBottom: 20,
          paddingBottom: 16,
          borderBottom: `1px solid ${E.border}`,
        };

  const body = focus ? (
    <>
      <p style={{ margin: 0, fontSize: 11, letterSpacing: '0.2em', textTransform: 'uppercase', color: E.accent }}>
        {GATE_COPY.title}
      </p>
      <h3 style={{ margin: '8px 0 0', fontSize: 18, fontWeight: 400, color: E.text }}>Admit as Known</h3>
      <p style={{ margin: '8px 0 0', fontSize: 12, color: E.dim, lineHeight: 1.5 }}>
        {TRUST_RECIPE_COPY.verifyWhy} Verify is private. Trust is still mutual, later.
      </p>

      <label style={{ display: 'block', marginTop: 14, fontSize: 12, color: E.muted }}>Name</label>
      <input value={name} onChange={(e) => setName(e.target.value)} style={fieldStyle} />

      <p style={{ margin: '12px 0 0', fontSize: 11, letterSpacing: '0.12em', color: E.dim }}>FINGERPRINT</p>
      <code
        style={{
          display: 'block',
          marginTop: 4,
          fontSize: 12,
          color: E.accent,
          wordBreak: 'break-all',
          fontFamily: E.fontMono,
        }}
      >
        {formatFingerprintForVerify(focus.fingerprint)}
      </code>

      <p style={{ margin: '12px 0 0', fontSize: 11, letterSpacing: '0.12em', color: E.dim }}>
        {GATE_COPY.provenance}
      </p>
      <p style={{ margin: '4px 0 0', fontSize: 12, color: E.muted }}>
        {focus.mintChannel === 'in_person' ? GATE_COPY.inPerson : GATE_COPY.remote}
        {' · '}
        {focus.inviteNonce}
      </p>

      <label style={{ display: 'block', marginTop: 14, fontSize: 12, color: E.muted }}>{GATE_COPY.groupLabel}</label>
      <input
        value={tags}
        onChange={(e) => setTags(e.target.value)}
        placeholder="builders, core"
        style={fieldStyle}
      />

      <label style={{ display: 'block', marginTop: 14, fontSize: 12, color: E.muted }}>{GATE_COPY.notesLabel}</label>
      <textarea
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        rows={3}
        style={{ ...fieldStyle, resize: 'vertical' }}
      />

      <p style={{ margin: '14px 0 6px', fontSize: 12, color: E.muted }}>Verify this key? (optional)</p>
      {(
        [
          ['none', GATE_COPY.verifyNone],
          ['in_person', TRUST_RECIPE_COPY.verifyInPerson],
          ['other_channel', TRUST_RECIPE_COPY.verifyOtherChannel],
        ] as const
      ).map(([v, label]) => (
        <label
          key={v}
          style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 6, fontSize: 13, color: E.text }}
        >
          <input type="radio" name="gate-verify" checked={verify === v} onChange={() => setVerify(v)} />
          {label}
        </label>
      ))}

      {error && <p style={{ color: E.danger, fontSize: 13, marginTop: 12 }}>{error}</p>}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 16 }}>
        <button
          type="button"
          data-testid="grow-gate-admit-confirm"
          disabled={busy}
          onClick={() => void onAdmit()}
          style={btnStyle(true)}
        >
          {busy ? '…' : GATE_COPY.admit}
        </button>
        <button type="button" data-testid="grow-gate-dismiss" disabled={busy} onClick={() => void onDismiss()} style={btnStyle()}>
          {GATE_COPY.dismiss}
        </button>
        <button type="button" onClick={() => setFocus(null)} style={{ ...btnStyle(), border: 'none' }}>
          Back
        </button>
      </div>
    </>
  ) : (
    <>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 8 }}>
        <p style={{ margin: 0, fontSize: 11, letterSpacing: '0.2em', textTransform: 'uppercase', color: E.accent }}>
          {GATE_COPY.title}
          {arrivals.length > 0 ? ` · ${arrivals.length}` : ''}
        </p>
        {variant === 'overlay' && onClose ? (
          <button
            type="button"
            data-testid="galaxy-gate-overlay-close"
            onClick={onClose}
            style={{ ...btnStyle(), width: 'auto', padding: '4px 10px', border: 'none', color: E.dim }}
          >
            Close
          </button>
        ) : null}
      </div>
      {(variant === 'overlay' || arrivals.length > 3) && (
        <input
          data-testid="galaxy-gate-search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={GATE_COPY.search}
          aria-label={GATE_COPY.search}
          style={{ ...fieldStyle, marginTop: 10 }}
        />
      )}
      {arrivals.length === 0 ? (
        <p style={{ margin: '8px 0 0', fontSize: 12, color: E.dim, lineHeight: 1.5 }}>{GATE_COPY.empty}</p>
      ) : visible.length === 0 ? (
        <p style={{ margin: '8px 0 0', fontSize: 12, color: E.dim }}>No matches.</p>
      ) : (
        <ul style={{ listStyle: 'none', margin: '10px 0 0', padding: 0 }}>
          {visible.map((a) => (
            <li key={a.fingerprint} style={{ marginBottom: 8 }}>
              <button
                type="button"
                data-testid="grow-gate-arrival"
                onClick={() => openAdmit(a)}
                style={{
                  ...btnStyle(),
                  textAlign: 'left',
                }}
              >
                <span style={{ display: 'block', color: E.text }}>{a.displayName || 'Unknown'}</span>
                <span style={{ display: 'block', marginTop: 4, fontSize: 11, color: E.dim }}>
                  {a.mintChannel === 'in_person' ? GATE_COPY.inPerson : GATE_COPY.remote}
                  {' · '}
                  {a.inviteNonce}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </>
  );

  return (
    <div
      data-testid={variant === 'overlay' ? 'galaxy-gate-overlay' : 'grow-gate-list'}
      style={shellStyle}
      onPointerDown={
        variant === 'overlay'
          ? (e) => {
              e.stopPropagation();
            }
          : undefined
      }
      onWheel={
        variant === 'overlay'
          ? (e) => {
              e.stopPropagation();
            }
          : undefined
      }
    >
      {body}
    </div>
  );
}
