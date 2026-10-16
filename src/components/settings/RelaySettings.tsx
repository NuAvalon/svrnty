'use client';

/**
 * Settings → Relay. Glass only: show current, validate /health, confirm, progress, result.
 * Switch calls `switchToRelay` — Apollo registers migrateRelay behind that seam.
 */

import { useEffect, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { solarEmber as E, solarGlass } from '@/components/recovery/solar-ember';
import { RELAY_COPY } from './relay-copy';
import { currentRelayUrl, writeChosenRelayUrl } from './relay-preference';
import { validateRelayHealth, type RelayHealth } from './relay-health';
import { RelayMigrateUnwiredError, switchToRelay } from './relay-migrate-seam';

type Phase = 'idle' | 'confirm' | 'switching' | 'result';

export function RelaySettings() {
  const fieldId = useId();
  const [current, setCurrent] = useState(currentRelayUrl);
  const [draft, setDraft] = useState('');
  const [health, setHealth] = useState<RelayHealth | null>(null);
  const [checking, setChecking] = useState(false);
  const [phase, setPhase] = useState<Phase>('idle');
  const [result, setResult] = useState<string | null>(null);
  const [resultKind, setResultKind] = useState<'ok' | 'incomplete' | 'unwired' | null>(null);
  const seq = useRef(0);

  useEffect(() => {
    setCurrent(currentRelayUrl());
  }, []);

  useEffect(() => {
    const raw = draft.trim();
    if (!raw) {
      setHealth(null);
      setChecking(false);
      return;
    }
    const n = ++seq.current;
    setChecking(true);
    const t = setTimeout(() => {
      void validateRelayHealth(raw).then((next) => {
        if (seq.current !== n) return;
        setHealth(next);
        setChecking(false);
      });
    }, 280);
    return () => clearTimeout(t);
  }, [draft]);

  const valid = health?.ok === true;
  const switchEnabled = valid && phase !== 'switching';

  const runSwitch = async () => {
    if (!health || !health.ok) return;
    setPhase('switching');
    setResult(null);
    setResultKind(null);
    try {
      const out = await switchToRelay(health.url);
      if (out.complete) {
        writeChosenRelayUrl(health.url);
        setCurrent(health.url);
        setResult(RELAY_COPY.nowOn(health.url));
        setResultKind('ok');
      } else {
        setResult(RELAY_COPY.incomplete(out.failedFps.length));
        setResultKind('incomplete');
      }
    } catch (err) {
      if (err instanceof RelayMigrateUnwiredError) {
        setResult(RELAY_COPY.unwired);
        setResultKind('unwired');
      } else {
        setResult(RELAY_COPY.invalid.reach);
        setResultKind('incomplete');
      }
    } finally {
      setPhase('result');
    }
  };

  return (
    <section
      data-testid="relay-settings"
      aria-label={RELAY_COPY.title}
      style={{
        marginTop: 16,
        padding: '16px 18px',
        background: E.surface,
        border: `1px solid ${E.border}`,
        borderRadius: 12,
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)',
        maxWidth: 420,
        marginLeft: 'auto',
        marginRight: 'auto',
        textAlign: 'left',
        fontFamily: E.fontSans,
      }}
    >
      <h3
        style={{
          margin: '0 0 4px',
          fontSize: 13,
          fontWeight: 600,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          color: E.accent,
        }}
      >
        {RELAY_COPY.title}
      </h3>
      <p
        data-testid="relay-current"
        style={{ margin: '0 0 14px', fontSize: 13, color: E.text, wordBreak: 'break-all' }}
      >
        {RELAY_COPY.currentPrefix} {current}
      </p>

      <label
        htmlFor={fieldId}
        style={{
          display: 'block',
          fontSize: 11,
          letterSpacing: '0.06em',
          textTransform: 'uppercase',
          color: E.dim,
          marginBottom: 6,
        }}
      >
        {RELAY_COPY.fieldLabel}
      </label>
      <input
        id={fieldId}
        data-testid="relay-url-input"
        type="url"
        inputMode="url"
        autoComplete="off"
        spellCheck={false}
        placeholder={RELAY_COPY.placeholder}
        value={draft}
        onChange={(e) => {
          setDraft(e.target.value);
          if (phase === 'result') {
            setPhase('idle');
            setResult(null);
            setResultKind(null);
          }
        }}
        style={{
          width: '100%',
          boxSizing: 'border-box',
          background: E.inputBg,
          border: `1px solid ${valid ? E.borderLit : E.border}`,
          borderRadius: 8,
          padding: '10px 12px',
          color: E.text,
          fontFamily: E.fontMono,
          fontSize: 13,
          outline: 'none',
        }}
      />

      <p
        data-testid="relay-health"
        data-valid={valid ? '1' : '0'}
        style={{
          margin: '8px 0 0',
          fontSize: 12,
          color: valid ? E.ok : health ? E.danger : E.dim,
          minHeight: 18,
        }}
      >
        {checking
          ? 'Checking…'
          : health?.ok
            ? `✓ ${RELAY_COPY.valid}`
            : health
              ? `✗ ${health.reason}`
              : ''}
      </p>

      <p
        data-testid="relay-helper"
        style={{ margin: '10px 0 14px', fontSize: 12, lineHeight: 1.45, color: E.muted }}
      >
        {RELAY_COPY.helper}
      </p>

      <button
        type="button"
        data-testid="relay-switch"
        disabled={!switchEnabled}
        onClick={() => setPhase('confirm')}
        style={{
          width: '100%',
          minHeight: 40,
          background: switchEnabled ? 'rgba(249, 168, 37, 0.08)' : 'transparent',
          border: `1px solid ${switchEnabled ? E.borderLit : E.border}`,
          borderRadius: 8,
          padding: '10px 14px',
          color: switchEnabled ? E.accent : E.dim,
          fontFamily: E.fontSans,
          fontSize: 12,
          fontWeight: 600,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          cursor: switchEnabled ? 'pointer' : 'default',
          opacity: switchEnabled ? 1 : 0.55,
        }}
      >
        {phase === 'switching' ? RELAY_COPY.switching : RELAY_COPY.switch}
      </button>

      {phase === 'switching' ? (
        <p
          data-testid="relay-progress"
          role="status"
          style={{ margin: '10px 0 0', fontSize: 12, color: E.muted }}
        >
          {RELAY_COPY.switching}
        </p>
      ) : null}

      {result ? (
        <p
          data-testid="relay-result"
          data-kind={resultKind || ''}
          role="status"
          style={{
            margin: '10px 0 0',
            fontSize: 12,
            lineHeight: 1.45,
            color: resultKind === 'ok' ? E.ok : resultKind === 'unwired' ? E.muted : E.accent,
          }}
        >
          {result}
        </p>
      ) : null}

      {phase === 'confirm'
        ? createPortal(
            <div
              role="presentation"
              data-testid="relay-confirm-overlay"
              onClick={() => setPhase('idle')}
              style={{
                position: 'fixed',
                inset: 0,
                zIndex: 80,
                pointerEvents: 'auto',
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
                aria-labelledby="relay-confirm-title"
                data-testid="relay-confirm"
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
                  id="relay-confirm-title"
                  style={{ margin: '0 0 8px', fontSize: 16, color: E.text }}
                >
                  {RELAY_COPY.confirmTitle}
                </h2>
                <p style={{ margin: '0 0 16px', fontSize: 13, lineHeight: 1.45, color: E.muted }}>
                  {RELAY_COPY.confirmBody}
                  {health?.ok ? (
                    <span style={{ display: 'block', marginTop: 8, color: E.text, wordBreak: 'break-all' }}>
                      {health.url}
                    </span>
                  ) : null}
                </p>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button
                    type="button"
                    data-testid="relay-confirm-cancel"
                    onClick={() => setPhase('idle')}
                    style={{
                      flex: 1,
                      minHeight: 40,
                      background: 'transparent',
                      border: `1px solid ${E.border}`,
                      borderRadius: 8,
                      color: E.muted,
                      cursor: 'pointer',
                      fontFamily: E.fontSans,
                    }}
                  >
                    {RELAY_COPY.cancel}
                  </button>
                  <button
                    type="button"
                    data-testid="relay-confirm-go"
                    onClick={() => void runSwitch()}
                    style={{
                      flex: 1,
                      minHeight: 40,
                      background: 'color-mix(in srgb, var(--se-accent) 14%, transparent)',
                      border: `1px solid ${E.borderLit}`,
                      borderRadius: 8,
                      color: E.accent,
                      cursor: 'pointer',
                      fontFamily: E.fontSans,
                      fontWeight: 600,
                    }}
                  >
                    {RELAY_COPY.confirm}
                  </button>
                </div>
              </div>
            </div>,
            document.body,
          )
        : null}
    </section>
  );
}
