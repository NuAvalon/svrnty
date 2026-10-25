'use client';

/**
 * Settings › Compose key. The ONLY place a pin / re-pin / replace screen can open (Flint P1): an arriving request never does. Pure decisions live in
 * src/lib/compose/compose-pin.ts (settingsView, startCeremony, applyPinChoice); this file reads the stored pin, draws what they return, and writes a pin
 * only from the non-null `write` that applyPinChoice returns for a confirmed "They match" press (K3: no auto-pin, nothing else ever writes one).
 *
 * The panel renders nothing while the session is locked. Words are PIN_COPY verbatim (Hypatia §7); the section title "Compose key" is taken from the
 * notices' own wording ("Settings › Compose key") and is flagged in the PR.
 */

import { useCallback, useEffect, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { solarEmber as E, solarGlass } from '@/components/recovery/solar-ember';
import { getComposePinState, setComposePin } from '@/lib/identity/client-store';
import { normalizeFingerprintHex } from '@/lib/identity/fingerprint';
import {
  applyPinChoice,
  fp16Groups,
  settingsView,
  startCeremony,
  type PinAction,
  type PinNotice,
  type PinScreen,
  type PinState,
} from '@/lib/compose/compose-pin';
import { PIN_COPY, PIN_DEFAULT_FOCUS } from '@/lib/compose/compose-pin-copy';
import { useActiveComposeController, useComposeSnapshot } from './compose-registry';

const ACTION_LABEL: Record<PinAction, string> = {
  pin: PIN_COPY.actionPin,
  're-pin': PIN_COPY.actionRePin,
  'compare-new': PIN_COPY.actionCompareNew,
  'keep-blocked': PIN_COPY.actionKeepBlocked,
};

const button = (primary: boolean): React.CSSProperties => ({
  flex: 1,
  minHeight: 44,
  background: primary ? 'color-mix(in srgb, var(--se-accent) 14%, transparent)' : 'transparent',
  border: `1px solid ${primary ? E.borderLit : E.border}`,
  borderRadius: 8,
  color: primary ? E.accent : E.muted,
  cursor: 'pointer',
  fontFamily: E.fontSans,
  fontWeight: 600,
});

function screenCopy(s: PinScreen): { title: string; body: string; match: string } {
  switch (s.screen) {
    case 'first-pin':
      return { title: PIN_COPY.firstTitle, body: PIN_COPY.firstBody, match: PIN_COPY.match };
    case 're-pin':
      return { title: PIN_COPY.rePinTitle, body: PIN_COPY.rePinBody, match: PIN_COPY.match };
    case 'replace':
      return { title: PIN_COPY.replaceTitle, body: PIN_COPY.replaceBody, match: PIN_COPY.replaceMatch };
  }
}

export function ComposePinSettings({ identity }: { identity: unknown }) {
  const titleId = useId();
  const controller = useActiveComposeController();
  const snap = useComposeSnapshot();
  const [fp, setFp] = useState('');
  const [pin, setPin] = useState<PinState>({ state: 'locked' });
  const [screen, setScreen] = useState<PinScreen | null>(null);
  const [result, setResult] = useState<PinNotice | null>(null);
  const noMatchRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const root = identity && typeof identity === 'object' ? (identity as { identity?: { fingerprint?: unknown } }) : {};
    const raw = root.identity?.fingerprint;
    setFp(typeof raw === 'string' ? normalizeFingerprintHex(raw) : '');
  }, [identity]);

  const refresh = useCallback(async () => {
    if (!fp) {
      setPin({ state: 'locked' });
      return;
    }
    setPin(await getComposePinState(fp));
  }, [fp]);

  // Re-read the stored pin on mount and whenever a candidate arrives or goes (an arrival can turn "Not pinned" into "a key arrived").
  const candidateKey = snap?.candidates.join(',') ?? '';
  useEffect(() => {
    void refresh();
  }, [refresh, candidateKey]);

  useEffect(() => {
    if (screen) noMatchRef.current?.focus(); // the SAFE choice (PIN_DEFAULT_FOCUS), never "They match"
  }, [screen]);

  const view = settingsView(pin, snap?.candidates ?? []);
  if (!fp || view.status === 'locked') return null;

  const act = (action: PinAction) => {
    setResult(null);
    if (action === 'keep-blocked') {
      if (view.candidate) controller?.forgetCandidate(view.candidate);
      return;
    }
    if (!view.candidate) return;
    setScreen(startCeremony(pin, action, view.candidate));
  };

  const choose = async (choice: 'match' | 'no-match') => {
    if (!screen) return;
    // Judge the choice against the pin AS STORED RIGHT NOW, not the copy this panel rendered with (a stale screen can never write).
    const current = await getComposePinState(fp);
    const out = applyPinChoice(current, screen, choice, new Date().toISOString());
    let notice: PinNotice | null = out.notice;
    if (out.write) {
      try {
        await setComposePin(fp, out.write);
        controller?.forgetCandidate(screen.candidate);
      } catch {
        notice = 'mismatch'; // could not store it: say "Not pinned", never "Pinned"
      }
    }
    setScreen(out.next);
    setResult(notice);
    await refresh();
  };

  const copy = screen ? screenCopy(screen) : null;

  return (
    <section
      data-testid="compose-pin-settings"
      aria-labelledby={titleId}
      style={{ marginTop: 16, padding: '16px 18px', background: E.surface, border: `1px solid ${E.border}`, borderRadius: 12, backdropFilter: 'blur(16px)', WebkitBackdropFilter: 'blur(16px)', maxWidth: 420, marginLeft: 'auto', marginRight: 'auto', textAlign: 'left', fontFamily: E.fontSans }}
    >
      <h3 id={titleId} style={{ margin: '0 0 4px', fontSize: 13, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: E.accent }}>Compose key</h3>
      <p data-testid="compose-pin-line" data-status={view.status} style={{ margin: '0 0 12px', fontSize: 13, color: E.text, wordBreak: 'break-all' }}>{view.line}</p>
      {view.actions.length > 0 ? (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {view.actions.map((a) => (
            <button
              key={a}
              type="button"
              data-testid={`compose-pin-action-${a}`}
              data-default-focus={a === 'keep-blocked' ? 'true' : undefined}
              onClick={() => act(a)}
              style={button(a !== 'keep-blocked')}
            >
              {ACTION_LABEL[a]}
            </button>
          ))}
        </div>
      ) : null}
      {result ? (
        <p data-testid="compose-pin-result" data-kind={result} role="status" style={{ margin: '10px 0 0', fontSize: 12, lineHeight: 1.45, color: result === 'pinned' || result === 'replaced' ? E.ok : E.muted }}>
          {PIN_COPY[result]}
        </p>
      ) : null}

      {screen && copy
        ? createPortal(
            <div role="presentation" data-testid="compose-pin-overlay" style={{ position: 'fixed', inset: 0, zIndex: 80, background: 'rgba(8, 5, 3, 0.72)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16, overflowY: 'auto' }}>
              <div
                role="dialog"
                aria-modal="true"
                aria-labelledby="compose-pin-screen-title"
                data-testid="compose-pin-screen"
                data-screen={screen.screen}
                onKeyDown={(e) => {
                  if (e.key === 'Escape') void choose('no-match');
                }}
                style={{ ...solarGlass, width: '100%', maxWidth: 420, padding: '22px 22px 18px', color: E.text, fontFamily: E.fontSans }}
              >
                <h2 id="compose-pin-screen-title" style={{ margin: '0 0 8px', fontSize: 16, color: E.text }}>{copy.title}</h2>
                <p style={{ margin: '0 0 12px', fontSize: 13, lineHeight: 1.45, color: E.muted }}>{copy.body}</p>
                {screen.screen === 'replace' ? (
                  <p data-testid="compose-pin-old" style={{ margin: '0 0 6px', fontSize: 13, color: E.muted, fontFamily: E.fontMono }}>
                    {PIN_COPY.oldLabel}
                    {fp16Groups(screen.pinned)}
                  </p>
                ) : null}
                <p data-testid="compose-pin-fp" style={{ margin: '0 0 16px', fontSize: 20, letterSpacing: '0.06em', color: E.text, fontFamily: E.fontMono }}>{fp16Groups(screen.candidate)}</p>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button ref={noMatchRef} type="button" data-testid="compose-pin-nomatch" data-default-focus={PIN_DEFAULT_FOCUS[screen.screen] === 'noMatch' ? 'true' : undefined} onClick={() => void choose('no-match')} style={button(false)}>{PIN_COPY.noMatch}</button>
                  <button type="button" data-testid="compose-pin-match" onClick={() => void choose('match')} style={button(true)}>{copy.match}</button>
                </div>
              </div>
            </div>,
            document.body,
          )
        : null}
    </section>
  );
}
