'use client';

/**
 * "Show up in trust maps": the owner's own choice, any time (including after a restore). Glass only: what it may write is setOwnerGlobalVisibleForOwner, which changes ONLY the global flag (the
 * people the owner blocked or listed stay suppressed either way) and refuses a record that is absent or unreadable. It lives inside the Lenses & vault panel and nowhere else: the Identity face, the
 * share dialog, the Galaxy and the ceremony are shown to other people, and "You're set to stay out of other people's trust maps" must not be readable there.
 * Three states: the stored choice (a switch; turning "show up" on asks first, turning it off does not), or unreadable (no switch: a write would be a guess). The not-live line shows in all of them
 * while isPiece2MutualBlockLive() is false (one source, so the screen cannot say "not live" while the emitter runs, or the reverse).
 */

import { useCallback, useEffect, useState } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { readOwnerGlobalVisibility, setOwnerGlobalVisibleForOwner } from '@/lib/identity/client-store';
import { isPiece2MutualBlockLive } from '@/lib/claim-gates';
import {
  TRUST_MAP_CONFIRM,
  TRUST_MAP_CONFIRM_NO,
  TRUST_MAP_CONFIRM_YES,
  TRUST_MAP_LABEL,
  TRUST_MAP_NOT_LIVE,
  TRUST_MAP_STATE_OFF,
  TRUST_MAP_STATE_ON,
  TRUST_MAP_UNREADABLE,
  TRUST_MAP_WRITE_FAILED,
} from './trust-map-copy';

type Stored = 'visible' | 'hidden' | 'unreadable';

const btn = (active: boolean): React.CSSProperties => ({
  flex: 1,
  minHeight: 40,
  background: active ? 'color-mix(in srgb, var(--se-accent) 14%, transparent)' : 'transparent',
  border: `1px solid ${active ? E.borderLit : E.border}`,
  borderRadius: 8,
  color: active ? E.accent : E.muted,
  cursor: 'pointer',
  fontFamily: E.fontSans,
  fontWeight: active ? 600 : 400,
});

export function TrustMapSettings({ ownerFingerprint }: { ownerFingerprint: string }) {
  const [stored, setStored] = useState<Stored | null>(null);
  const [asking, setAsking] = useState(false);
  const [failed, setFailed] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setStored(await readOwnerGlobalVisibility(ownerFingerprint));
    } catch {
      setStored('unreadable');
    }
  }, [ownerFingerprint]);

  useEffect(() => {
    void load();
  }, [load]);

  const choose = useCallback(async (visible: boolean) => {
    setBusy(true);
    setAsking(false);
    try {
      setFailed((await setOwnerGlobalVisibleForOwner(ownerFingerprint, visible)) !== 'set');
    } catch {
      setFailed(true); // a write that threw changed nothing we can vouch for: the glass below shows what is stored, read again
    } finally {
      await load();
      setBusy(false);
    }
  }, [ownerFingerprint, load]);

  if (stored === null) return null;
  const visible = stored === 'visible';

  return (
    <section
      data-testid="trust-map-settings"
      data-state={stored}
      aria-label={TRUST_MAP_LABEL}
      style={{ marginTop: 14, paddingTop: 14, borderTop: `1px solid ${E.border}`, color: E.text, fontFamily: E.fontSans }}
    >
      <h3 style={{ margin: '0 0 6px', fontSize: 13, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: E.accent }}>{TRUST_MAP_LABEL}</h3>

      {stored === 'unreadable' ? (
        <p data-testid="trust-map-unreadable" style={{ margin: '8px 0', fontSize: 13, lineHeight: 1.45, color: E.muted }}>{TRUST_MAP_UNREADABLE}</p>
      ) : (
        <>
          <p data-testid="trust-map-state" style={{ margin: '8px 0 10px', fontSize: 13, lineHeight: 1.45, color: E.text }}>{visible ? TRUST_MAP_STATE_ON : TRUST_MAP_STATE_OFF}</p>
          <button
            type="button"
            role="switch"
            aria-checked={visible}
            aria-label={TRUST_MAP_LABEL}
            data-testid="trust-map-switch"
            disabled={busy}
            onClick={() => (visible ? void choose(false) : setAsking(true))}
            style={{ ...btn(visible), flex: 'none', width: '100%' }}
          >
            {TRUST_MAP_LABEL}
          </button>
          {asking ? (
            <div data-testid="trust-map-confirm" role="group" style={{ marginTop: 10, padding: '10px 12px', border: `1px solid ${E.borderLit}`, borderRadius: 8 }}>
              <p style={{ margin: '0 0 10px', fontSize: 13, lineHeight: 1.45, color: E.text }}>{TRUST_MAP_CONFIRM}</p>
              <div style={{ display: 'flex', gap: 8 }}>
                <button type="button" data-testid="trust-map-confirm-yes" disabled={busy} onClick={() => void choose(true)} style={btn(false)}>{TRUST_MAP_CONFIRM_YES}</button>
                <button type="button" data-testid="trust-map-confirm-no" disabled={busy} onClick={() => setAsking(false)} style={btn(false)}>{TRUST_MAP_CONFIRM_NO}</button>
              </div>
            </div>
          ) : null}
        </>
      )}

      {!isPiece2MutualBlockLive() ? (
        <p data-testid="trust-map-not-live" style={{ margin: '10px 0 0', fontSize: 12, lineHeight: 1.45, color: E.muted }}>{TRUST_MAP_NOT_LIVE}</p>
      ) : null}
      {failed ? (
        <p data-testid="trust-map-write-failed" role="alert" style={{ margin: '10px 0 0', fontSize: 12, color: E.danger }}>{TRUST_MAP_WRITE_FAILED}</p>
      ) : null}
    </section>
  );
}
