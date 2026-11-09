'use client';

/**
 * Settings → Delivery. Glass only: the rules (what a send may do) are delivery-receipt-setting.ts; what this panel may write is delivery-actions.ts.
 * Three states: the owner has a choice (On/Off, plus a one-time notice after an upgrade), the owner is asked once (a restore: nothing goes out
 * until they answer), or the record can't be read (no switch is offered: a write would be a guess).
 */

import { useCallback, useEffect, useState } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { readDeliveryDefaultMigrating, writeDeliveryDefault } from '@/lib/identity/client-store';
import { DELIVERY_COPY } from './delivery-copy';
import { chooseDelivery, dismissDeliveryNotice, loadDeliveryPanel, type DeliveryIO, type DeliveryPanel } from './delivery-actions';
import type { DeliveryValue } from '@/lib/trust/delivery-receipt-setting';

const IO: DeliveryIO = {
  read: readDeliveryDefaultMigrating,
  write: (owner, rec) => writeDeliveryDefault(owner, rec),
};

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

export function DeliverySettings({ ownerFingerprint }: { ownerFingerprint: string }) {
  const [panel, setPanel] = useState<DeliveryPanel | null>(null);
  const [failed, setFailed] = useState(false);

  const run = useCallback(async (f: () => Promise<DeliveryPanel>) => {
    try {
      setFailed(false);
      setPanel(await f());
    } catch {
      setFailed(true); // a write that threw changed nothing we can vouch for: re-read so the glass shows what is stored
      void loadDeliveryPanel(IO, ownerFingerprint).then(setPanel).catch(() => setPanel({ kind: 'unreadable' }));
    }
  }, [ownerFingerprint]);

  useEffect(() => {
    void run(() => loadDeliveryPanel(IO, ownerFingerprint));
  }, [run, ownerFingerprint]);

  if (!panel) return null;
  const choose = (v: DeliveryValue) => void run(() => chooseDelivery(IO, ownerFingerprint, v));

  return (
    <section
      data-testid="delivery-settings"
      data-state={panel.kind === 'choice' ? panel.value : panel.kind}
      aria-label={DELIVERY_COPY.title}
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
        color: E.text,
        fontFamily: E.fontSans,
      }}
    >
      <h3 style={{ margin: '0 0 4px', fontSize: 13, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: E.accent }}>
        {DELIVERY_COPY.title}
      </h3>

      {panel.kind === 'unreadable' ? (
        <p data-testid="delivery-unreadable" style={{ margin: '8px 0 0', fontSize: 13, lineHeight: 1.45, color: E.muted }}>
          {DELIVERY_COPY.unreadable}
        </p>
      ) : panel.kind === 'ask' ? (
        <div data-testid="delivery-restore-ask">
          <p style={{ margin: '8px 0 14px', fontSize: 13, lineHeight: 1.45, color: E.text }}>{DELIVERY_COPY.restoreAsk}</p>
          <div style={{ display: 'flex', gap: 8 }}>
            <button type="button" data-testid="delivery-restore-yes" onClick={() => choose('on')} style={btn(false)}>
              {DELIVERY_COPY.restoreYes}
            </button>
            <button type="button" data-testid="delivery-restore-no" onClick={() => choose('off')} style={btn(false)}>
              {DELIVERY_COPY.restoreNo}
            </button>
          </div>
        </div>
      ) : (
        <>
          {panel.notice ? (
            <div
              data-testid="delivery-upgrade-notice"
              role="status"
              style={{ margin: '8px 0 12px', padding: '10px 12px', border: `1px solid ${E.borderLit}`, borderRadius: 8 }}
            >
              <p style={{ margin: '0 0 10px', fontSize: 13, lineHeight: 1.45, color: E.text }}>{DELIVERY_COPY.upgradeNotice}</p>
              <button
                type="button"
                data-testid="delivery-notice-dismiss"
                onClick={() => void run(() => dismissDeliveryNotice(IO, ownerFingerprint))}
                style={{ ...btn(false), flex: 'none', padding: '0 16px' }}
              >
                {DELIVERY_COPY.upgradeNoticeDismiss}
              </button>
            </div>
          ) : null}
          <p data-testid="delivery-line" style={{ margin: '8px 0 12px', fontSize: 13, lineHeight: 1.45, color: E.muted }}>
            {DELIVERY_COPY.globalLine}
          </p>
          <div role="group" aria-label={DELIVERY_COPY.title} style={{ display: 'flex', gap: 8 }}>
            <button type="button" data-testid="delivery-on" aria-pressed={panel.value === 'on'} onClick={() => choose('on')} style={btn(panel.value === 'on')}>
              {DELIVERY_COPY.on}
            </button>
            <button type="button" data-testid="delivery-off" aria-pressed={panel.value === 'off'} onClick={() => choose('off')} style={btn(panel.value === 'off')}>
              {DELIVERY_COPY.off}
            </button>
          </div>
        </>
      )}
      {failed ? (
        <p data-testid="delivery-write-failed" role="alert" style={{ margin: '10px 0 0', fontSize: 12, color: E.danger }}>
          {DELIVERY_COPY.writeFailed}
        </p>
      ) : null}
    </section>
  );
}
