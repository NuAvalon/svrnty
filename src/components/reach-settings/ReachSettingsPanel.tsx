'use client';

import { solarEmber as E } from '@/components/recovery/solar-ember';
import {
  REACH_LEVEL_OPTIONS,
  type ReachLevel,
  type ReachPrefs,
  reachStatusLine,
} from './reach-prefs';

type Props = {
  prefs: ReachPrefs;
  onChange: (next: ReachPrefs) => void;
  /** When true, show that fleet gate commit is still stub-not-live. */
  gateStub?: boolean;
};

/**
 * Global disclosure-reach chrome — awaken the circle + default private/L1/L2.
 * Does not call `visible()`; Apollo enforces. Per-bond overrides live on the
 * contact sheet (`BondReachControl`).
 */
export function ReachSettingsPanel({ prefs, onChange, gateStub = true }: Props) {
  return (
    <section
      data-testid="reach-settings"
      aria-label="Disclosure reach"
      style={{
        marginTop: 12,
        padding: '16px 18px',
        background: E.surface,
        border: `1px solid ${E.border}`,
        borderRadius: 12,
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)',
        textAlign: 'left' as const,
      }}
    >
      <h3
        style={{
          margin: '0 0 4px',
          fontFamily: E.fontSans,
          fontSize: 13,
          fontWeight: 600,
          letterSpacing: '0.08em',
          textTransform: 'uppercase' as const,
          color: E.accent,
        }}
      >
        Disclosure reach
      </h3>
      <p
        style={{
          margin: '0 0 14px',
          fontFamily: E.fontSans,
          fontSize: 12,
          lineHeight: 1.45,
          color: E.muted,
        }}
      >
        Choose how far your consented bonds may be disclosed. Every visible line
        is consented — none inferred. Awakening never invents a connection.
      </p>

      <label
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: 10,
          cursor: 'pointer',
          marginBottom: 14,
        }}
      >
        <input
          data-testid="reach-awaken-toggle"
          type="checkbox"
          checked={prefs.awakenCircle}
          onChange={(e) => onChange({ ...prefs, awakenCircle: e.target.checked })}
          style={{ marginTop: 2, accentColor: E.accent }}
        />
        <span style={{ fontFamily: E.fontSans, fontSize: 13, color: E.text, lineHeight: 1.4 }}>
          Awaken the circle
          <span style={{ display: 'block', fontSize: 11, color: E.dim, marginTop: 2 }}>
            Global opt-in. When off, bonds stay private. When on, default reach
            applies — a tighter per-bond setting still wins.
          </span>
        </span>
      </label>

      <label
        style={{
          display: 'block',
          fontFamily: E.fontSans,
          fontSize: 11,
          letterSpacing: '0.06em',
          textTransform: 'uppercase' as const,
          color: E.dim,
          marginBottom: 6,
        }}
      >
        Default bond reach
      </label>
      <div
        role="radiogroup"
        aria-label="Default bond reach"
        data-testid="reach-default-group"
        style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 12 }}
      >
        {REACH_LEVEL_OPTIONS.map((o) => {
          const selected = prefs.defaultReach === o.value;
          return (
            <label
              key={o.value}
              data-testid={`reach-default-${o.value}`}
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: 10,
                cursor: prefs.awakenCircle ? 'pointer' : 'not-allowed',
                opacity: prefs.awakenCircle ? 1 : 0.55,
                padding: '10px 12px',
                borderRadius: 8,
                border: `1px solid ${selected ? E.borderLit : E.border}`,
                background: selected
                  ? 'color-mix(in srgb, var(--se-accent) 10%, transparent)'
                  : 'transparent',
              }}
            >
              <input
                type="radio"
                name="reach-default"
                value={o.value}
                checked={selected}
                disabled={!prefs.awakenCircle}
                onChange={() =>
                  onChange({
                    ...prefs,
                    defaultReach: o.value as ReachLevel,
                  })
                }
                style={{ marginTop: 3, accentColor: E.accent }}
              />
              <span style={{ fontFamily: E.fontSans, fontSize: 13, color: E.text, lineHeight: 1.4 }}>
                {o.label}
                <span style={{ display: 'block', fontSize: 11, color: E.dim, marginTop: 2 }}>
                  {o.hint}
                </span>
              </span>
            </label>
          );
        })}
      </div>

      <p
        style={{
          margin: 0,
          fontFamily: E.fontSans,
          fontSize: 11,
          color: E.dim,
          lineHeight: 1.4,
        }}
      >
        {reachStatusLine(prefs)}
        {gateStub ? (
          <span style={{ display: 'block', marginTop: 6, color: E.muted }}>
            Disclosure enforcement is not live yet — preferences are saved as
            consent intent on this device until the fleet gate is wired.
          </span>
        ) : null}
      </p>
    </section>
  );
}
