'use client';

import { solarEmber as E } from '@/components/recovery/solar-ember';
import {
  REACH_LEVEL_OPTIONS,
  effectiveBondReach,
  reachLevelLabel,
  type ReachLevel,
  type ReachPrefs,
} from './reach-prefs';

type Props = {
  prefs: ReachPrefs;
  peerFingerprint: string;
  peerName?: string;
  /** Current stored override, or inherit. */
  onChange: (level: ReachLevel | 'inherit') => void;
};

/**
 * Per-bond reach override on the contact sheet.
 * Narrow-only vs default — glass refuses wider values in prefs helpers.
 */
export function BondReachControl({
  prefs,
  peerFingerprint,
  peerName,
  onChange,
}: Props) {
  const key = peerFingerprint.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  const hasOverride = !!(key && prefs.edgeReach[key]);
  const effective = effectiveBondReach(prefs, peerFingerprint);
  const selectValue: ReachLevel | 'inherit' = hasOverride
    ? prefs.edgeReach[key]
    : 'inherit';

  return (
    <div
      data-testid="bond-reach-control"
      style={{
        marginTop: 12,
        paddingTop: 12,
        borderTop: `1px solid ${E.border}`,
      }}
    >
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
        Bond reach{peerName ? ` · ${peerName}` : ''}
      </label>
      <select
        data-testid="bond-reach-select"
        value={selectValue}
        disabled={!prefs.awakenCircle}
        onChange={(e) => {
          const v = e.target.value as ReachLevel | 'inherit';
          onChange(v);
        }}
        style={{
          width: '100%',
          background: E.inputBg,
          border: `1px solid ${E.border}`,
          borderRadius: 8,
          padding: '10px 12px',
          color: E.text,
          fontFamily: E.fontSans,
          fontSize: 13,
          outline: 'none',
          opacity: prefs.awakenCircle ? 1 : 0.55,
          cursor: prefs.awakenCircle ? 'pointer' : 'not-allowed',
        }}
      >
        <option value="inherit">
          Inherit default ({reachLevelLabel(prefs.defaultReach)})
        </option>
        {REACH_LEVEL_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label} — {o.short}
          </option>
        ))}
      </select>
      <p
        style={{
          margin: '8px 0 0',
          fontFamily: E.fontSans,
          fontSize: 11,
          color: E.dim,
          lineHeight: 1.4,
        }}
      >
        {prefs.awakenCircle
          ? `Effective for this bond: ${reachLevelLabel(effective)}. A tighter setting than your default is kept; a wider one is narrowed.`
          : 'Circle is asleep — this bond stays private. Awaken the circle in reach settings to disclose.'}
      </p>
    </div>
  );
}
