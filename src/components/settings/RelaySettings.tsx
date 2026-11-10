'use client';

/**
 * Settings → Relay. Shows where you are and what a relay can see.
 * The URL field, its health check and Switch are off the tab until moving is wired: see README.md here.
 */

import { useEffect, useState } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { RELAY_COPY } from './relay-copy';
import { currentRelayUrl } from './relay-preference';

export function RelaySettings() {
  const [current, setCurrent] = useState(currentRelayUrl);

  useEffect(() => {
    setCurrent(currentRelayUrl());
  }, []);

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

      <p
        data-testid="relay-helper"
        style={{ margin: '10px 0 14px', fontSize: 12, lineHeight: 1.45, color: E.muted }}
      >
        {RELAY_COPY.helper}
      </p>

      <p
        data-testid="relay-unavailable"
        style={{ margin: 0, fontSize: 12, lineHeight: 1.45, color: E.dim }}
      >
        {RELAY_COPY.unavailable}
      </p>
    </section>
  );
}
