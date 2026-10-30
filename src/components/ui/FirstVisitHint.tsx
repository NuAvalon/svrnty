'use client';

import { useEffect, useState, type ReactNode } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { hintHasBeenSeen, markHintSeen } from './first-visit-hint';

/**
 * Clickable helper. Open the first time you land; later it is just the chip.
 * Closing (or leaving the page while open) remembers that you have been here.
 */
export function FirstVisitHint({
  id,
  label,
  children,
  testId,
}: {
  id: string;
  label: string;
  children: ReactNode;
  testId?: string;
}) {
  const [open, setOpen] = useState(() => !hintHasBeenSeen(id));

  useEffect(() => {
    if (!open) return;
    const mark = () => markHintSeen(id);
    window.addEventListener('pagehide', mark);
    return () => window.removeEventListener('pagehide', mark);
  }, [id, open]);

  const toggle = () => {
    setOpen((prev) => {
      const next = !prev;
      if (!next) markHintSeen(id);
      return next;
    });
  };

  return (
    <div
      data-testid={testId ?? `hint-${id}`}
      data-hint-id={id}
      data-open={open ? '1' : '0'}
    >
      <button
        type="button"
        data-testid={`hint-toggle-${id}`}
        aria-expanded={open}
        onClick={toggle}
        style={{
          display: 'inline',
          margin: 0,
          padding: 0,
          border: 'none',
          background: 'transparent',
          color: E.muted,
          fontFamily: E.fontSans,
          fontSize: 11,
          letterSpacing: '0.02em',
          lineHeight: 1.4,
          textAlign: 'left',
          cursor: 'pointer',
          textDecoration: open ? 'none' : 'underline',
          textUnderlineOffset: 3,
          textDecorationColor: 'color-mix(in srgb, var(--se-accent) 35%, transparent)',
        }}
      >
        {label}
      </button>
      {open ? (
        <div
          data-testid={`hint-body-${id}`}
          style={{
            margin: '6px 0 0',
            fontFamily: E.fontSans,
            fontSize: 11,
            color: E.dim,
            lineHeight: 1.45,
          }}
        >
          {children}
        </div>
      ) : null}
    </div>
  );
}
