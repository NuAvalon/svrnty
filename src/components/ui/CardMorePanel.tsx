'use client';

import { useEffect, useRef, type CSSProperties, type ReactNode } from 'react';
import { ChevronDown } from 'lucide-react';
import { solarEmber as E } from '@/components/recovery/solar-ember';

/** Closed-by-default drawer under a card. Does not lengthen the first screen. */
export function CardMorePanel({
  open,
  onOpenChange,
  label,
  testId = 'card-more-toggle',
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  label: string;
  testId?: string;
  children: ReactNode;
}) {
  const rootRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    rootRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [open]);

  return (
    <div ref={rootRef} style={{ width: '100%', maxWidth: 440, margin: '10px auto 0' }}>
      <button
        type="button"
        data-testid={testId}
        aria-expanded={open}
        onClick={() => onOpenChange(!open)}
        style={toggleStyle(open)}
      >
        {label}
        <ChevronDown
          size={14}
          style={{
            transform: open ? 'rotate(180deg)' : undefined,
            transition: 'transform 120ms ease',
          }}
        />
      </button>
      {open ? (
        <div
          data-testid={`${testId}-panel`}
          style={{
            marginTop: 10,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: 10,
          }}
        >
          {children}
        </div>
      ) : null}
    </div>
  );
}

function toggleStyle(open: boolean): CSSProperties {
  return {
    width: '100%',
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 6,
    fontFamily: E.fontSans,
    fontSize: 12,
    fontWeight: 600,
    letterSpacing: '0.06em',
    padding: '8px 12px',
    borderRadius: 10,
    border: `1px solid ${E.border}`,
    background: open
      ? 'color-mix(in srgb, var(--se-accent) 12%, transparent)'
      : 'transparent',
    color: E.muted,
    cursor: 'pointer',
  };
}
