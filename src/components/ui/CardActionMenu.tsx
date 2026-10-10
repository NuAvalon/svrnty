'use client';

import { useEffect, useRef, type CSSProperties, type ReactNode } from 'react';
import { ChevronDown } from 'lucide-react';
import { solarEmber as E } from '@/components/recovery/solar-ember';

/** Compact overflow menu. Items stay in the menu — they do not lengthen the card. */
export function CardActionMenu({
  open,
  onOpenChange,
  label = 'Actions',
  testId = 'card-actions-toggle',
  align = 'end',
  side = 'up',
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  label?: string;
  testId?: string;
  align?: 'start' | 'end';
  /** `down` stays in flow so a parent overflow:hidden cannot swallow the menu. */
  side?: 'up' | 'down';
  children: ReactNode;
}) {
  const root = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const menu = root.current?.querySelector('[role="menu"]');
    (menu as HTMLElement | null)?.scrollIntoView({ behavior: 'auto', block: 'nearest' });
    const onDoc = (e: PointerEvent) => {
      if (!root.current?.contains(e.target as Node)) onOpenChange(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onOpenChange(false);
    };
    document.addEventListener('pointerdown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('pointerdown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [open, onOpenChange]);

  return (
    <div ref={root} style={{ position: 'relative', flex: '1 1 0', minWidth: 0 }}>
      <button
        type="button"
        data-testid={testId}
        aria-expanded={open}
        aria-haspopup="menu"
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
          role="menu"
          data-testid={`${testId}-menu`}
          style={
            side === 'down'
              ? inFlowMenuStyle
              : {
                  ...menuStyle,
                  [align === 'end' ? 'right' : 'left']: 0,
                }
          }
        >
          {children}
        </div>
      ) : null}
    </div>
  );
}

export function CardMenuItem({
  label,
  onClick,
  danger,
  primary,
  testId,
}: {
  label: string;
  onClick: () => void;
  danger?: boolean;
  primary?: boolean;
  testId?: string;
}) {
  return (
    <button
      type="button"
      role="menuitem"
      data-testid={testId}
      onClick={onClick}
      style={{
        width: '100%',
        textAlign: 'left',
        fontFamily: E.fontSans,
        fontSize: 13,
        fontWeight: primary ? 600 : 400,
        padding: '10px 12px',
        border: 'none',
        borderRadius: 8,
        background: 'transparent',
        color: danger ? E.danger : E.text,
        cursor: 'pointer',
      }}
    >
      {label}
    </button>
  );
}

/** Shared Chat / Send update / Actions size — one verb row, one height. */
export function cardVerbBtnStyle(opts?: {
  muted?: boolean;
  open?: boolean;
}): CSSProperties {
  return {
    flex: '1 1 0',
    minWidth: 0,
    width: '100%',
    minHeight: 40,
    boxSizing: 'border-box',
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 6,
    fontFamily: E.fontSans,
    fontSize: 12,
    fontWeight: 600,
    letterSpacing: 0,
    padding: '8px 10px',
    borderRadius: 10,
    border: `1px solid ${opts?.muted ? E.border : E.borderLit}`,
    background: opts?.open
      ? 'color-mix(in srgb, var(--se-accent) 16%, transparent)'
      : opts?.muted
        ? 'transparent'
        : 'color-mix(in srgb, var(--se-accent) 12%, transparent)',
    color: opts?.muted ? E.muted : E.accent,
    cursor: 'pointer',
  };
}

function toggleStyle(open: boolean): CSSProperties {
  return cardVerbBtnStyle({ open });
}

const menuStyle: CSSProperties = {
  position: 'absolute',
  bottom: 'calc(100% + 6px)',
  zIndex: 30,
  minWidth: '100%',
  maxHeight: '46dvh',
  overflowY: 'auto',
  padding: 6,
  borderRadius: 12,
  border: `1px solid ${E.borderLit}`,
  background: E.surfaceSolid,
  boxShadow: 'var(--se-glass-shadow)',
};

const inFlowMenuStyle: CSSProperties = {
  position: 'relative',
  zIndex: 30,
  width: '100%',
  marginTop: 6,
  maxHeight: '46dvh',
  overflowY: 'auto',
  padding: 6,
  borderRadius: 12,
  border: `1px solid ${E.borderLit}`,
  background: E.surfaceSolid,
  boxShadow: 'var(--se-glass-shadow)',
};
