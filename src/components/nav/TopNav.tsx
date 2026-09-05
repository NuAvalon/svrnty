'use client';

/**
 * App header — wordmark always visible; action buttons collapse at phone widths.
 * Same handlers as the previous inline header (Grow / Recovery / lock).
 * Does not change unlock or recovery control flow.
 */

import { useEffect, useId, useRef, useState, type CSSProperties } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { AppearanceToggle } from '@/components/ui-prefs/AppearanceToggle';
import { LockNowButton } from '@/components/app-lock/LockNowButton';
import { HelpGuide } from '@/components/HelpGuide';
import './top-nav.css';

export type TopNavProps = {
  hasIdentity: boolean;
  canLock: boolean;
  onLock: () => void;
  onGrow: () => void;
  onRecovery: () => void;
};

const pillStyle: CSSProperties = {
  fontFamily: E.fontSans,
  fontSize: 12,
  letterSpacing: '0.12em',
  textTransform: 'uppercase',
  color: E.accent,
  background: 'transparent',
  border: `1px solid ${E.borderLit}`,
  borderRadius: 999,
  padding: '6px 12px',
  cursor: 'pointer',
};

const menuItemStyle: CSSProperties = {
  width: '100%',
  textAlign: 'left',
  fontFamily: E.fontSans,
  fontSize: 13,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  color: E.accent,
  background: 'transparent',
  border: 'none',
  borderRadius: 8,
  padding: '12px 14px',
  cursor: 'pointer',
};

function NavPill({
  label,
  onClick,
  testId,
}: {
  label: string;
  onClick: () => void;
  testId?: string;
}) {
  return (
    <button type="button" data-testid={testId} onClick={onClick} style={pillStyle}>
      {label}
    </button>
  );
}

export function TopNav({
  hasIdentity,
  canLock,
  onLock,
  onGrow,
  onRecovery,
}: TopNavProps) {
  const [menuOpen, setMenuOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuBtnRef = useRef<HTMLButtonElement>(null);
  const menuId = useId();

  useEffect(() => {
    if (!menuOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMenuOpen(false);
    };
    const onPointer = (e: PointerEvent) => {
      const t = e.target as Node | null;
      if (!t) return;
      if (menuRef.current?.contains(t)) return;
      if (menuBtnRef.current?.contains(t)) return;
      setMenuOpen(false);
    };
    document.addEventListener('keydown', onKey);
    document.addEventListener('pointerdown', onPointer);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('pointerdown', onPointer);
    };
  }, [menuOpen]);

  const openSheet = (fn: () => void) => {
    setMenuOpen(false);
    fn();
  };

  return (
    <header className="svrnty-topnav" data-testid="top-nav" style={{ fontFamily: E.fontSans }}>
      <span className="svrnty-topnav-wordmark" data-testid="top-nav-wordmark">
        SVRNTY.IS YOURS
      </span>

      <div className="svrnty-topnav-desktop" data-testid="top-nav-desktop">
        {canLock && <LockNowButton onLock={onLock} />}
        <AppearanceToggle />
        {hasIdentity ? (
          <>
            <NavPill label="Grow" onClick={onGrow} testId="nav-grow" />
            <NavPill label="Recovery" onClick={onRecovery} testId="nav-recovery" />
          </>
        ) : null}
        <HelpGuide />
      </div>

      <div className="svrnty-topnav-phone" data-testid="top-nav-phone">
        <button
          ref={menuBtnRef}
          type="button"
          data-testid="top-nav-menu-btn"
          aria-label="Menu"
          aria-expanded={menuOpen}
          aria-controls={menuId}
          onClick={() => setMenuOpen((v) => !v)}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            fontFamily: E.fontSans,
            fontSize: 11,
            fontWeight: 500,
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            color: E.accent,
            background: 'transparent',
            border: `1px solid ${E.borderLit}`,
            borderRadius: 8,
            padding: '6px 10px',
            cursor: 'pointer',
          }}
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinecap="round"
            aria-hidden
          >
            <path d="M4 7h16M4 12h16M4 17h16" />
          </svg>
          Menu
        </button>

        {menuOpen ? (
          <div
            ref={menuRef}
            id={menuId}
            className="svrnty-topnav-menu"
            data-testid="top-nav-menu"
            role="menu"
            aria-label="App actions"
          >
            {hasIdentity ? (
              <button
                type="button"
                role="menuitem"
                data-testid="nav-recovery-menu"
                onClick={() => openSheet(onRecovery)}
                style={menuItemStyle}
              >
                Recovery
              </button>
            ) : null}
            <button
              type="button"
              role="menuitem"
              data-testid="nav-help-menu"
              onClick={() => {
                setMenuOpen(false);
                setHelpOpen(true);
              }}
              style={menuItemStyle}
            >
              Help
            </button>
            {canLock ? (
              <button
                type="button"
                role="menuitem"
                data-testid="nav-lock-menu"
                onClick={() => openSheet(onLock)}
                style={menuItemStyle}
              >
                Lock
              </button>
            ) : null}
            {hasIdentity ? (
              <>
                <button
                  type="button"
                  role="menuitem"
                  data-testid="nav-grow-menu"
                  onClick={() => openSheet(onGrow)}
                  style={menuItemStyle}
                >
                  Grow
                </button>
              </>
            ) : null}
            <div style={{ padding: '6px 6px 2px' }}>
              <AppearanceToggle />
            </div>
          </div>
        ) : null}
      </div>

      <HelpGuide showTrigger={false} open={helpOpen} onOpenChange={setHelpOpen} />
    </header>
  );
}
