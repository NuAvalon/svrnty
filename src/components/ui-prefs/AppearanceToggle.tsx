'use client';

import { solarEmber as E } from '@/components/recovery/solar-ember';
import { useAppearance } from './AppearanceProvider';

/** Quiet light/dark toggle. Future: open a fuller UI prefs panel from here. */
export function AppearanceToggle() {
  const { appearance, toggleAppearance } = useAppearance();
  const isLight = appearance === 'light';

  return (
    <button
      type="button"
      onClick={toggleAppearance}
      aria-label={isLight ? 'Switch to dark mode' : 'Switch to light mode'}
      title={isLight ? 'Dark mode' : 'Light mode'}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        background: 'transparent',
        border: `1px solid ${E.border}`,
        borderRadius: 8,
        padding: '6px 10px',
        color: E.muted,
        fontFamily: E.fontSans,
        fontSize: 11,
        fontWeight: 500,
        letterSpacing: '0.06em',
        cursor: 'pointer',
        transition: 'border-color 0.2s, color 0.2s',
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = 'var(--se-border-lit)';
        e.currentTarget.style.color = 'var(--se-accent)';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = 'var(--se-border)';
        e.currentTarget.style.color = 'var(--se-muted)';
      }}
    >
      {isLight ? (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <path d="M21 14.5A8.5 8.5 0 1 1 11.5 3 7 7 0 0 0 21 14.5z" />
        </svg>
      ) : (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
        </svg>
      )}
      <span>{isLight ? 'Dark' : 'Light'}</span>
    </button>
  );
}
