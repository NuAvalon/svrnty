'use client';

import { solarEmber as E } from '@/components/recovery/solar-ember';

type Props = {
  onLock: () => void;
  disabled?: boolean;
};

/** Header control — clears session via caller (fleet `lockSession`). */
export function LockNowButton({ onLock, disabled }: Props) {
  return (
    <button
      type="button"
      data-testid="lock-now-btn"
      onClick={onLock}
      disabled={disabled}
      aria-label="Lock now"
      title="Lock now — clears keys from memory"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        background: 'transparent',
        border: `1px solid ${E.border}`,
        borderRadius: 8,
        padding: '6px 10px',
        color: disabled ? E.dim : E.muted,
        fontFamily: E.fontSans,
        fontSize: 11,
        fontWeight: 500,
        letterSpacing: '0.06em',
        cursor: disabled ? 'default' : 'pointer',
        opacity: disabled ? 0.5 : 1,
        transition: 'border-color 0.2s, color 0.2s',
      }}
      onMouseEnter={(e) => {
        if (disabled) return;
        e.currentTarget.style.borderColor = 'var(--se-border-lit)';
        e.currentTarget.style.color = 'var(--se-accent)';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = 'var(--se-border)';
        e.currentTarget.style.color = disabled ? 'var(--se-dim)' : 'var(--se-muted)';
      }}
    >
      <svg
        width="14"
        height="14"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden
      >
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
      <span>Lock</span>
    </button>
  );
}
