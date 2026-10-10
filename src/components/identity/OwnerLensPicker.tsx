'use client';

/**
 * Lens chips — pick which lens of YOU is on the card / Grow handoff.
 * Same identity. Different profile. No second key.
 */

import type { CSSProperties } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
export function OwnerLensPicker({
  lenses,
  selectedId,
  defaultId,
  onSelect,
  onEditLenses,
  testId = 'owner-lens-picker',
}: {
  lenses: Array<{ id: string; name: string }>;
  selectedId?: string;
  defaultId?: string;
  onSelect: (id: string) => void;
  /** Opens the lens editor (studio). */
  onEditLenses?: () => void;
  testId?: string;
}) {
  if (!lenses.length) return null;
  return (
    <div
      data-testid={testId}
      style={{ display: 'flex', flexWrap: 'wrap', gap: 6, width: '100%' }}
    >
      {lenses.map((l) => {
        const on = l.id === selectedId;
        return (
          <button
            key={l.id}
            type="button"
            data-testid={`${testId}-chip`}
            data-lens-id={l.id}
            aria-pressed={on}
            onClick={() => onSelect(l.id)}
            style={chip(on)}
          >
            {l.name || 'Untitled'}
            {l.id === defaultId ? ' · default' : ''}
          </button>
        );
      })}
      {onEditLenses ? (
        <button
          type="button"
          data-testid={`${testId}-edit`}
          onClick={onEditLenses}
          style={chip(false)}
        >
          Edit lenses
        </button>
      ) : null}
    </div>
  );
}

function chip(active: boolean): CSSProperties {
  return {
    fontSize: 11,
    fontFamily: E.fontSans,
    padding: '6px 10px',
    borderRadius: 8,
    cursor: 'pointer',
    border: `1px solid ${active ? E.borderLit : E.border}`,
    background: active ? 'color-mix(in srgb, var(--se-accent) 14%, transparent)' : 'transparent',
    color: active ? E.accent : E.muted,
  };
}
