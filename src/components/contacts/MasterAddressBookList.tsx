'use client';

/**
 * Flat Master Address Book rows — no living/resting chrome.
 */

import type { CSSProperties } from 'react';
import { Check } from 'lucide-react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { isSvrnNetworkContact } from '@/lib/contacts/is-svrn-contact';

export type MasterBookRow = {
  id: string;
  name: string;
  email?: string;
  fingerprint?: string;
  public_key?: string;
  trust_level?: string;
  blocked?: boolean;
  /** Owner-local private tags (groups) — never a wire field. */
  tags?: string[];
  /** SVRNTY awaiting reciprocal add — no pulse yet. */
  pending?: boolean;
};

export type MasterAddressBookListProps = {
  rows: MasterBookRow[];
  selectedIds: Set<string>;
  selectionMode: boolean;
  onToggleSelect: (id: string) => void;
  onOpen: (id: string) => void;
  /**
   * Contact ids whose latest repaint came from a live peer apply.
   * Sets data-live="push" — demo-arc beat-4 honesty hinge (reason:'live-apply' only).
   */
  liveIds?: Set<string>;
};

function isTrusted(row: MasterBookRow): boolean {
  const t = (row.trust_level || '').toLowerCase();
  return t === 'trusted' || t === 'verified';
}

const rowBtn: CSSProperties = {
  width: '100%',
  textAlign: 'left',
  display: 'flex',
  alignItems: 'center',
  gap: 12,
  borderRadius: 12,
  border: `1px solid ${E.border}`,
  padding: '12px 14px',
  background: E.surfaceSolid,
  cursor: 'pointer',
  fontFamily: E.fontSans,
  color: E.text,
};

export function MasterAddressBookList({
  rows,
  selectedIds,
  selectionMode,
  onToggleSelect,
  onOpen,
  liveIds,
}: MasterAddressBookListProps) {
  if (rows.length === 0) return null;

  return (
    <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
      {rows.map((row) => {
        const svrn = isSvrnNetworkContact(row);
        const selected = selectedIds.has(row.id);
        const live = liveIds?.has(row.id) === true;
        return (
          <li key={row.id}>
            <button
              type="button"
              data-testid="contact-row"
              data-master-book-row="1"
              data-svrn={svrn ? '1' : '0'}
              data-live={live ? 'push' : undefined}
              onClick={() => {
                if (selectionMode) onToggleSelect(row.id);
                else onOpen(row.id);
              }}
              style={{
                ...rowBtn,
                borderColor: selected || live ? E.borderLit : E.border,
                background: selected || live
                  ? 'color-mix(in srgb, var(--se-accent) 10%, transparent)'
                  : E.surfaceSolid,
                boxShadow: live
                  ? '0 0 18px color-mix(in srgb, var(--se-accent) 22%, transparent)'
                  : undefined,
              }}
            >
              {selectionMode ? (
                <span
                  aria-hidden
                  style={{
                    width: 18,
                    height: 18,
                    borderRadius: 4,
                    border: `1px solid ${selected ? E.accent : E.border}`,
                    background: selected ? E.accent : 'transparent',
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                  }}
                >
                  {selected ? <Check className="h-3 w-3" style={{ color: E.bg }} /> : null}
                </span>
              ) : null}
              <span style={{ flex: 1, minWidth: 0 }}>
                <span
                  style={{
                    display: 'block',
                    fontSize: 14,
                    fontWeight: 600,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {row.name || 'Unnamed'}
                </span>
                <span
                  style={{
                    display: 'block',
                    fontSize: 11,
                    color: E.dim,
                    fontFamily: E.fontMono,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {row.email || (row.fingerprint ? `${row.fingerprint.slice(0, 12)}…` : 'no key yet')}
                </span>
                {row.tags && row.tags.length > 0 ? (
                  <span
                    style={{
                      display: 'flex',
                      flexWrap: 'wrap',
                      gap: 4,
                      marginTop: 6,
                    }}
                  >
                    {row.tags.slice(0, 4).map((tag) => (
                      <span
                        key={tag}
                        style={{
                          fontSize: 10,
                          fontFamily: E.fontSans,
                          color: E.muted,
                          border: `1px solid ${E.border}`,
                          borderRadius: 6,
                          padding: '1px 6px',
                        }}
                      >
                        {tag}
                      </span>
                    ))}
                    {row.tags.length > 4 ? (
                      <span style={{ fontSize: 10, color: E.dim }}>+{row.tags.length - 4}</span>
                    ) : null}
                  </span>
                ) : null}
              </span>
              <span style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4, flexShrink: 0 }}>
                <span
                  style={{
                    fontSize: 10,
                    letterSpacing: '0.08em',
                    textTransform: 'uppercase',
                    color: svrn ? E.accent : E.dim,
                    fontFamily: E.fontSans,
                  }}
                >
                  {svrn ? 'SVRN' : 'Classical'}
                </span>
                {svrn && row.pending ? (
                  <span
                    data-testid="master-row-pending"
                    style={{ fontSize: 10, color: E.accent, letterSpacing: '0.04em' }}
                  >
                    Pending
                  </span>
                ) : null}
                {svrn ? (
                  <span
                    style={{
                      fontSize: 10,
                      color: row.blocked ? E.danger : isTrusted(row) ? E.ok : E.muted,
                    }}
                  >
                    {row.blocked ? 'Blocked' : isTrusted(row) ? 'Trusted' : 'Known'}
                  </span>
                ) : null}
              </span>
            </button>
          </li>
        );
      })}
    </ul>
  );
}
