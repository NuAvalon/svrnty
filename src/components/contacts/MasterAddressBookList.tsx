'use client';

/**
 * Flat Living Address Book rows — status grammar matches Trust Map.
 */

import type { CSSProperties } from 'react';
import { Check } from 'lucide-react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { isSvrnNetworkContact } from '@/lib/contacts/is-svrn-contact';
import {
  livingEdgeStatus,
  livingStatusChip,
  type LivingEdgeStatus,
} from '@/lib/trust/living-edge-status';
import type { TrustEdge } from '@/lib/trust/types';

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
  /** Precomputed living status (from contactRecordToEdge projection). */
  living?: LivingEdgeStatus;
  lastMoment?: string | null;
};

export type MasterAddressBookListProps = {
  rows: MasterBookRow[];
  selectedIds: Set<string>;
  selectionMode: boolean;
  onToggleSelect: (id: string) => void;
  onOpen: (id: string) => void;
  liveIds?: Set<string>;
};

function statusForRow(row: MasterBookRow): LivingEdgeStatus {
  if (row.living) return row.living;
  // Fallback projection when parent did not pass living status.
  const edge = {
    id: row.id,
    peer_fingerprint: row.fingerprint || row.id,
    peer_name: row.name,
    peer_email: row.email || '',
    peer_public_key: row.public_key || '',
    trusted: (row.trust_level || '').toLowerCase() === 'verified' || (row.trust_level || '').toLowerCase() === 'trusted',
    trusted_since: null,
    last_interaction: new Date().toISOString(),
    decay_days: 730,
    trust_history: [],
    verification: { method: 'none', verified_at: null },
    mutual: { they_trust_me: null, last_sync: null, reciprocal: false },
    tags: row.tags || [],
    notes: '',
    connection_channels: [],
    added_at: new Date().toISOString(),
    connection_status: row.pending ? 'pending' : 'accepted',
  } as TrustEdge;
  return livingEdgeStatus(edge);
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

function chipColor(status: LivingEdgeStatus): string {
  if (status.trust === 'mutual') return E.accent2;
  if (status.trust === 'outbound') return E.accent;
  if (status.connection === 'pending') return E.accent;
  if (status.methodDelivery === 'undelivered') return E.danger || '#c45c4a';
  if (status.canCommunicate) return E.ok || E.accent;
  return E.muted;
}

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
        const status = statusForRow(row);
        const chip = livingStatusChip(status);
        return (
          <li key={row.id}>
            <button
              type="button"
              data-testid="contact-row"
              data-master-book-row="1"
              data-svrn={svrn ? '1' : '0'}
              data-live={live ? 'push' : undefined}
              data-living-trust={status.trust}
              data-can-communicate={status.canCommunicate ? '1' : '0'}
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
                  : status.trust === 'mutual'
                    ? '0 0 12px color-mix(in srgb, var(--se-accent2) 16%, transparent)'
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
                  data-testid="master-row-status"
                  style={{
                    display: 'block',
                    fontSize: 11,
                    color: E.muted,
                    marginTop: 2,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {status.statusLine}
                  {status.lastMoment ? ` · ${status.lastMoment}` : ''}
                </span>
                {status.detailLine ? (
                  <span
                    data-testid="master-row-detail"
                    style={{
                      display: 'block',
                      fontSize: 10,
                      color:
                        status.methodDelivery === 'undelivered' || status.methodDelivery === 'awaiting-ack'
                          ? E.accent
                          : E.dim,
                      marginTop: 2,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {status.detailLine}
                  </span>
                ) : null}
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
                <span
                  data-testid="master-row-chip"
                  style={{
                    fontSize: 10,
                    letterSpacing: '0.04em',
                    color: chipColor(status),
                    fontWeight: status.trust === 'mutual' || status.trust === 'outbound' ? 600 : 400,
                  }}
                >
                  {chip}
                </span>
                {row.blocked ? (
                  <span style={{ fontSize: 10, color: E.danger }}>Blocked</span>
                ) : null}
              </span>
            </button>
          </li>
        );
      })}
    </ul>
  );
}
