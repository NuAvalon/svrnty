'use client';

/**
 * Shared contact card — Galaxy sheet and Living Address Book use the same chrome.
 * List vs graph is the view; Chat / Actions / More stay one object.
 */

import type { CSSProperties, ReactNode } from 'react';
import { ChevronDown } from 'lucide-react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { IdentitySeal } from '@/components/identity/IdentitySeal';
import { CardActionMenu } from '@/components/ui/CardActionMenu';

export function ContactActionCard({
  testId = 'contact-action-card',
  name,
  fingerprint,
  bondLabel,
  bondColor = E.muted,
  lit = false,
  distress = false,
  introPending = false,
  expanded,
  onToggleExpand,
  onClose,
  canChat = false,
  onChat,
  actionsOpen,
  onActionsOpenChange,
  actionsSide = 'up',
  actions,
  more,
  edit,
  banner,
}: {
  testId?: string;
  name: string;
  fingerprint?: string;
  bondLabel: string;
  bondColor?: string;
  lit?: boolean;
  distress?: boolean;
  introPending?: boolean;
  expanded: boolean;
  onToggleExpand: () => void;
  onClose?: () => void;
  canChat?: boolean;
  onChat?: () => void;
  actionsOpen: boolean;
  onActionsOpenChange: (open: boolean) => void;
  actionsSide?: 'up' | 'down';
  actions: ReactNode;
  more?: ReactNode;
  edit?: ReactNode;
  banner?: ReactNode;
}) {
  const showMore = expanded || !!edit;

  return (
    <div
      className="contact-action-card"
      data-testid={testId}
      onClick={(e) => e.stopPropagation()}
      style={{
        marginTop: 10,
        padding: 10,
        borderRadius: 14,
        background: E.surfaceSolid,
        border: `1px solid ${
          distress ? E.accent2 : lit || introPending ? E.borderLit : E.border
        }`,
        boxShadow: 'var(--se-glass-shadow)',
        fontFamily: E.fontSans,
        overflow: 'visible',
      }}
    >
      {banner}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        {fingerprint ? (
          <span className="contact-hex" aria-hidden="true">
            <IdentitySeal fingerprint={fingerprint} size={28} />
          </span>
        ) : (
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: 8,
              border: `1px dashed ${E.border}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: E.dim,
              fontSize: 8,
              flexShrink: 0,
            }}
          >
            no key
          </div>
        )}
        <div style={{ flex: 1, minWidth: 0 }}>
          <p
            style={{
              margin: 0,
              fontSize: 14,
              fontWeight: 600,
              color: E.text,
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
          >
            {name || 'Unnamed'}
          </p>
          <p
            data-testid="trust-node-bond-label"
            style={{
              margin: '2px 0 0',
              fontSize: 11,
              color: bondColor,
              fontWeight: lit ? 600 : 500,
            }}
          >
            {bondLabel}
          </p>
        </div>
        <button
          type="button"
          data-testid="star-sheet-expand"
          aria-expanded={showMore}
          onClick={onToggleExpand}
          style={iconBtn}
        >
          {showMore ? 'Less' : 'More'}
          <ChevronDown
            size={12}
            style={{
              transform: showMore ? 'rotate(180deg)' : undefined,
              transition: 'transform 120ms ease',
            }}
          />
        </button>
        {onClose ? (
          <button type="button" onClick={onClose} style={{ ...iconBtn, border: 'none', padding: '6px 4px' }}>
            Close
          </button>
        ) : null}
      </div>

      {edit}

      {!edit ? (
        <div style={{ display: 'flex', gap: 8, marginTop: 10, alignItems: 'flex-start' }}>
          {canChat && onChat ? (
            <button
              type="button"
              data-testid="galaxy-open-note"
              onClick={onChat}
              style={chatBtn}
            >
              Chat
            </button>
          ) : null}
          <CardActionMenu open={actionsOpen} onOpenChange={onActionsOpenChange} side={actionsSide}>
            {actions}
          </CardActionMenu>
        </div>
      ) : null}

      {showMore && more ? more : null}
    </div>
  );
}

const iconBtn: CSSProperties = {
  background: 'transparent',
  border: `1px solid ${E.border}`,
  color: E.muted,
  cursor: 'pointer',
  fontSize: 11,
  fontFamily: E.fontSans,
  borderRadius: 8,
  padding: '6px 8px',
  display: 'inline-flex',
  alignItems: 'center',
  gap: 4,
  flexShrink: 0,
};

const chatBtn: CSSProperties = {
  flex: 1,
  fontSize: 12,
  fontFamily: E.fontSans,
  fontWeight: 600,
  padding: '8px 10px',
  borderRadius: 10,
  border: `1px solid ${E.borderLit}`,
  background: 'color-mix(in srgb, var(--se-accent) 12%, transparent)',
  color: E.accent,
  cursor: 'pointer',
};
