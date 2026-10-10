'use client';

// Sovereign Identity card — Solar Ember home surface.
// UI-only: renders existing identity fields. "Revise" is an L1 stub (no broadcast crypto).

import { useState, type ReactNode } from 'react';
import { IdentitySeal } from './IdentitySeal';
import { solarEmber as E, solarGlass } from '../recovery/solar-ember';
import { SVRNTY_DOMAIN } from '@/lib/config/domain';
import { downloadOwnVCard } from '@/lib/contacts/own-vcard';
import { CardActionMenu, CardMenuItem } from '@/components/ui/CardActionMenu';

export type MethodKind = 'email' | 'signal' | 'site';

export interface SovereignIdentityCardProps {
  name: string;
  fingerprint: string;
  /** Display slug like alice.svrnty.is or claimed URL short form */
  handle?: string;
  email?: string;
  signal?: string;
  site?: string;
  hasPqKeys?: boolean;
  onRevise?: (kind: MethodKind) => void;
  onOpenCircle?: () => void;
  /** Open Share Identity (moved from Contacts). */
  onShareIdentity?: () => void;
  /** Optional override — default downloads name + methods as native .vcf */
  onExportVcf?: () => void;
  /** Extra overflow-menu rows (vault, backup, claim). Closed via the callback. */
  extraActions?: (close: () => void) => ReactNode;
}

function formatKeyGroups(fp: string): string {
  const hex = fp.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (!hex) return '····';
  const groups = hex.match(/.{1,4}/g) || [];
  return groups.slice(0, 8).join('·');
}

function maskSignal(value: string): string {
  const digits = value.replace(/\D/g, '');
  if (digits.length >= 4) {
    return `+${digits.length > 10 ? digits[0] : '1'} ••• ••• ${digits.slice(-4)}`;
  }
  return value;
}

function MethodIcon({ kind }: { kind: MethodKind }) {
  const stroke = E.accent;
  const common = { width: 16, height: 16, viewBox: '0 0 24 24', fill: 'none', stroke, strokeWidth: 1.5, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const };
  if (kind === 'email') {
    return (
      <svg {...common}>
        <rect x="3" y="5" width="18" height="14" rx="2" />
        <path d="M3 7l9 6 9-6" />
      </svg>
    );
  }
  if (kind === 'signal') {
    return (
      <svg {...common}>
        <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.13.81.36 1.6.68 2.34a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.74-1.74a2 2 0 0 1 2.11-.45c.74.32 1.53.55 2.34.68A2 2 0 0 1 22 16.92z" />
      </svg>
    );
  }
  return (
    <svg {...common}>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" />
    </svg>
  );
}

function MethodRow({
  kind,
  label,
  value,
  emptyHint,
  onRevise,
}: {
  kind: MethodKind;
  label: string;
  value?: string;
  emptyHint: string;
  onRevise?: (kind: MethodKind) => void;
}) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        padding: '5px 8px',
        borderRadius: 10,
        background: E.inputBg,
        border: `1px solid ${E.border}`,
      }}
    >
      <div
        style={{
          width: 22,
          height: 22,
          borderRadius: 8,
          border: `1px solid ${E.borderLit}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
          background: 'color-mix(in srgb, var(--se-accent) 8%, transparent)',
        }}
      >
        <MethodIcon kind={kind} />
      </div>
      <div style={{ flex: 1, minWidth: 0, display: 'flex', alignItems: 'baseline', gap: 8 }}>
        <span
          style={{
            fontSize: 10,
            letterSpacing: '0.14em',
            textTransform: 'uppercase',
            color: E.dim,
            fontFamily: E.fontSans,
            flexShrink: 0,
            width: 48,
          }}
        >
          {label}
        </span>
        <span
          style={{
            fontSize: 13,
            color: value ? E.text : E.dim,
            fontFamily: value ? E.fontSans : E.fontMono,
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          }}
        >
          {value || emptyHint}
        </span>
      </div>
      <button
        type="button"
        className="ember-act"
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          onRevise?.(kind);
        }}
        aria-label={`Revise ${label}`}
        style={{
          background: 'transparent',
          border: 'none',
          color: E.accent,
          fontSize: 11,
          fontFamily: E.fontSans,
          cursor: 'pointer',
          padding: '2px 4px',
          flexShrink: 0,
          letterSpacing: '0.04em',
        }}
      >
        Revise
      </button>
    </div>
  );
}

export function SovereignIdentityCard({
  name,
  fingerprint,
  handle,
  email,
  signal,
  site,
  hasPqKeys = false,
  onRevise,
  onOpenCircle,
  onShareIdentity,
  onExportVcf,
  extraActions,
}: SovereignIdentityCardProps) {
  const [reviseNote, setReviseNote] = useState<string | null>(null);
  const [actionsOpen, setActionsOpen] = useState(false);
  const displayHandle = handle
    ? (handle.startsWith('@') ? handle : `@${handle}`)
    : `@….${SVRNTY_DOMAIN}`;
  const signalDisplay = signal ? maskSignal(signal) : undefined;

  const handleRevise = (kind: MethodKind) => {
    if (onRevise) {
      onRevise(kind);
      return;
    }
    setReviseNote(
      kind === 'email'
        ? 'Revise email — living method SEND is L1 (UI stub; team owns broadcast).'
        : kind === 'signal'
          ? 'Revise Signal — living method SEND is L1 (UI stub; team owns broadcast).'
          : 'Revise site — living method SEND is L1 (UI stub; team owns broadcast).'
    );
  };

  const handleExportVcf = () => {
    if (onExportVcf) {
      onExportVcf();
      return;
    }
    downloadOwnVCard({ name, fingerprint, email, signal, site });
  };

  return (
    <div
      style={{
        width: '100%',
        maxWidth: 440,
        margin: '0 auto',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 8,
      }}
    >
      <div
        data-testid="sovereign-identity-card"
        style={{
          ...solarGlass,
          width: '100%',
          padding: '12px 12px 10px',
          borderRadius: 16,
          border: `1px solid ${E.borderLit}`,
          boxShadow: 'var(--se-glass-shadow)',
          background: E.surfaceSolid,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
          <IdentitySeal fingerprint={fingerprint} size={56} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <p
              style={{
                margin: 0,
                fontSize: 10,
                letterSpacing: '0.18em',
                textTransform: 'uppercase',
                color: E.accent,
                fontFamily: E.fontSans,
              }}
            >
              Your card
            </p>
            <h2
              style={{
                margin: '2px 0 0',
                fontSize: 20,
                fontWeight: 600,
                color: E.text,
                fontFamily: E.fontSans,
              }}
            >
              {name || 'Unnamed'}
            </h2>
            <p style={{ margin: '2px 0 0', fontSize: 12, color: E.accent, fontFamily: E.fontMono }}>
              {displayHandle}
            </p>
            <p
              style={{
                margin: '4px 0 0',
                fontSize: 10,
                color: E.dim,
                fontFamily: E.fontMono,
                letterSpacing: '0.03em',
              }}
            >
              {formatKeyGroups(fingerprint)}
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 10 }}>
          <MethodRow kind="email" label="Email" value={email} emptyHint="not set" onRevise={handleRevise} />
          <MethodRow kind="signal" label="Signal" value={signalDisplay} emptyHint="not set" onRevise={handleRevise} />
          <MethodRow kind="site" label="Site" value={site} emptyHint="not set" onRevise={handleRevise} />
        </div>

        {reviseNote && (
          <p style={{ margin: '0 0 10px', fontSize: 11, color: E.muted, textAlign: 'center' }}>
            {reviseNote}
          </p>
        )}

        <div style={{ display: 'flex', gap: 8 }}>
          {onShareIdentity ? (
            <button
              type="button"
              onClick={onShareIdentity}
              data-testid="share-identity-from-card"
              style={{
                flex: 1,
                padding: '10px 12px',
                borderRadius: 10,
                border: `1px solid ${E.borderLit}`,
                background: 'color-mix(in srgb, var(--se-accent) 12%, transparent)',
                color: E.accent,
                fontFamily: E.fontSans,
                fontSize: 13,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Share
            </button>
          ) : null}
          <CardActionMenu open={actionsOpen} onOpenChange={setActionsOpen}>
            <CardMenuItem
              testId="export-own-vcf"
              label="Save contact card (.vcf)"
              onClick={() => {
                handleExportVcf();
                setActionsOpen(false);
              }}
            />
            {onOpenCircle ? (
              <CardMenuItem
                label="Your Galaxy"
                onClick={() => {
                  onOpenCircle();
                  setActionsOpen(false);
                }}
              />
            ) : null}
            {extraActions?.(() => setActionsOpen(false))}
          </CardActionMenu>
        </div>
        <p style={{ margin: '8px 0 0', fontSize: 10, color: E.dim, textAlign: 'center' }}>
          Local-first · {hasPqKeys ? 'Ed25519 + ML-DSA' : 'Ed25519'}
        </p>
      </div>
    </div>
  );
}
