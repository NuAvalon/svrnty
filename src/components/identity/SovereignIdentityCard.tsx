'use client';

// Sovereign Identity card — Solar Ember home surface.
// UI-only: renders existing identity fields. "Revise" is an L1 stub (no broadcast crypto).

import { useState, type ReactNode } from 'react';
import { IdentitySeal } from './IdentitySeal';
import { solarEmber as E, solarGlass } from '../recovery/solar-ember';
import { SVRNTY_DOMAIN } from '@/lib/config/domain';
import { downloadOwnVCard } from '@/lib/contacts/own-vcard';
import { CardActionMenu, CardMenuItem } from '@/components/ui/CardActionMenu';
import { OwnerLensPicker } from '@/components/identity/OwnerLensPicker';

export type MethodKind = 'email' | 'signal' | 'site';

export type IdentityCardMethod = {
  id?: string;
  kind: string;
  label: string;
  value?: string;
};

export type IdentityCardLens = {
  id: string;
  name: string;
  isDefault?: boolean;
};

export interface SovereignIdentityCardProps {
  name: string;
  fingerprint: string;
  /** Display slug like alice.svrnty.is or claimed URL short form */
  handle?: string;
  email?: string;
  signal?: string;
  site?: string;
  /** Short line under the name for this face. */
  note?: string;
  /** Active lens name — painted on the card chrome. */
  lensName?: string;
  /** When set, these rows replace the classic email/Signal/site trio. */
  methods?: IdentityCardMethod[];
  lenses?: IdentityCardLens[];
  selectedLensId?: string;
  onSelectLens?: (id: string) => void;
  onEditFaces?: () => void;
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

function MethodIcon({ kind }: { kind: string }) {
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
  if (kind === 'signal' || kind === 'phone' || kind === 'whatsapp' || kind === 'telegram') {
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
  kind: string;
  label: string;
  value?: string;
  emptyHint: string;
  onRevise?: () => void;
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
      {onRevise ? (
        <button
          type="button"
          className="ember-act"
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            onRevise();
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
      ) : null}
    </div>
  );
}

function isClassicKind(kind: string): kind is MethodKind {
  return kind === 'email' || kind === 'signal' || kind === 'site';
}

export function SovereignIdentityCard({
  name,
  fingerprint,
  handle,
  email,
  signal,
  site,
  note,
  lensName,
  methods,
  lenses,
  selectedLensId,
  onSelectLens,
  onEditFaces,
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

  const rows: IdentityCardMethod[] = methods
    ? methods
    : [
        { kind: 'email', label: 'Email', value: email },
        { kind: 'signal', label: 'Signal', value: signalDisplay },
        { kind: 'site', label: 'Site', value: site },
      ];

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
        {lenses && lenses.length > 0 && onSelectLens ? (
          <div style={{ marginBottom: 10 }}>
            <OwnerLensPicker
              lenses={lenses}
              selectedId={selectedLensId}
              defaultId={lenses.find((l) => l.isDefault)?.id}
              onSelect={onSelectLens}
              onEditFaces={onEditFaces}
              testId="identity-lens-picker"
            />
          </div>
        ) : null}

        <div
          data-testid="identity-card-face"
          data-lens-id={selectedLensId || ''}
          data-lens-name={lensName || ''}
          style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}
        >
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
              Your card{lensName ? ` · ${lensName}` : ''}
            </p>
            <h2
              data-testid="identity-card-name"
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
            {note ? (
              <p
                data-testid="identity-card-note"
                style={{
                  margin: '4px 0 0',
                  fontSize: 12,
                  color: E.muted,
                  fontFamily: E.fontSans,
                  lineHeight: 1.35,
                }}
              >
                {note}
              </p>
            ) : null}
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

        <div
          data-testid="identity-card-methods"
          style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 10 }}
        >
          {rows.length === 0 ? (
            <p style={{ margin: 0, fontSize: 12, color: E.dim, fontFamily: E.fontSans }}>
              No channels on this face yet.
            </p>
          ) : (
            rows.map((row) => {
              const value =
                row.kind === 'signal' && row.value ? maskSignal(row.value) : row.value;
              const classic = isClassicKind(row.kind) ? row.kind : null;
              const revise = classic ? () => handleRevise(classic) : onEditFaces;
              return (
                <MethodRow
                  key={`${row.id || row.kind}-${row.label}`}
                  kind={row.kind}
                  label={row.label}
                  value={value}
                  emptyHint="not set"
                  onRevise={revise}
                />
              );
            })
          )}
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
