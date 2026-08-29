'use client';

// Archie's Sovereign Identity card — Solar Ember home surface.
// UI-only: renders existing identity fields. "Revise" is an L1 stub (no broadcast crypto).

import { useMemo, useRef, useState } from 'react';
import { IdentitySeal } from './IdentitySeal';
import { solarEmber as E, solarGlass } from '../recovery/solar-ember';
import { SVRNTY_DOMAIN } from '@/lib/config/domain';
import {
  downloadSealPng,
  downloadSealSvg,
  sealFilename,
} from '@/lib/identity/seal-export';

export type MethodKind = 'email' | 'signal' | 'site';

export interface SovereignIdentityCardProps {
  name: string;
  fingerprint: string;
  /** Display slug like peter.svrnty.is or claimed URL short form */
  handle?: string;
  email?: string;
  signal?: string;
  site?: string;
  hasPqKeys?: boolean;
  onRevise?: (kind: MethodKind) => void;
  onOpenCircle?: () => void;
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

function CircleGlyph({ fingerprint }: { fingerprint: string }) {
  // Deterministic mini egocentric lattice from fingerprint (I-6) — not decorative noise.
  const pts = useMemo(() => {
    const hex = fingerprint.replace(/[^0-9a-fA-F]/g, '').toLowerCase().padEnd(16, '0');
    const nodes: { x: number; y: number; r: number }[] = [{ x: 28, y: 28, r: 3.2 }];
    for (let i = 0; i < 6; i++) {
      const a = ((parseInt(hex.slice(i * 2, i * 2 + 2), 16) / 255) * Math.PI * 2 + i * 1.05) % (Math.PI * 2);
      const dist = 12 + (parseInt(hex[(i + 4) % 16], 16) % 8);
      nodes.push({
        x: 28 + Math.cos(a) * dist,
        y: 28 + Math.sin(a) * dist,
        r: 1.6 + (parseInt(hex[(i + 8) % 16], 16) % 10) / 10,
      });
    }
    return nodes;
  }, [fingerprint]);

  return (
    <svg width={56} height={56} viewBox="0 0 56 56" aria-hidden>
      {pts.slice(1).map((p, i) => (
        <line key={`e${i}`} x1={pts[0].x} y1={pts[0].y} x2={p.x} y2={p.y} stroke={E.accent} strokeOpacity={0.35} strokeWidth={0.8} />
      ))}
      {pts.map((p, i) => (
        <circle
          key={`n${i}`}
          cx={p.x}
          cy={p.y}
          r={p.r}
          fill={i === 0 ? E.text : E.accent}
          fillOpacity={i === 0 ? 0.95 : 0.55}
        />
      ))}
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
        gap: 12,
        padding: '12px 14px',
        borderRadius: 12,
        background: 'rgba(12,8,5,.55)',
        border: `1px solid ${E.border}`,
      }}
    >
      <div
        style={{
          width: 36,
          height: 36,
          borderRadius: 10,
          border: `1px solid ${E.borderLit}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
          background: 'rgba(249,168,37,.04)',
        }}
      >
        <MethodIcon kind={kind} />
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          style={{
            fontSize: 10,
            letterSpacing: '0.16em',
            textTransform: 'uppercase',
            color: E.dim,
            fontFamily: E.fontSans,
            marginBottom: 2,
          }}
        >
          {label}
        </div>
        <div
          style={{
            fontSize: 14,
            color: value ? E.text : E.dim,
            fontFamily: value ? E.fontSans : E.fontMono,
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          }}
        >
          {value || emptyHint}
        </div>
      </div>
      <button
        type="button"
        onClick={() => onRevise?.(kind)}
        style={{
          background: 'none',
          border: 'none',
          color: E.muted,
          fontSize: 11,
          fontFamily: E.fontSans,
          cursor: 'pointer',
          padding: '4px 2px',
          opacity: 0.75,
          flexShrink: 0,
        }}
      >
        revise
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
}: SovereignIdentityCardProps) {
  const [reviseNote, setReviseNote] = useState<string | null>(null);
  const [exportNote, setExportNote] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const sealWrapRef = useRef<HTMLDivElement>(null);
  const displayHandle = handle
    ? (handle.startsWith('@') ? handle : `@${handle}`)
    : `@….${SVRNTY_DOMAIN}`;
  const signalDisplay = signal ? maskSignal(signal) : undefined;
  const exportBase = useMemo(() => {
    const slug = handle?.replace(/^@/, '') || name || fingerprint.slice(0, 8);
    return slug;
  }, [handle, name, fingerprint]);

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

  const findSealSvg = (): SVGSVGElement | null => {
    return sealWrapRef.current?.querySelector('svg[data-identity-seal]') ?? null;
  };

  const handleExport = async (format: 'svg' | 'png') => {
    const svg = findSealSvg();
    if (!svg) {
      setExportNote('Seal not ready — try again.');
      return;
    }
    setExporting(true);
    setExportNote(null);
    try {
      const file = sealFilename(exportBase, format);
      if (format === 'svg') downloadSealSvg(svg, file);
      else await downloadSealPng(svg, file);
      setExportNote('Saved — your crystal only; not your key.');
    } catch {
      setExportNote('Could not export seal.');
    } finally {
      setExporting(false);
    }
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
        gap: 20,
      }}
    >
      <p
        style={{
          margin: 0,
          fontSize: 11,
          letterSpacing: '0.22em',
          textTransform: 'uppercase',
          color: E.accent,
          fontFamily: E.fontSans,
          fontWeight: 500,
        }}
      >
        Sovereign Identity · Your Card
      </p>

      <div
        style={{
          ...solarGlass,
          width: '100%',
          padding: '28px 22px 22px',
          borderRadius: 20,
          border: `1px solid ${E.borderLit}`,
          boxShadow: `0 0 48px rgba(249,168,37,.08), inset 0 1px 0 rgba(255,190,120,.06)`,
          background: 'linear-gradient(165deg, rgba(36,24,12,.72), rgba(18,12,7,.88))',
        }}
      >
        <div
          ref={sealWrapRef}
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: 10,
            marginBottom: 18,
          }}
        >
          <IdentitySeal fingerprint={fingerprint} size={96} />
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button
              type="button"
              disabled={exporting}
              onClick={() => void handleExport('png')}
              style={{
                background: 'rgba(249,168,37,.08)',
                border: `1px solid ${E.borderLit}`,
                color: E.accent,
                fontSize: 11,
                fontFamily: E.fontSans,
                fontWeight: 500,
                letterSpacing: '0.04em',
                padding: '6px 12px',
                borderRadius: 8,
                cursor: exporting ? 'wait' : 'pointer',
                opacity: exporting ? 0.6 : 1,
              }}
            >
              Save PNG
            </button>
            <button
              type="button"
              disabled={exporting}
              onClick={() => void handleExport('svg')}
              style={{
                background: 'transparent',
                border: `1px solid ${E.border}`,
                color: E.muted,
                fontSize: 11,
                fontFamily: E.fontSans,
                fontWeight: 500,
                letterSpacing: '0.04em',
                padding: '6px 12px',
                borderRadius: 8,
                cursor: exporting ? 'wait' : 'pointer',
                opacity: exporting ? 0.6 : 1,
              }}
            >
              Save SVG
            </button>
          </div>
          <p
            style={{
              margin: 0,
              fontSize: 10,
              color: E.dim,
              fontFamily: E.fontSans,
              textAlign: 'center',
              lineHeight: 1.45,
              maxWidth: 260,
            }}
          >
            Your crystal — unique to your key, shareable, not reversible.
          </p>
          {exportNote && (
            <p
              style={{
                margin: 0,
                fontSize: 10,
                color: E.ok,
                fontFamily: E.fontSans,
                textAlign: 'center',
              }}
            >
              {exportNote}
            </p>
          )}
        </div>

        <h2
          style={{
            margin: '0 0 6px',
            textAlign: 'center',
            fontSize: 26,
            fontWeight: 600,
            color: E.text,
            fontFamily: E.fontSans,
            letterSpacing: '0.01em',
          }}
        >
          {name || 'Unnamed'}
        </h2>
        <p
          style={{
            margin: '0 0 10px',
            textAlign: 'center',
            fontSize: 14,
            color: E.accent,
            fontFamily: E.fontMono,
          }}
        >
          {displayHandle}
        </p>
        <p
          style={{
            margin: '0 0 22px',
            textAlign: 'center',
            fontSize: 11,
            color: E.dim,
            fontFamily: E.fontMono,
            letterSpacing: '0.04em',
            wordBreak: 'break-all',
          }}
        >
          key · {formatKeyGroups(fingerprint)}
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 22 }}>
          <MethodRow kind="email" label="Email" value={email} emptyHint="not set" onRevise={handleRevise} />
          <MethodRow kind="signal" label="Signal" value={signalDisplay} emptyHint="not set" onRevise={handleRevise} />
          <MethodRow kind="site" label="Site" value={site} emptyHint="not set" onRevise={handleRevise} />
        </div>

        {reviseNote && (
          <p
            style={{
              margin: '0 0 16px',
              fontSize: 11,
              color: E.muted,
              fontFamily: E.fontSans,
              lineHeight: 1.5,
              textAlign: 'center',
            }}
          >
            {reviseNote}
          </p>
        )}

        <button
          type="button"
          onClick={onOpenCircle}
          style={{
            width: '100%',
            display: 'flex',
            alignItems: 'center',
            gap: 14,
            padding: '12px 8px',
            marginBottom: 18,
            background: 'none',
            border: 'none',
            cursor: onOpenCircle ? 'pointer' : 'default',
            textAlign: 'left',
          }}
        >
          <CircleGlyph fingerprint={fingerprint} />
          <p style={{ margin: 0, fontSize: 13, lineHeight: 1.55, color: E.muted, fontFamily: E.fontSans }}>
            <span style={{ color: E.text, fontWeight: 600 }}>Your circle.</span>{' '}
            The people you&apos;ve bonded with, and who they vouch for —{' '}
            <span style={{ color: E.text, fontWeight: 600 }}>your view</span>, never a global map.
          </p>
        </button>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center' }}>
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 8,
              padding: '7px 12px',
              borderRadius: 999,
              border: `1px solid ${E.border}`,
              background: 'rgba(12,8,5,.45)',
              fontSize: 11,
              color: E.muted,
              fontFamily: E.fontMono,
            }}
          >
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: E.ok, boxShadow: `0 0 8px ${E.ok}` }} />
            local-first · we can&apos;t read it
          </span>
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 8,
              padding: '7px 12px',
              borderRadius: 999,
              border: `1px solid ${E.border}`,
              background: 'rgba(12,8,5,.45)',
              fontSize: 11,
              color: E.muted,
              fontFamily: E.fontMono,
            }}
          >
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: E.accent, boxShadow: `0 0 8px ${E.accent}88` }} />
            {hasPqKeys ? 'Ed25519 + ML-DSA' : 'Ed25519'}
          </span>
        </div>
      </div>

      <p
        style={{
          margin: 0,
          textAlign: 'center',
          fontSize: 13,
          lineHeight: 1.6,
          fontFamily: E.fontSans,
          maxWidth: 340,
        }}
      >
        <span style={{ color: E.muted }}>The card is yours.</span>{' '}
        <span style={{ color: E.accent }}>No account.</span>{' '}
        <span style={{ color: E.muted }}>No server that can read you.</span>
      </p>
    </div>
  );
}
