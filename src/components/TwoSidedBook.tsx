"use client";

// TwoSidedBook — 0.14, the two-sided living address book.
//
// Two facing pages: the LIVING side (vouched + fresh) and the RESTING side
// (gray cards you hold + dim contacts that have faded). A contact that ignites
// — gray/dim -> living — blooms: a brief glow as it crosses to the living page.
//
// All state is DERIVED from the trust edges (see book-view.ts / contact-state.ts);
// this component stores nothing but the transient bloom glow. Mount it with a
// TrustEdge[] — it does not fetch, mutate, or persist. Wiring into a page is a
// one-liner: <TwoSidedBook edges={edges} onSelect={...} />.

import { useEffect, useRef, useState, type CSSProperties } from 'react';
import { Sparkles, Moon, Circle, ChevronRight } from 'lucide-react';
import type { TrustEdge } from '@/lib/trust/types';
import type { ContactState } from '@/lib/trust/contact-state';
import { CONTACT_STATE_META } from '@/lib/trust/contact-state';
import { buildBookView, type BookRow } from '@/lib/trust/book-view';
import { solarEmber as E } from '@/components/recovery/solar-ember';

const BLOOM_MS = 1200;

const STATE_TONE: Record<ContactState, { fg: string; bg: string; border: string }> = {
  gray: { fg: E.dim, bg: 'rgba(143,117,80,0.08)', border: E.border },
  living: { fg: E.accent, bg: 'rgba(249,168,37,0.1)', border: E.borderLit },
  dim: { fg: E.muted, bg: 'rgba(201,162,113,0.08)', border: 'rgba(255,190,120,0.16)' },
};

const STATE_ICON: Record<ContactState, typeof Circle> = {
  gray: Circle,
  living: Sparkles,
  dim: Moon,
};

/** Short, honest freshness line under each name. */
function hintFor(row: BookRow): string {
  const d = row.daysUntilDecay;
  switch (row.state) {
    case 'living':
      return d != null && d > 0 ? `Fresh · ${d}d until it rests` : 'Fresh';
    case 'dim':
      return d != null ? `Faded ${Math.abs(d)}d ago · re-ignites on contact` : 'Faded · re-ignites on contact';
    case 'gray':
      return CONTACT_STATE_META.gray.hint; // "Known, not yet vouched"
  }
}

function Row({ row, glowing, live, onSelect }: {
  row: BookRow;
  glowing: boolean;
  live?: boolean;
  onSelect?: (edge: TrustEdge) => void;
}) {
  const Icon = STATE_ICON[row.state];
  const meta = CONTACT_STATE_META[row.state];
  const tone = STATE_TONE[row.state];
  return (
    <button
      type="button"
      data-testid="contact-row"
      data-live={live ? 'push' : undefined}
      onClick={() => onSelect?.(row.edge)}
      title={meta.hint}
      style={{
        width: '100%',
        textAlign: 'left',
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        borderRadius: 12,
        border: `1px solid ${glowing ? E.borderLit : tone.border}`,
        padding: '12px 14px',
        background: glowing ? 'rgba(249,168,37,0.12)' : 'rgba(12,8,5,0.45)',
        boxShadow: glowing ? '0 0 18px rgba(249,168,37,0.28)' : 'none',
        cursor: 'pointer',
        fontFamily: E.fontSans,
        color: E.text,
        transition: 'border-color 0.4s, box-shadow 0.7s, background 0.4s',
      }}
    >
      <span
        style={{
          display: 'inline-flex',
          height: 32,
          width: 32,
          flexShrink: 0,
          alignItems: 'center',
          justifyContent: 'center',
          borderRadius: '50%',
          border: `1px solid ${tone.border}`,
          background: tone.bg,
          color: tone.fg,
        }}
      >
        <Icon size={16} />
      </span>
      <span style={{ minWidth: 0, flex: 1 }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span
            style={{
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              fontWeight: 500,
              fontSize: 14,
              fontFamily: E.fontSans,
              color: E.text,
            }}
          >
            {row.edge.peer_name || row.edge.peer_email || 'Unnamed'}
          </span>
          <span
            style={{
              fontSize: 10,
              fontFamily: E.fontMono,
              letterSpacing: '0.06em',
              textTransform: 'uppercase',
              color: tone.fg,
              border: `1px solid ${tone.border}`,
              background: tone.bg,
              borderRadius: 999,
              padding: '2px 8px',
              flexShrink: 0,
            }}
          >
            {meta.label}
          </span>
        </span>
        <span
          style={{
            display: 'block',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            fontSize: 12,
            color: E.dim,
            fontFamily: E.fontSans,
            fontWeight: 300,
            marginTop: 2,
          }}
        >
          {hintFor(row)}
        </span>
      </span>
      <ChevronRight size={16} style={{ flexShrink: 0, color: E.dim, opacity: 0.5 }} />
    </button>
  );
}

function Side({ title, subtitle, rows, glow, liveIds, onSelect, empty }: {
  title: string;
  subtitle: string;
  rows: BookRow[];
  glow: Set<string>;
  liveIds?: Set<string>;
  onSelect?: (edge: TrustEdge) => void;
  empty: string;
}) {
  return (
    <div style={sidePanel}>
      <div style={{ borderBottom: `1px solid ${E.border}`, padding: '14px 16px 12px' }}>
        <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 8 }}>
          <h3
            style={{
              margin: 0,
              fontFamily: E.fontSerif,
              fontWeight: 300,
              fontSize: 22,
              letterSpacing: '0.04em',
              color: E.text,
            }}
          >
            {title}
          </h3>
          <span style={{ fontFamily: E.fontMono, fontSize: 11, color: E.dim }}>{rows.length}</span>
        </div>
        <p
          style={{
            margin: '6px 0 0',
            fontSize: 12,
            lineHeight: 1.5,
            color: E.muted,
            fontFamily: E.fontSans,
            fontWeight: 300,
          }}
        >
          {subtitle}
        </p>
      </div>
      <div style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
        {rows.length === 0 ? (
          <p
            style={{
              padding: '24px 8px',
              textAlign: 'center',
              fontSize: 12,
              color: E.dim,
              fontFamily: E.fontSans,
              fontWeight: 300,
              lineHeight: 1.5,
            }}
          >
            {empty}
          </p>
        ) : (
          rows.map((row) => (
            <Row
              key={row.edge.id}
              row={row}
              glowing={glow.has(row.edge.id)}
              live={liveIds?.has(row.edge.id)}
              onSelect={onSelect}
            />
          ))
        )}
      </div>
    </div>
  );
}

const sidePanel: CSSProperties = {
  flex: 1,
  borderRadius: 16,
  border: `1px solid ${E.border}`,
  background: E.surface,
  backdropFilter: 'blur(20px)',
  WebkitBackdropFilter: 'blur(20px)',
  boxShadow: '0 0 40px rgba(249,168,37,.04)',
  overflow: 'hidden',
};

export function TwoSidedBook({ edges, onSelect, className = '', liveIds }: {
  edges: TrustEdge[];
  onSelect?: (edge: TrustEdge) => void;
  className?: string;
  /** Contact ids whose latest repaint came from a live peer apply → data-live="push" (beat-4). */
  liveIds?: Set<string>;
}) {
  const prevStates = useRef<Record<string, ContactState>>({});
  const view = buildBookView(edges, prevStates.current);

  const [glow, setGlow] = useState<Set<string>>(() => new Set());

  // Remember this render's states so the NEXT render can detect transitions.
  useEffect(() => {
    prevStates.current = view.states;
  });

  // Light up freshly-ignited contacts, then fade them after the bloom window.
  const bloomKey = view.bloomingIds.join(',');
  useEffect(() => {
    if (!view.bloomingIds.length) return;
    const ids = view.bloomingIds;
    setGlow(prev => { const n = new Set(prev); ids.forEach(id => n.add(id)); return n; });
    const t = setTimeout(() => {
      setGlow(prev => { const n = new Set(prev); ids.forEach(id => n.delete(id)); return n; });
    }, BLOOM_MS);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bloomKey]);

  return (
    <div
      className={className}
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 16,
        fontFamily: E.fontSans,
      }}
    >
      <style>{`
        @media (min-width: 768px) {
          .two-sided-book-row { flex-direction: row !important; align-items: stretch !important; }
          .two-sided-book-rule { display: block !important; }
        }
      `}</style>
      <div className="two-sided-book-row" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Side
          title="Living"
          subtitle="Vouched and fresh — the people your trust is currently reaching."
          rows={view.living}
          glow={glow}
          liveIds={liveIds}
          onSelect={onSelect}
          empty="No living contacts yet. Vouch for someone to bring them to life."
        />
        <div
          className="two-sided-book-rule"
          style={{ display: 'none', width: 1, alignSelf: 'stretch', background: E.border }}
          aria-hidden
        />
        <Side
          title="Resting"
          subtitle="Cards you hold, and contacts that have quietly faded. Nothing is broken — a single interaction re-ignites them."
          rows={view.resting}
          glow={glow}
          liveIds={liveIds}
          onSelect={onSelect}
          empty="Nothing resting. Every card you hold is alive."
        />
      </div>
    </div>
  );
}

export default TwoSidedBook;
