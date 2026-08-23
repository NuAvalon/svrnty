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

import { useEffect, useRef, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Sparkles, Moon, Circle, ChevronRight } from 'lucide-react';
import type { TrustEdge } from '@/lib/trust/types';
import type { ContactState } from '@/lib/trust/contact-state';
import { CONTACT_STATE_META } from '@/lib/trust/contact-state';
import { buildBookView, type BookRow } from '@/lib/trust/book-view';

const BLOOM_MS = 1200;

const STATE_CLASS: Record<ContactState, string> = {
  gray: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
  living: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  dim: 'bg-amber-500/10 text-amber-300/80 border-amber-500/20',
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
  return (
    <button
      type="button"
      data-testid="contact-row"
      data-live={live ? 'push' : undefined}
      onClick={() => onSelect?.(row.edge)}
      title={meta.hint}
      className={[
        'group w-full text-left flex items-center gap-3 rounded-lg border p-3',
        'bg-card hover:border-border transition-all duration-700 cursor-pointer',
        glowing
          ? 'border-emerald-400/70 ring-2 ring-emerald-400/60 shadow-[0_0_18px_rgba(52,211,153,0.45)]'
          : 'border-border/40',
      ].join(' ')}
    >
      <span className={`inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full border ${STATE_CLASS[row.state]}`}>
        <Icon className="h-4 w-4" />
      </span>
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-2">
          <span className="truncate font-medium">{row.edge.peer_name || row.edge.peer_email || 'Unnamed'}</span>
          <Badge className={`border text-[10px] font-medium ${STATE_CLASS[row.state]}`}>{meta.label}</Badge>
        </span>
        <span className="block truncate text-xs text-muted-foreground">{hintFor(row)}</span>
      </span>
      <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
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
    <Card className="flex-1 border-border/40 bg-card/50 backdrop-blur-sm">
      <CardHeader className="border-b border-border/40 pb-3">
        <CardTitle className="flex items-baseline justify-between text-base">
          <span>{title}</span>
          <span className="text-xs font-normal text-muted-foreground">{rows.length}</span>
        </CardTitle>
        <p className="text-xs text-muted-foreground">{subtitle}</p>
      </CardHeader>
      <CardContent className="space-y-2 pt-3">
        {rows.length === 0
          ? <p className="py-6 text-center text-xs text-muted-foreground">{empty}</p>
          : rows.map(row => (
              <Row
                key={row.edge.id}
                row={row}
                glowing={glow.has(row.edge.id)}
                live={liveIds?.has(row.edge.id)}
                onSelect={onSelect}
              />
            ))}
      </CardContent>
    </Card>
  );
}

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
    <div className={`flex flex-col gap-4 md:flex-row md:items-stretch ${className}`}>
      <Side
        title="Living"
        subtitle="Vouched and fresh — the people your trust is currently reaching."
        rows={view.living}
        glow={glow}
        liveIds={liveIds}
        onSelect={onSelect}
        empty="No living contacts yet. Vouch for someone to bring them to life."
      />
      <div className="hidden w-px self-stretch bg-border/40 md:block" aria-hidden />
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
  );
}

export default TwoSidedBook;
