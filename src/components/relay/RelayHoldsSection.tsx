'use client';

/**
 * "What the relay lists" in the Lenses & vault panel: what the relay's allowed list holds, next to what the owner's own contacts allow, and the difference. Owner-only; nothing here renders in the Galaxy or any in-person view.
 *   - Opening it makes NO request: it shows the last read the revoke check kept (relay-holds-port.ts), and says so when there is none (it was forgotten on lock, or never made).
 *   - The ONE thing that asks the relay again is the "Check again" button, which waits out a gap between presses; the other is a CONFIRMED repair, which re-reads once.
 *   - Every sentence is the copy owner's (relay-holds-copy.ts, ordered by relay-holds-view-model.ts). No fingerprint is ever shown: rows are named by the contact's name and keyed by position.
 *   - Repair is a deliberate press on one row, with its warning shown before the press; the book is re-read at the press (relay-holds-repair.ts).
 *   - Hidden while the PSI gate is dark: no reads exist then, and "could not check" would mislead.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { cardVerbBtnStyle } from '@/components/ui/CardActionMenu';
import { isPSIDiscoveryLive } from '@/lib/claim-gates';
import { RELAY_ENTRY, RELAY_REFRESH_BUTTON, RELAY_REPAIR_BUTTON, RELAY_REPAIR_WARNING } from './relay-holds-copy';
import { loadPanel, type RelayHoldsPort } from './relay-holds-port';
import { REFRESH_MIN_GAP_MS, canRefresh } from './relay-holds-refresh';
import { repairRow } from './relay-holds-repair';
import { repairLine, viewLines } from './relay-holds-view-model';
import type { PanelModel } from './relay-holds-model';

export type RelayHoldsSectionProps = {
  port: RelayHoldsPort;
  /** the PSI gate: nothing is rendered while it is dark */
  gate?: () => boolean;
};

const line = { margin: 0, fontSize: 13, fontFamily: E.fontSans, color: E.text } as const;
const mutedLine = { ...line, color: E.muted } as const;

export function RelayHoldsSection({ port, gate = isPSIDiscoveryLive }: RelayHoldsSectionProps) {
  const [open, setOpen] = useState(false);
  const [loaded, setLoaded] = useState<{ model: PanelModel; at: number | undefined } | null>(null);
  const [notices, setNotices] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [lastPress, setLastPress] = useState<number | undefined>(undefined);
  const [, rerender] = useState(0);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);

  const reload = useCallback(async () => { setLoaded(await loadPanel(port)); }, [port]);

  if (!gate()) return null;

  const toggle = async () => {
    if (open) { setOpen(false); return; }
    setOpen(true);
    setNotices([]);
    await reload();                                   // reads memory and the book: no request
  };

  const onRefresh = async () => {
    const now = port.nowMs();
    if (!canRefresh(lastPress, now).allowed) return;
    setLastPress(now);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => rerender((n) => n + 1), REFRESH_MIN_GAP_MS + 50);   // re-enable the button when the gap is over
    await port.refresh();
    await reload();
  };

  const onRepair = async (rows: ReadonlyArray<{ fp: string; label: string; name: string | null }>, index: number) => {
    const row = rows[index];
    if (!row || busy) return;
    setBusy(true);
    try {
      const out = await repairRow(rows, row.fp, port.repair);
      const text = repairLine(out, row.name);
      if (text) setNotices((n) => [...n, text]);
      if (out.kind === 'repaired') await port.refresh();   // one re-read, and only for a CONFIRMED repair
      await reload();
    } finally {
      setBusy(false);
    }
  };

  const waiting = !canRefresh(lastPress, port.nowMs()).allowed;
  const view = loaded ? viewLines(loaded.model, loaded.at, port.nowMs()) : null;

  return (
    <div data-testid="relay-holds-section" style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
      <button type="button" data-testid="relay-holds-entry" aria-expanded={open} onClick={() => { void toggle(); }} style={cardVerbBtnStyle({ muted: true })}>
        {RELAY_ENTRY}
      </button>
      {open && view ? (
        <div data-testid="relay-holds-panel" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {view.lines.map((l) => (
            <div key={l.id} style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <p data-testid={`relay-holds-line-${l.id}`} role={l.id === 'unknown' || l.id === 'book-damaged' ? 'status' : undefined} style={l.id === 'checked' || l.id === 'bydesign' ? mutedLine : line}>{l.text}</p>
              {l.id === 'under' ? (
                <ul data-testid="relay-holds-rows" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {view.rows.map((r, i) => (
                    <li key={i} data-testid={`relay-holds-row-${i}`} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      <span style={line}>{r.label}</span>
                      <p data-testid={`relay-holds-warning-${i}`} style={mutedLine}>{RELAY_REPAIR_WARNING}</p>
                      <button type="button" data-testid={`relay-holds-repair-${i}`} disabled={busy} onClick={() => { void onRepair(view.rows, i); }} style={cardVerbBtnStyle()}>
                        {RELAY_REPAIR_BUTTON}
                      </button>
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          ))}
          {notices.map((t, i) => <p key={i} data-testid="relay-holds-notice" role="status" style={line}>{t}</p>)}
          <button type="button" data-testid="relay-holds-refresh" disabled={waiting || busy} onClick={() => { void onRefresh(); }} style={cardVerbBtnStyle({ muted: true })}>
            {RELAY_REFRESH_BUTTON}
          </button>
        </div>
      ) : null}
    </div>
  );
}
