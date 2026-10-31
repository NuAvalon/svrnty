'use client';
// src/components/notes/RatchetRows.tsx
// #720 reliable receive, the thread half: the NAMED rows for messages from THIS contact that did not open, and the user-initiated
// "Reset message session" action. Copy is Hypatia's v0_10 through Athena's ratchet-rows.ts; the data is the encrypted dead-letter records
// and the per-contact reset flag (reset-flag-store.ts). A reset is only ever the user's click on Reset in a dialog whose focus starts on Cancel
// (R1/R7); nothing here runs on a poll or a message.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { listDeadLetters } from '@/lib/messaging/dead-letter-store';
import { hasResetFlag } from '@/lib/messaging/reset-flag-store';
import { resetMessageSession } from '@/lib/messaging/session-reset';
import type { DeadLetterRow } from '@/lib/sync/dead-letter';
import { resetDialog, resetButtonLabel } from './ratchet-rows';
import { ratchetViewFor } from './ratchet-rows-view';
import { solarEmber as E } from '@/components/recovery/solar-ember';

// PROVISIONAL (Apollo): the one line this component needs that copy v0_10 does not have. Observed-only, no cause, no promise. Hypatia to freeze or replace.
export const RESET_FAILED_LINE = "Couldn't reset right now.";

const REFRESH_MS = 5000;

export function RatchetRows({ ownerFingerprint, peerFingerprint, peerName, storeReady }: {
  ownerFingerprint: string;
  peerFingerprint: string;
  peerName: string;
  storeReady: boolean;
}) {
  const [records, setRecords] = useState<DeadLetterRow[]>([]);
  const [outOfStep, setOutOfStep] = useState(false);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const cancelRef = useRef<HTMLButtonElement | null>(null);
  const seq = useRef(0);
  const invalidate = useCallback(() => { seq.current += 1; }, []);

  const load = useCallback(async () => {
    if (!storeReady || !peerFingerprint) return;
    const mine = ++seq.current;
    try {
      const [rows, flag] = await Promise.all([listDeadLetters(), hasResetFlag(peerFingerprint)]);
      if (mine === seq.current) { setRecords(rows); setOutOfStep(flag); }
    } catch {
      /* store locked or unreadable: keep what is shown; the next refresh tries again */
    }
  }, [storeReady, peerFingerprint]);

  useEffect(() => {
    setOpen(false); setFailed(false); setRecords([]); setOutOfStep(false);
    void load();
    const t = setInterval(() => void load(), REFRESH_MS);
    return () => { clearInterval(t); invalidate(); };
  }, [load, invalidate]);

  const view = useMemo(() => ratchetViewFor(records, peerFingerprint, peerName, outOfStep), [records, peerFingerprint, peerName, outOfStep]);
  const dialog = useMemo(() => resetDialog(peerName, view.held), [peerName, view.held]);

  useEffect(() => { if (open) cancelRef.current?.focus(); }, [open]);

  const confirm = async () => {
    if (busy) return;
    setBusy(true); setFailed(false);
    try {
      await resetMessageSession(ownerFingerprint, peerFingerprint);
      setOpen(false);
      await load();
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  };

  if (!view.rows.length && !view.canReset) return null;
  return (
    <div data-testid="ratchet-rows" style={{ margin: '8px 0', display: 'grid', gap: 8 }}>
      {view.rows.map((r) => (
        <div key={r.key} role="status" data-testid="ratchet-row" style={{ border: `1px solid ${E.muted}`, borderRadius: 10, padding: '10px 12px', fontSize: 13, lineHeight: 1.45, color: E.text }}>
          <p data-testid="ratchet-row-line" style={{ margin: 0 }}>{r.line}</p>
          {r.hint ? <p data-testid="ratchet-row-hint" style={{ margin: '6px 0 0', color: E.muted }}>{r.hint}</p> : null}
        </div>
      ))}
      {view.canReset && !open ? (
        <button type="button" data-testid="ratchet-reset-open" onClick={() => { setFailed(false); setOpen(true); }} style={{ justifySelf: 'start', font: 'inherit', fontSize: 13, padding: '6px 10px', cursor: 'pointer' }}>
          {resetButtonLabel(peerName)}
        </button>
      ) : null}
      {open ? (
        <div role="alertdialog" aria-labelledby="ratchet-reset-title" aria-describedby="ratchet-reset-body" data-testid="ratchet-reset-dialog" style={{ border: `1px solid ${E.muted}`, borderRadius: 10, padding: '12px', fontSize: 13, lineHeight: 1.45, color: E.text }}>
          <p id="ratchet-reset-title" style={{ margin: 0, fontWeight: 600 }}>{dialog.title}</p>
          <div id="ratchet-reset-body">
            <p style={{ margin: '6px 0 0' }}>{dialog.explainer}</p>
            {dialog.countLine ? <p data-testid="ratchet-reset-count" style={{ margin: '6px 0 0' }}>{dialog.countLine}</p> : null}
            {failed ? <p data-testid="ratchet-reset-failed" role="alert" style={{ margin: '6px 0 0' }}>{RESET_FAILED_LINE}</p> : null}
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
            <button ref={cancelRef} type="button" data-testid="ratchet-reset-cancel" disabled={busy} onClick={() => setOpen(false)} style={{ font: 'inherit', fontSize: 13, padding: '6px 10px', cursor: 'pointer' }}>{dialog.cancel}</button>
            <button type="button" data-testid="ratchet-reset-confirm" disabled={busy} onClick={() => void confirm()} style={{ font: 'inherit', fontSize: 13, padding: '6px 10px', cursor: 'pointer' }}>{dialog.confirm}</button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
