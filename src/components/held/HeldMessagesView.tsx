'use client';

/**
 * The hold view: the owner's own screen of the notes kept from one frozen (or since-unblocked, or removed) sender. Copy ledger rows 335a-335i4 and 316a, every sentence from hold-view-copy.ts (this file spells
 * none of its own). It works ONLY through the HeldPort it is given (hold-view-model.ts), which is local to this device: opening it, reading, moving to the inbox and deleting send nothing to anyone.
 *   - Delete is behind a confirm whose default is CANCEL (it has the focus when it opens); moving to the inbox has no confirm.
 *   - A failure for ONE note says nothing was changed; a failure for ALL says how many held notes are still here, re-counted by the loop, never guessed.
 *   - A view that cannot load says so; it never shows "No held messages." for a store it could not read.
 *   - No reply, no export, no count anywhere before this view is opened.
 */

import { useCallback, useEffect, useState } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { cardVerbBtnStyle } from '@/components/ui/CardActionMenu';
import { HOLD_CAP_PER_SENDER, holdLimits } from '@/lib/messaging/held-note';
import type { NoteRecord } from '@/lib/messaging/types';
import {
  HOLD_VIEW_CONFIRM_CANCEL,
  HOLD_VIEW_CONFIRM_DELETE,
  HOLD_VIEW_CONFIRM_DELETE_ONE,
  HOLD_VIEW_DELETE_ALL,
  HOLD_VIEW_DELETE_ONE,
  HOLD_VIEW_EMPTY,
  HOLD_VIEW_FAILED_DELETE_ONE,
  HOLD_VIEW_FAILED_MOVE_ONE,
  HOLD_VIEW_LOAD_FAILED,
  HOLD_VIEW_MOVE_ALL,
  HOLD_VIEW_MOVE_ONE,
  HOLD_VIEW_MOVED_ONE_NOT_FROZEN,
  HOLD_VIEW_TITLE,
  holdViewAgeLine,
  holdViewCapLine,
  holdViewConfirmDeleteAll,
  holdViewFailedDeleteAll,
  holdViewFailedMoveAll,
  holdViewIntro,
  holdViewMovedAll,
  holdViewMovedAllNotFrozen,
  holdViewMovedOne,
} from './hold-view-copy';
import { deleteAllHeld, moveAllHeld, noteLines, type HeldPort } from './hold-view-model';

export type HeldMessagesViewProps = {
  /** The sender whose held notes are shown (the sender's fingerprint, as the notes carry it). */
  fingerprint: string;
  /** The contact's name, or null for a sender with no name (the sentences then say "this person"). */
  name: string | null;
  port: HeldPort;
  /** True (the default) on a frozen contact's own page, where "is still frozen" is true. False in the Lenses & vault section (removed or unblocked senders), where it would be false and the move results leave it off. */
  stillFrozen?: boolean;
};

type Confirm = { kind: 'one'; id: string } | { kind: 'all' } | null;
type Status = { text: string; failed: boolean } | null;

export function HeldMessagesView({ fingerprint, name, port, stillFrozen = true }: HeldMessagesViewProps) {
  const [notes, setNotes] = useState<NoteRecord[] | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [confirm, setConfirm] = useState<Confirm>(null);
  const [status, setStatus] = useState<Status>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async (): Promise<NoteRecord[] | null> => {
    try {
      const list = await port.listHeld(fingerprint);
      setNotes(list);
      setLoadFailed(false);
      return list;
    } catch {
      setLoadFailed(true);
      return null;
    }
  }, [port, fingerprint]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const moveOne = async (id: string) => {
    setBusy(true);
    setConfirm(null);
    let res: Awaited<ReturnType<HeldPort['release']>>;
    try {
      res = await port.release(id);
    } catch {
      res = 'lost-race';
    }
    setStatus(res === 'done' ? { text: stillFrozen ? holdViewMovedOne(name) : HOLD_VIEW_MOVED_ONE_NOT_FROZEN, failed: false } : res === 'gone' || res === 'not-held' ? null : { text: HOLD_VIEW_FAILED_MOVE_ONE, failed: true });
    await refresh();
    setBusy(false);
  };

  const deleteOne = async (id: string) => {
    setBusy(true);
    setConfirm(null);
    let res: Awaited<ReturnType<HeldPort['remove']>>;
    try {
      res = await port.remove(id);
    } catch {
      res = 'lost-race';
    }
    setStatus(res === 'done' || res === 'gone' || res === 'not-held' ? null : { text: HOLD_VIEW_FAILED_DELETE_ONE, failed: true });
    await refresh();
    setBusy(false);
  };

  const moveAll = async () => {
    if (!notes) return;
    setBusy(true);
    setConfirm(null);
    try {
      const r = await moveAllHeld(port, fingerprint, notes.map((n) => n.note_id));
      setStatus(r.ok ? { text: stillFrozen ? holdViewMovedAll(r.n, name) : holdViewMovedAllNotFrozen(r.n), failed: false } : { text: holdViewFailedMoveAll(r.stillHere), failed: true });
    } catch {
      setLoadFailed(true);
    }
    await refresh();
    setBusy(false);
  };

  const deleteAll = async () => {
    if (!notes) return;
    setBusy(true);
    setConfirm(null);
    try {
      const r = await deleteAllHeld(port, fingerprint, notes.map((n) => n.note_id));
      setStatus(r.ok ? null : { text: holdViewFailedDeleteAll(r.stillHere), failed: true });
    } catch {
      setLoadFailed(true);
    }
    await refresh();
    setBusy(false);
  };

  const { limitDays, graceDays } = holdLimits();
  const ageLine = holdViewAgeLine(limitDays, graceDays);
  const now = port.nowMs();

  return (
    <section
      data-testid="held-view"
      aria-label={HOLD_VIEW_TITLE}
      style={{ marginTop: 8, padding: 12, borderRadius: 12, border: `1px solid ${E.border}`, background: E.surface, display: 'flex', flexDirection: 'column', gap: 10, fontFamily: E.fontSans, color: E.text }}
    >
      <h3 data-testid="held-title" style={{ margin: 0, fontSize: 15 }}>{HOLD_VIEW_TITLE}</h3>
      <p data-testid="held-intro" style={{ margin: 0, fontSize: 13, lineHeight: 1.45 }}>{holdViewIntro(name)}</p>

      {loadFailed ? (
        <p data-testid="held-load-failed" role="status" style={{ margin: 0, fontSize: 13 }}>{HOLD_VIEW_LOAD_FAILED}</p>
      ) : notes === null ? null : notes.length === 0 ? (
        <p data-testid="held-empty" style={{ margin: 0, fontSize: 13, color: E.muted }}>{HOLD_VIEW_EMPTY}</p>
      ) : (
        <>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button type="button" data-testid="held-move-all" disabled={busy} onClick={() => { void moveAll(); }} style={cardVerbBtnStyle()}>{HOLD_VIEW_MOVE_ALL}</button>
            <button type="button" data-testid="held-delete-all" disabled={busy} onClick={() => setConfirm({ kind: 'all' })} style={cardVerbBtnStyle({ muted: true })}>{HOLD_VIEW_DELETE_ALL}</button>
          </div>
          <ul data-testid="held-list" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 10 }}>
            {notes.map((n) => {
              const lines = noteLines(n, now);
              return (
                <li key={n.note_id} data-testid={`held-note-${n.note_id}`} style={{ padding: 10, borderRadius: 10, border: `1px solid ${E.border}`, display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <p data-testid="held-note-body" style={{ margin: 0, fontSize: 14, lineHeight: 1.45, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{n.body}</p>
                  {lines.arrived ? <small data-testid="held-note-arrived" style={{ color: E.muted }}>{lines.arrived}</small> : null}
                  {lines.theirs ? <small data-testid="held-note-theirs" style={{ color: E.muted }}>{lines.theirs}</small> : null}
                  {lines.expiring ? <small data-testid="held-note-expiring">{lines.expiring}</small> : null}
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    <button type="button" data-testid="held-move-one" disabled={busy} onClick={() => { void moveOne(n.note_id); }} style={cardVerbBtnStyle()}>{HOLD_VIEW_MOVE_ONE}</button>
                    <button type="button" data-testid="held-delete-one" disabled={busy} onClick={() => setConfirm({ kind: 'one', id: n.note_id })} style={cardVerbBtnStyle({ muted: true })}>{HOLD_VIEW_DELETE_ONE}</button>
                  </div>
                  {confirm && confirm.kind === 'one' && confirm.id === n.note_id ? (
                    <div data-testid="held-confirm" role="alertdialog" aria-label={HOLD_VIEW_CONFIRM_DELETE_ONE} style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      <p style={{ margin: 0, fontSize: 13 }}>{HOLD_VIEW_CONFIRM_DELETE_ONE}</p>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button type="button" data-testid="held-confirm-cancel" autoFocus onClick={() => setConfirm(null)} style={cardVerbBtnStyle()}>{HOLD_VIEW_CONFIRM_CANCEL}</button>
                        <button type="button" data-testid="held-confirm-delete" disabled={busy} onClick={() => { void deleteOne(n.note_id); }} style={cardVerbBtnStyle({ muted: true })}>{HOLD_VIEW_CONFIRM_DELETE}</button>
                      </div>
                    </div>
                  ) : null}
                </li>
              );
            })}
          </ul>
          {confirm && confirm.kind === 'all' ? (
            <div data-testid="held-confirm" role="alertdialog" aria-label={holdViewConfirmDeleteAll(notes.length, name)} style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <p style={{ margin: 0, fontSize: 13 }}>{holdViewConfirmDeleteAll(notes.length, name)}</p>
              <div style={{ display: 'flex', gap: 8 }}>
                <button type="button" data-testid="held-confirm-cancel" autoFocus onClick={() => setConfirm(null)} style={cardVerbBtnStyle()}>{HOLD_VIEW_CONFIRM_CANCEL}</button>
                <button type="button" data-testid="held-confirm-delete" disabled={busy} onClick={() => { void deleteAll(); }} style={cardVerbBtnStyle({ muted: true })}>{HOLD_VIEW_CONFIRM_DELETE}</button>
              </div>
            </div>
          ) : null}
        </>
      )}

      {status ? <p data-testid="held-status" role="status" style={{ margin: 0, fontSize: 13 }}>{status.text}</p> : null}

      <div data-testid="held-limits" style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: 12, color: E.muted }}>
        {ageLine ? <p data-testid="held-age-line" style={{ margin: 0 }}>{ageLine}</p> : null}
        <p data-testid="held-cap-line" style={{ margin: 0 }}>{holdViewCapLine(HOLD_CAP_PER_SENDER)}</p>
      </div>
    </section>
  );
}
