'use client';

/**
 * Over-wire Notes inbox — compose/send + thread list.
 * Calls fleet sendNoteToPeer / listThreads / listNotesForThread. Does not reimplement crypto.
 * Receive persist is already in the app-shell live-book poll; this glass re-reads the store.
 */

import { useCallback, useEffect, useMemo, useState, type CSSProperties } from 'react';
import { getAllContacts } from '@/lib/identity/client-store';
import { subscribeContactChanges } from '@/lib/contacts/contact-events';
import {
  initNotesStore,
  isNotesStoreUnlocked,
  listNotesForThread,
  listThreads,
  type NoteRecord,
  type NoteThread,
} from '@/lib/messaging';
import { solarEmber as E, solarGlass } from '@/components/recovery/solar-ember';
import { emitNoteArrival, subscribeNoteArrivals } from './note-events';
import { toNoteableContacts, type NoteableContact } from './notes-contacts';
import { NOTES_BOUNDS, NOTES_COPY } from './notes-copy';
import { loadOwnerNoteSender, type OwnerNoteSender } from './notes-keys';
import { sendNoteFromInbox } from './notes-send';
import { outboundStatus, statusLabel, type NoteBubbleStatus } from './notes-status';
import { boundDisplayText, formatFingerprintShort } from './notes-text';

type Props = {
  identity: {
    identity?: { fingerprint?: string; name?: string; public_key?: string };
    post_quantum?: { kem_public_key?: string; sig_public_key?: string };
  } | null;
};

const fieldStyle: CSSProperties = {
  width: '100%',
  fontFamily: E.fontSans,
  fontSize: 14,
  color: E.text,
  background: E.inputBg,
  border: `1px solid ${E.border}`,
  borderRadius: 10,
  padding: '10px 12px',
};

const areaStyle: CSSProperties = {
  ...fieldStyle,
  minHeight: 88,
  resize: 'vertical',
  lineHeight: 1.5,
};

const primaryBtn: CSSProperties = {
  fontFamily: E.fontSans,
  fontSize: 13,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  color: E.bg,
  background: E.accent,
  border: 'none',
  borderRadius: 999,
  padding: '10px 18px',
  cursor: 'pointer',
};

const STORE_REREAD_MS = 1_500;

function threadPeerFp(thread: NoteThread, ownerFp: string): string {
  const peer = thread.participants.find((p) => p.fingerprint !== ownerFp);
  return peer?.fingerprint || thread.participants[0]?.fingerprint || '';
}

function threadLabel(thread: NoteThread, contacts: NoteableContact[], ownerFp: string): string {
  const fp = threadPeerFp(thread, ownerFp);
  const named = contacts.find((c) => c.fingerprint === fp);
  if (named) return named.name;
  const fromThread = thread.participants.find((p) => p.fingerprint === fp)?.display_name;
  return boundDisplayText(fromThread) || formatFingerprintShort(fp);
}

export function NotesInbox({ identity }: Props) {
  const fp = identity?.identity?.fingerprint || '';
  const [rows, setRows] = useState<NoteableContact[]>([]);
  const [threads, setThreads] = useState<NoteThread[]>([]);
  const [notes, setNotes] = useState<NoteRecord[]>([]);
  const [selectedFp, setSelectedFp] = useState('');
  const [activeThreadId, setActiveThreadId] = useState<string | null>(null);
  const [draft, setDraft] = useState('');
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [storeReady, setStoreReady] = useState(false);
  const [sender, setSender] = useState<OwnerNoteSender | null>(null);
  const [failedIds, setFailedIds] = useState<Record<string, true>>({});

  const loadBook = useCallback(async () => {
    if (!fp) return;
    try {
      const records = await getAllContacts(fp);
      setRows(toNoteableContacts(records));
    } catch {
      setRows([]);
    }
  }, [fp]);

  const loadThreads = useCallback(async () => {
    if (!isNotesStoreUnlocked()) return;
    try {
      setThreads(await listThreads());
    } catch {
      setThreads([]);
    }
  }, []);

  const loadNotes = useCallback(async (threadId: string | null) => {
    if (!threadId || !isNotesStoreUnlocked()) {
      setNotes([]);
      return;
    }
    try {
      setNotes(await listNotesForThread(threadId));
    } catch {
      setNotes([]);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!fp) return;
      const owner = await loadOwnerNoteSender(fp, identity);
      if (cancelled) return;
      setSender(owner);
      if (!owner) return;
      try {
        if (!isNotesStoreUnlocked()) await initNotesStore(owner.passphrase);
        if (!cancelled) setStoreReady(true);
      } catch {
        if (!cancelled) setStoreReady(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [fp, identity]);

  useEffect(() => {
    void loadBook();
  }, [loadBook]);

  useEffect(() => {
    return subscribeContactChanges(() => {
      void loadBook();
    });
  }, [loadBook]);

  useEffect(() => {
    if (!storeReady) return;
    void loadThreads();
  }, [storeReady, loadThreads]);

  useEffect(() => {
    if (!storeReady) return;
    return subscribeNoteArrivals(() => {
      void loadThreads();
      void loadNotes(activeThreadId);
    });
  }, [storeReady, activeThreadId, loadThreads, loadNotes]);

  useEffect(() => {
    if (!storeReady) return;
    const tick = () => {
      void loadThreads();
      void loadNotes(activeThreadId);
    };
    const id = window.setInterval(tick, STORE_REREAD_MS);
    const onVis = () => {
      if (document.visibilityState === 'visible') tick();
    };
    document.addEventListener('visibilitychange', onVis);
    return () => {
      window.clearInterval(id);
      document.removeEventListener('visibilitychange', onVis);
    };
  }, [storeReady, activeThreadId, loadThreads, loadNotes]);

  const selected = useMemo(
    () => rows.find((c) => c.fingerprint === selectedFp) ?? null,
    [rows, selectedFp],
  );

  useEffect(() => {
    if (!selectedFp) return;
    const existing = threads.find(
      (t) => t.kind === 'direct' && t.participants.some((p) => p.fingerprint === selectedFp),
    );
    const nextId = existing?.thread_id ?? null;
    setActiveThreadId(nextId);
    void loadNotes(nextId);
  }, [selectedFp, threads, loadNotes]);

  const onPickContact = (nextFp: string) => {
    setSelectedFp(nextFp);
    setStatus(null);
    setError(null);
    setDraft('');
  };

  const onSend = async () => {
    setError(null);
    setStatus(null);
    const body = boundDisplayText(draft, NOTES_BOUNDS.body);
    if (!body) {
      setError(NOTES_COPY.emptyBody);
      return;
    }
    if (!selected) {
      setError(rows.length === 0 ? NOTES_COPY.noSendableContacts : NOTES_COPY.noContactSelected);
      return;
    }
    if (!sender) {
      setError(NOTES_COPY.identityKeysMissing);
      return;
    }
    if (!sender.canonical) {
      setError(NOTES_COPY.needCanonical);
      return;
    }
    setBusy(true);
    try {
      const existing = threads.find(
        (t) => t.kind === 'direct' && t.participants.some((p) => p.fingerprint === selected.fingerprint),
      );
      const result = await sendNoteFromInbox({
        sender,
        peerFingerprint: selected.fingerprint,
        peerPublicKeyArmored: selected.publicKeyArmored,
        body,
        threadId: existing?.thread_id,
      });
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setDraft('');
      setActiveThreadId(result.thread_id);
      if (!result.deposited) {
        setFailedIds((prev) => ({ ...prev, [result.note_id]: true }));
        setStatus(NOTES_COPY.notSent);
      } else {
        setStatus(NOTES_COPY.sentUnconfirmed);
      }
      emitNoteArrival({ note_id: result.note_id, thread_id: result.thread_id });
      await loadThreads();
      await loadNotes(result.thread_id);
    } finally {
      setBusy(false);
    }
  };

  const bubbleStatus = (note: NoteRecord): NoteBubbleStatus => {
    if (note.direction !== 'outbound') return 'inbound';
    if (failedIds[note.note_id]) return 'not-sent';
    return outboundStatus(true);
  };

  return (
    <section
      data-testid="notes-inbox"
      style={{
        ...solarGlass,
        maxWidth: 720,
        margin: '0 auto',
        padding: 24,
        fontFamily: E.fontSans,
        color: E.text,
      }}
    >
      <h2
        style={{
          fontFamily: E.fontSans,
          fontSize: 18,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          color: E.accent,
          margin: '0 0 8px',
        }}
      >
        {NOTES_COPY.tabLabel}
      </h2>
      <p
        data-testid="notes-heading"
        style={{ margin: '0 0 8px', fontSize: 16, color: E.text, lineHeight: 1.4 }}
      >
        {NOTES_COPY.heading}
      </p>
      <p style={{ margin: '0 0 12px', fontSize: 14, color: E.muted, lineHeight: 1.5 }}>
        {NOTES_COPY.whatItIs}
      </p>
      <p style={{ margin: '0 0 8px', fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
        {NOTES_COPY.sending}
      </p>
      <p style={{ margin: '0 0 8px', fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
        {NOTES_COPY.sendingWait}
      </p>
      <p data-testid="notes-receiving" style={{ margin: '0 0 20px', fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
        {NOTES_COPY.receiving}
      </p>

      {!sender && fp ? (
        <p role="alert" style={{ color: E.danger, fontSize: 13, margin: '0 0 16px' }}>
          {NOTES_COPY.identityKeysMissing}
        </p>
      ) : null}

      {sender && !sender.canonical ? (
        <p data-testid="notes-need-canonical" role="alert" style={{ color: E.danger, fontSize: 13, margin: '0 0 16px' }}>
          {NOTES_COPY.needCanonical}
        </p>
      ) : null}

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(0, 1fr)',
          gap: 16,
        }}
      >
        <div>
          <p
            style={{
              margin: '0 0 8px',
              fontSize: 12,
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              color: E.muted,
            }}
          >
            {NOTES_COPY.inboxLabel}
          </p>
          {threads.length === 0 ? (
            <p data-testid="notes-inbox-empty" style={{ color: E.muted, fontSize: 13, margin: '0 0 12px' }}>
              {NOTES_COPY.inboxEmpty}
            </p>
          ) : (
            <ul data-testid="notes-thread-list" style={{ listStyle: 'none', margin: '0 0 16px', padding: 0 }}>
              {threads.map((t) => {
                const peer = threadPeerFp(t, fp);
                const active = t.thread_id === activeThreadId;
                return (
                  <li key={t.thread_id}>
                    <button
                      type="button"
                      data-testid={`notes-thread-${t.thread_id}`}
                      onClick={() => onPickContact(peer)}
                      style={{
                        width: '100%',
                        textAlign: 'left',
                        fontFamily: E.fontSans,
                        fontSize: 14,
                        color: E.text,
                        background: active
                          ? 'color-mix(in srgb, var(--se-accent) 14%, transparent)'
                          : 'transparent',
                        border: `1px solid ${active ? E.borderLit : E.border}`,
                        borderRadius: 10,
                        padding: '10px 12px',
                        marginBottom: 8,
                        cursor: 'pointer',
                      }}
                    >
                      {threadLabel(t, rows, fp)}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        <label
          style={{
            display: 'block',
            marginBottom: 8,
            fontSize: 12,
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            color: E.muted,
          }}
        >
          {NOTES_COPY.pickerLabel}
          <select
            data-testid="notes-contact-picker"
            value={selectedFp}
            onChange={(e) => onPickContact(e.target.value)}
            disabled={rows.length === 0}
            style={{ ...fieldStyle, marginTop: 8, color: E.text }}
          >
            <option value="">
              {rows.length === 0 ? NOTES_COPY.noSendableContacts : NOTES_COPY.pickerPlaceholder}
            </option>
            {rows.map((c) => (
              <option key={c.fingerprint} value={c.fingerprint}>
                {c.name} · {formatFingerprintShort(c.fingerprint)}
              </option>
            ))}
          </select>
        </label>

        {rows.length === 0 ? (
          <p data-testid="notes-empty-book" style={{ color: E.danger, fontSize: 13, margin: '0 0 8px' }}>
            {NOTES_COPY.noSendableContacts}
          </p>
        ) : null}

        <div data-testid="notes-timeline" style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: '36vh', overflowY: 'auto' }}>
          {notes.map((n) => {
            const outbound = n.direction === 'outbound';
            const label = statusLabel(bubbleStatus(n));
            return (
              <article
                key={n.note_id}
                data-testid={`notes-bubble-${n.note_id}`}
                data-direction={n.direction}
                style={{
                  alignSelf: outbound ? 'flex-end' : 'flex-start',
                  maxWidth: '88%',
                  padding: '10px 12px',
                  borderRadius: 14,
                  border: `1px solid ${outbound ? E.borderLit : E.border}`,
                  background: outbound
                    ? 'color-mix(in srgb, var(--se-accent) 10%, transparent)'
                    : 'rgba(30,20,10,.45)',
                }}
              >
                <p style={{ margin: '0 0 6px', whiteSpace: 'pre-wrap', fontSize: 14 }}>
                  {boundDisplayText(n.body, NOTES_BOUNDS.body)}
                </p>
                {label ? (
                  <p data-testid="notes-sent-status" style={{ margin: 0, fontSize: 11, color: E.muted }}>
                    {label}
                  </p>
                ) : null}
              </article>
            );
          })}
          {activeThreadId && notes.length === 0 ? (
            <p data-testid="notes-thread-empty" style={{ color: E.muted, fontSize: 13 }}>
              {NOTES_COPY.threadEmpty}
            </p>
          ) : null}
        </div>

        <label
          style={{
            display: 'block',
            fontSize: 12,
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            color: E.muted,
          }}
        >
          {NOTES_COPY.composeLabel}
          <textarea
            data-testid="notes-compose"
            value={draft}
            maxLength={NOTES_BOUNDS.body}
            placeholder={NOTES_COPY.composePlaceholder}
            onChange={(e) => setDraft(e.target.value)}
            style={{ ...areaStyle, marginTop: 8 }}
          />
        </label>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginTop: 4 }}>
          <button
            type="button"
            data-testid="notes-send-btn"
            onClick={() => void onSend()}
            disabled={busy || !sender?.canonical || rows.length === 0}
            style={{ ...primaryBtn, opacity: busy || !sender?.canonical || rows.length === 0 ? 0.6 : 1 }}
          >
            {busy ? NOTES_COPY.sendingAction : NOTES_COPY.sendAction}
          </button>
        </div>

        {error ? (
          <p data-testid="notes-error" role="alert" style={{ color: E.danger, fontSize: 13, margin: 0 }}>
            {error}
          </p>
        ) : null}
        {status ? (
          <p data-testid="notes-send-status" style={{ color: E.ok, fontSize: 13, margin: 0 }}>
            {status}
          </p>
        ) : null}
      </div>
    </section>
  );
}
