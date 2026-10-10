'use client';

/**
 * Thread Field — Chat window. People rail + ember conversation.
 * Calls fleet sendNoteToPeer / listThreads / listNotesForThread. Does not reimplement crypto.
 * Receive persist is already in the app-shell live-book poll; this glass re-reads the store.
 */

import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
} from 'react';
import { getAllContacts } from '@/lib/identity/client-store';
import { normalizeFingerprintHex } from '@/lib/identity/fingerprint';
import { subscribeContactChanges } from '@/lib/contacts/contact-events';
import {
  initNotesStore,
  isNotesStoreUnlocked,
  listNotesForThread,
  listThreads,
  type NoteRecord,
  type NoteThread,
} from '@/lib/messaging';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { FirstVisitHint } from '@/components/ui/FirstVisitHint';
import { IdentitySeal } from '@/components/identity/IdentitySeal';
import { emitNoteArrival, subscribeNoteArrivals } from '@/lib/notes/note-events';
import { toNoteableContacts, type ContactRow } from './notes-contacts';
import { NOTES_BOUNDS, NOTES_COPY } from './notes-copy';
import {
  displayNameFor,
  filterFieldPeople,
  formatNoteClock,
  formatNoteDay,
  mergeFieldPeople,
  previewLine,
  sortFieldPeople,
  type FieldName,
} from './notes-field';
import { loadOwnerNoteSender, type OwnerNoteSender } from './notes-keys';
import { sendNoteFromInbox } from './notes-send';
import { outboundStatus, statusLabel, type NoteBubbleStatus } from './notes-status';
import { boundDisplayText, formatFingerprintShort } from './notes-text';

type Props = {
  identity: {
    identity?: { fingerprint?: string; name?: string; public_key?: string };
    post_quantum?: { kem_public_key?: string; sig_public_key?: string };
  } | null;
  /** Galaxy star hop — open this peer's conversation. */
  focusFingerprint?: string;
  /** Display name from the star sheet (book may not have a key-bound fingerprint). */
  focusName?: string;
  /** Thread name hop — parent switches to Galaxy and focuses this star. */
  onOpenGalaxy?: (peer: { fingerprint: string; name: string }) => void;
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
  minHeight: 56,
  maxHeight: 160,
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

function bookNames(records: ContactRow[]): FieldName[] {
  const out: FieldName[] = [];
  const seen = new Set<string>();
  for (const row of records) {
    const fingerprint = normalizeFingerprintHex(
      String(row.fingerprint || row.peer_fingerprint || row.metadata?.sample_fingerprint || ''),
    );
    if (fingerprint.length < 16 || seen.has(fingerprint)) continue;
    seen.add(fingerprint);
    out.push({
      fingerprint,
      name: boundDisplayText(row.name || row.peer_name) || formatFingerprintShort(fingerprint),
    });
  }
  return out;
}

export function NotesInbox({ identity, focusFingerprint, focusName, onOpenGalaxy }: Props) {
  const fp = identity?.identity?.fingerprint || '';
  const [book, setBook] = useState<ContactRow[]>([]);
  const [threads, setThreads] = useState<NoteThread[]>([]);
  const [notes, setNotes] = useState<NoteRecord[]>([]);
  const [previews, setPreviews] = useState<Record<string, string>>({});
  const [selectedFp, setSelectedFp] = useState('');
  const [activeThreadId, setActiveThreadId] = useState<string | null>(null);
  const [draft, setDraft] = useState('');
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [storeReady, setStoreReady] = useState(false);
  const [sender, setSender] = useState<OwnerNoteSender | null>(null);
  const [failedIds, setFailedIds] = useState<Record<string, true>>({});
  const [mobilePane, setMobilePane] = useState<'people' | 'thread'>('people');
  const [query, setQuery] = useState('');
  const timelineRef = useRef<HTMLDivElement | null>(null);
  const previewSig = useRef('');

  const rows = useMemo(() => toNoteableContacts(book), [book]);
  const names = useMemo(() => bookNames(book), [book]);
  const sendable = useMemo(() => new Set(rows.map((r) => r.fingerprint)), [rows]);
  const wantFocus = normalizeFingerprintHex(focusFingerprint || '');

  const loadBook = useCallback(async () => {
    if (!fp) return;
    try {
      const records = await getAllContacts(fp);
      setBook(records as ContactRow[]);
    } catch {
      setBook([]);
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

  useEffect(() => {
    if (wantFocus.length < 16) return;
    setSelectedFp(wantFocus);
    setMobilePane('thread');
    setStatus(null);
    setError(null);
  }, [wantFocus]);

  useEffect(() => {
    if (!storeReady || threads.length === 0) {
      if (threads.length === 0) setPreviews({});
      return;
    }
    const sig = threads.map((t) => `${t.thread_id}:${t.last_activity_at}`).join('|');
    if (sig === previewSig.current) return;
    previewSig.current = sig;
    let cancelled = false;
    void (async () => {
      const next: Record<string, string> = {};
      for (const thread of threads) {
        try {
          const list = await listNotesForThread(thread.thread_id);
          const last = list[list.length - 1];
          if (last) next[thread.thread_id] = previewLine(last.body);
        } catch {
          /* skip unread-less preview */
        }
      }
      if (!cancelled) setPreviews(next);
    })();
    return () => {
      cancelled = true;
    };
  }, [storeReady, threads]);

  useLayoutEffect(() => {
    const el = timelineRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [notes, activeThreadId]);

  const people = useMemo(
    () =>
      mergeFieldPeople({
        ownerFp: fp,
        threads,
        names,
        sendable,
        previews,
        extraFp: selectedFp || wantFocus || undefined,
        extraName: focusName,
      }),
    [fp, threads, names, sendable, previews, selectedFp, wantFocus, focusName],
  );

  const peerName = displayNameFor(selectedFp, names, focusName);
  const visiblePeople = useMemo(
    () => filterFieldPeople(sortFieldPeople(people), query),
    [people, query],
  );

  const onPickContact = (nextFp: string) => {
    setSelectedFp(nextFp);
    setMobilePane(nextFp ? 'thread' : 'people');
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
        ownerIdentity: identity,
        peerFingerprint: selected.fingerprint,
        peerPublicKeyArmored: selected.publicKeyArmored,
        peerPqKemPublicKey: selected.pqKemPublicKey,
        peerPqSigPublicKey: selected.pqSigPublicKey,
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

  const onComposeKey = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key !== 'Enter' || e.shiftKey) return;
    e.preventDefault();
    if (!busy) void onSend();
  };

  const bubbleStatus = (note: NoteRecord): NoteBubbleStatus => {
    if (note.direction !== 'outbound') return 'inbound';
    if (failedIds[note.note_id]) return 'not-sent';
    return outboundStatus(true);
  };

  const sendDisabled = busy || !sender?.canonical || rows.length === 0 || !selected;

  return (
    <section data-testid="notes-inbox" className="notes-field-shell" aria-label={NOTES_COPY.tabLabel}>
      <h2 className="sr-only">{NOTES_COPY.heading}</h2>

      {!sender && fp ? (
        <p role="alert" style={{ color: E.danger, fontSize: 13, margin: '0 0 12px' }}>
          {NOTES_COPY.identityKeysMissing}
        </p>
      ) : null}

      {sender && !sender.canonical ? (
        <p data-testid="notes-need-canonical" role="alert" style={{ color: E.danger, fontSize: 13, margin: '0 0 12px' }}>
          {NOTES_COPY.needCanonical}
        </p>
      ) : null}

      <div className="notes-field" data-testid="notes-field" data-pane={mobilePane}>
        <aside className="notes-field-people">
          <p
            style={{
              margin: 0,
              fontSize: 11,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              color: E.muted,
            }}
          >
            {NOTES_COPY.fieldPeople}
          </p>

          <label
            style={{
              display: 'block',
              fontSize: 11,
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              color: E.muted,
            }}
          >
            {NOTES_COPY.searchLabel}
            <input
              data-testid="notes-search"
              type="search"
              value={query}
              maxLength={NOTES_BOUNDS.name}
              placeholder={NOTES_COPY.searchPlaceholder}
              onChange={(e) => setQuery(e.target.value)}
              style={{ ...fieldStyle, marginTop: 8 }}
            />
          </label>

          {threads.length === 0 && people.length === 0 ? (
            <p data-testid="notes-inbox-empty" style={{ color: E.muted, fontSize: 13, margin: 0 }}>
              {NOTES_COPY.inboxEmpty}
            </p>
          ) : visiblePeople.length === 0 ? (
            <p data-testid="notes-search-empty" style={{ color: E.muted, fontSize: 13, margin: 0 }}>
              {NOTES_COPY.searchEmpty}
            </p>
          ) : (
            <ul data-testid="notes-thread-list" className="notes-chat-list">
              {visiblePeople.map((person) => {
                const active = person.fingerprint === selectedFp;
                return (
                  <li key={person.fingerprint}>
                    <button
                      type="button"
                      className="notes-person"
                      data-active={active ? 'true' : 'false'}
                      data-testid={person.threadId ? `notes-thread-${person.threadId}` : `notes-person-${person.fingerprint}`}
                      onClick={() => onPickContact(person.fingerprint)}
                    >
                      <span className="notes-hex" aria-hidden="true">
                        <IdentitySeal fingerprint={person.fingerprint} size={26} />
                      </span>
                      <span style={{ minWidth: 0, flex: 1 }}>
                        <span style={{ display: 'block', fontSize: 15, fontWeight: 600, color: E.text }}>
                          {person.name}
                        </span>
                        <span style={{ display: 'block', fontSize: 13, color: E.dim, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {person.preview || NOTES_COPY.fieldPreviewEmpty}
                        </span>
                      </span>
                      {person.lastAt ? (
                        <span style={{ fontSize: 11, color: E.dim, flexShrink: 0 }}>
                          {formatNoteClock(person.lastAt)}
                        </span>
                      ) : null}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}

          <label
            style={{
              display: 'block',
              fontSize: 11,
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              color: E.muted,
            }}
          >
            {NOTES_COPY.pickerLabel}
            <select
              data-testid="notes-contact-picker"
              value={selected && sendable.has(selected.fingerprint) ? selected.fingerprint : ''}
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
            <p data-testid="notes-empty-book" style={{ color: E.danger, fontSize: 13, margin: 0 }}>
              {NOTES_COPY.noSendableContacts}
            </p>
          ) : null}
        </aside>

        <div className="notes-field-thread">
          <div className="notes-field-thread-head">
            <button
              type="button"
              data-testid="notes-field-back"
              className="ember-act notes-field-back"
              onClick={() => setMobilePane('people')}
              style={{
                fontFamily: E.fontSans,
                fontSize: 12,
                letterSpacing: '0.06em',
                textTransform: 'uppercase',
                color: E.accent,
                background: 'transparent',
                border: `1px solid ${E.border}`,
                borderRadius: 999,
                padding: '6px 10px',
                cursor: 'pointer',
              }}
            >
              {NOTES_COPY.fieldBack}
            </button>
            {selectedFp ? (
              <button
                type="button"
                className="notes-field-peer-hop"
                data-testid="notes-field-peer"
                aria-label={`Show ${peerName} in Galaxy`}
                onClick={() => onOpenGalaxy?.({ fingerprint: selectedFp, name: peerName })}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  minWidth: 0,
                  flex: 1,
                  margin: 0,
                  padding: 0,
                  border: 'none',
                  background: 'transparent',
                  cursor: onOpenGalaxy ? 'pointer' : 'default',
                  textAlign: 'left',
                  font: 'inherit',
                  color: E.text,
                }}
              >
                <span className="notes-hex" aria-hidden="true">
                  <IdentitySeal fingerprint={selectedFp} size={32} />
                </span>
                <span style={{ minWidth: 0 }}>
                  <span style={{ display: 'block', fontSize: 16, fontWeight: 600, color: 'inherit' }}>
                    {peerName}
                  </span>
                  <span style={{ display: 'block', marginTop: 3, fontSize: 11, color: E.dim, fontFamily: E.fontMono }}>
                    {formatFingerprintShort(selectedFp)}
                  </span>
                </span>
              </button>
            ) : (
              <p data-testid="notes-field-peer" style={{ margin: 0, fontSize: 14, color: E.muted }}>
                {NOTES_COPY.fieldPick}
              </p>
            )}
          </div>

          <div
            ref={timelineRef}
            data-testid="notes-timeline"
            className="notes-field-timeline"
          >
            {notes.map((n, i) => {
              const outbound = n.direction === 'outbound';
              const label = statusLabel(bubbleStatus(n));
              const day = formatNoteDay(n.sent_at);
              const prevDay = i > 0 ? formatNoteDay(notes[i - 1].sent_at) : '';
              return (
                <div key={n.note_id} style={{ display: 'contents' }}>
                  {day && day !== prevDay ? (
                    <p className="notes-day">{day}</p>
                  ) : null}
                  <article
                    className="notes-bubble"
                    data-testid={`notes-bubble-${n.note_id}`}
                    data-direction={n.direction}
                  >
                    <p style={{ margin: '0 0 6px', whiteSpace: 'pre-wrap', fontSize: 14 }}>
                      {boundDisplayText(n.body, NOTES_BOUNDS.body)}
                    </p>
                    <p style={{ margin: 0, fontSize: 11, color: E.dim, display: 'flex', gap: 8, justifyContent: outbound ? 'flex-end' : 'flex-start' }}>
                      <span>{formatNoteClock(n.sent_at)}</span>
                      {label ? <span data-testid="notes-sent-status">{label}</span> : null}
                    </p>
                  </article>
                </div>
              );
            })}
            {activeThreadId && notes.length === 0 ? (
              <p data-testid="notes-thread-empty" style={{ color: E.muted, fontSize: 13 }}>
                {NOTES_COPY.threadEmpty}
              </p>
            ) : null}
            {!selectedFp ? (
              <p style={{ color: E.dim, fontSize: 13, margin: 'auto 0', textAlign: 'center' }}>
                {NOTES_COPY.fieldPick}
              </p>
            ) : null}
          </div>

          <div className="notes-field-compose">
            <label
              style={{
                display: 'block',
                fontSize: 11,
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
                onKeyDown={onComposeKey}
                style={{ ...areaStyle, marginTop: 8 }}
              />
            </label>
            <div style={{ margin: '6px 0 8px' }}>
              <FirstVisitHint id="chat-compose" label="Send keys">
                {NOTES_COPY.composeHint}
              </FirstVisitHint>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center' }}>
              <button
                type="button"
                className="ember-act"
                data-flash={busy ? 'busy' : undefined}
                data-testid="notes-send-btn"
                onClick={() => void onSend()}
                disabled={sendDisabled}
                style={{ ...primaryBtn, opacity: sendDisabled ? 0.6 : 1 }}
              >
                {busy ? NOTES_COPY.sendingAction : NOTES_COPY.sendAction}
              </button>
              {selectedFp && !selected ? (
                <p style={{ margin: 0, fontSize: 12, color: E.muted }}>
                  {NOTES_COPY.contactNotSendable}
                </p>
              ) : null}
            </div>
            {error ? (
              <p data-testid="notes-error" role="alert" style={{ color: E.danger, fontSize: 13, margin: '10px 0 0' }}>
                {error}
              </p>
            ) : null}
            {status ? (
              <p data-testid="notes-send-status" style={{ color: E.ok, fontSize: 13, margin: '10px 0 0' }}>
                {status}
              </p>
            ) : null}
          </div>
        </div>
      </div>
    </section>
  );
}
