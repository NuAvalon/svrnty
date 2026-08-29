'use client';

// Notes PWA (/msg) — Phase 3 rung 1 · Hive aesthetic (mobile-first).
// Claim discipline: NOTES between admitted contacts — not "messaging".
// Visual language: sovereign YOU node ↔ hex hive of admitted keys (Apollo Hive glimpse).
// No trading/berries mechanics — only the network geometry + palette.

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  getActiveFingerprint,
  getAllContacts,
  hasEncryptedKeys,
  initSessionKey,
  isSessionUnlocked,
  listIdentities,
  loadIdentity,
  loadKey,
  lockSession,
  type ContactRecord,
} from '@/lib/identity/client-store';
import {
  initNotesStore,
  isNotesStoreUnlocked,
  lockNotesStore,
  listThreads,
  listNotesForThread,
  sendNoteToPeer,
  putThread,
  type NoteThread,
  type NoteRecord,
} from '@/lib/messaging';

type Gate = 'loading' | 'locked' | 'ready' | 'empty';
type Phase = 'select' | 'compose' | 'sealed';

export default function NotesPage() {
  const [gate, setGate] = useState<Gate>('loading');
  const [passphrase, setPassphrase] = useState('');
  const [unlockError, setUnlockError] = useState('');
  const [identityName, setIdentityName] = useState('');
  const [fingerprint, setFingerprint] = useState('');
  const [contacts, setContacts] = useState<ContactRecord[]>([]);
  const [threads, setThreads] = useState<NoteThread[]>([]);
  const [activeThreadId, setActiveThreadId] = useState<string | null>(null);
  const [notes, setNotes] = useState<NoteRecord[]>([]);
  const [peerFp, setPeerFp] = useState('');
  const [draft, setDraft] = useState('');
  const [status, setStatus] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [phase, setPhase] = useState<Phase>('select');

  const refresh = useCallback(async (fp: string) => {
    const [c, t] = await Promise.all([getAllContacts(fp), listThreads()]);
    setContacts(c);
    setThreads(t);
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const ids = await listIdentities();
        if (!ids.length) {
          setGate('empty');
          return;
        }
        const fp = (await getActiveFingerprint()) || ids[0].fingerprint;
        const id = await loadIdentity(fp);
        setFingerprint(fp);
        setIdentityName(id?.data?.identity?.name || id?.data?.identity?.display_name || 'You');
        if (isSessionUnlocked() && isNotesStoreUnlocked()) {
          setGate('ready');
          await refresh(fp);
        } else {
          setGate('locked');
        }
      } catch {
        setGate('empty');
      }
    })();
  }, [refresh]);

  useEffect(() => {
    if (!activeThreadId || gate !== 'ready') return;
    listNotesForThread(activeThreadId).then(setNotes).catch(() => setNotes([]));
  }, [activeThreadId, gate]);

  const hiveNodes = useMemo(() => {
    // Prefer contacts that already have a thread, then the rest — hex hive of admitted keys only.
    const withThread = new Set(
      threads.flatMap((t) => t.participants.map((p) => p.fingerprint)),
    );
    const sorted = [...contacts].sort((a, b) => {
      const at = withThread.has(a.fingerprint) ? 0 : 1;
      const bt = withThread.has(b.fingerprint) ? 0 : 1;
      return at - bt || (a.name || '').localeCompare(b.name || '');
    });
    return sorted.slice(0, 18); // keep the hive readable on a phone
  }, [contacts, threads]);

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setUnlockError('');
    try {
      if (!(await hasEncryptedKeys(fingerprint))) {
        setUnlockError('No encrypted keys on this device.');
        return;
      }
      await initSessionKey(passphrase);
      await loadKey(fingerprint);
      await initNotesStore(passphrase);
      setPassphrase('');
      setGate('ready');
      await refresh(fingerprint);
    } catch {
      lockSession();
      lockNotesStore();
      setUnlockError('Unlock failed — check passphrase.');
    }
  };

  const selectPeer = (fp: string) => {
    setPeerFp(fp);
    setPhase('compose');
    setStatus(null);
    const existing = threads.find(
      (t) => t.kind === 'direct' && t.participants.some((p) => p.fingerprint === fp),
    );
    setActiveThreadId(existing?.thread_id ?? null);
  };

  const handleSend = async () => {
    if (!draft.trim() || !peerFp) return;
    const contact = contacts.find((c) => c.fingerprint === peerFp);
    if (!contact?.public_key) {
      setStatus('They need a public key in your book before a note can seal.');
      return;
    }
    setSending(true);
    setStatus(null);
    try {
      const key = await loadKey(fingerprint);
      if (!key) throw new Error('Session locked');
      const thread = threads.find(
        (t) => t.kind === 'direct' && t.participants.some((p) => p.fingerprint === peerFp),
      );
      const result = await sendNoteToPeer({
        sender: { fingerprint, participant_kind: 'human' },
        peerFingerprint: peerFp,
        peerPublicKeyArmored: contact.public_key,
        body: draft.trim(),
        threadId: thread?.thread_id,
      });
      const tlist = await listThreads();
      const updated = tlist.find((t) => t.thread_id === result.thread_id);
      if (updated) {
        updated.participants = [
          {
            fingerprint: peerFp,
            kind: contact.metadata?.identity_type === 'agent' ? 'agent' : 'human',
            display_name: contact.name || peerFp.slice(0, 8),
          },
        ];
        await putThread(updated);
      }
      setDraft('');
      setActiveThreadId(result.thread_id);
      setPhase('sealed');
      setStatus(result.deposited ? 'Sealed · queued to their mailbox' : 'Saved locally · mailbox deposit failed');
      await refresh(fingerprint);
      setNotes(await listNotesForThread(result.thread_id));
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Send failed');
    } finally {
      setSending(false);
    }
  };

  const selected = contacts.find((c) => c.fingerprint === peerFp);
  const active = threads.find((t) => t.thread_id === activeThreadId) || null;

  return (
    <div className="hive">
      <HiveStyles />
      <div className="hive-stage">
        {gate === 'loading' && (
          <p className="hive-muted center">Igniting…</p>
        )}

        {gate === 'empty' && (
          <div className="hive-lock">
            <HexMark label="YOU" sub="Sovereign" tone="you" />
            <h1>Notes</h1>
            <p className="hive-lede">No identity on this device yet.</p>
            <Link className="hive-link" href="/">Create identity →</Link>
          </div>
        )}

        {gate === 'locked' && (
          <div className="hive-lock">
            <p className="hive-eyebrow">Notes · sealed · ephemeral-by-default</p>
            <HexMark label="YOU" sub="Sovereign" tone="you" large />
            <h1>{identityName}</h1>
            <p className="hive-lede">
              Unlock to reach the hive of contacts you have admitted. Strangers cannot write here.
            </p>
            <form onSubmit={handleUnlock} className="hive-form">
              <input
                type="password"
                placeholder="Unlock passphrase"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                autoComplete="current-password"
              />
              {unlockError && <p className="hive-err">{unlockError}</p>}
              <button type="submit">Unlock notes</button>
            </form>
            <Link className="hive-link" href="/">← Trust book</Link>
          </div>
        )}

        {gate === 'ready' && (
          <>
            <header className="hive-top">
              <Link className="hive-chip" href="/">Book</Link>
              <div className="hive-top-title">
                <p className="hive-eyebrow">The Hive · Notes</p>
                <h1>Admitted only</h1>
              </div>
              <button
                type="button"
                className="hive-chip"
                onClick={() => {
                  setPhase('select');
                  setPeerFp('');
                  setActiveThreadId(null);
                  setStatus(null);
                }}
              >
                Reset
              </button>
            </header>

            <Steps phase={phase} />

            {/* Spatial hive — mobile-first: hex cluster above, YOU below */}
            <div className="hive-field" aria-label="Admitted contacts">
              <div className="hive-cluster">
                {hiveNodes.length === 0 ? (
                  <p className="hive-muted center">Add contacts in the book to grow the hive.</p>
                ) : (
                  hiveNodes.map((c, i) => {
                    const isAgent = c.metadata?.identity_type === 'agent';
                    const selectedNode = c.fingerprint === peerFp;
                    const hasThread = threads.some((t) =>
                      t.participants.some((p) => p.fingerprint === c.fingerprint),
                    );
                    return (
                      <button
                        key={c.id}
                        type="button"
                        className={[
                          'hex-node',
                          selectedNode ? 'is-selected' : '',
                          hasThread ? 'has-thread' : '',
                          isAgent ? 'is-agent' : '',
                        ].join(' ')}
                        style={{ ['--i' as string]: String(i) }}
                        onClick={() => selectPeer(c.fingerprint)}
                        title={c.name || c.fingerprint}
                      >
                        <span className="hex-shape" />
                        <span className="hex-label">{(c.name || '?').slice(0, 10)}</span>
                        <span className="hex-sub">{isAgent ? 'Agent' : hasThread ? 'Thread' : 'Known'}</span>
                      </button>
                    );
                  })
                )}
              </div>

              <div className="hive-spine" aria-hidden />

              <div className="hive-you">
                <HexMark label="YOU" sub="Sovereign" tone="you" />
                <p className="hive-you-name">{identityName}</p>
              </div>
            </div>

            {/* Compose sheet — rises when a hex is selected */}
            {phase !== 'select' && selected && (
              <section className="hive-sheet" data-testid="notes-compose">
                <div className="sheet-head">
                  <div>
                    <p className="hive-eyebrow">{selected.metadata?.identity_type === 'agent' ? 'Agent' : 'Human'}</p>
                    <h2>{selected.name || selected.fingerprint.slice(0, 12)}</h2>
                  </div>
                  <button type="button" className="hive-chip" onClick={() => setPhase('select')}>
                    Close
                  </button>
                </div>

                <div className="timeline" data-testid="notes-timeline">
                  {notes.map((n) => (
                    <article key={n.note_id} className={n.direction === 'outbound' ? 'bubble out' : 'bubble in'}>
                      <p>{n.body}</p>
                      <time>{new Date(n.sent_at).toLocaleString()}</time>
                    </article>
                  ))}
                  {active && notes.length === 0 && (
                    <p className="hive-muted">No notes in this thread yet.</p>
                  )}
                </div>

                <div className="composer">
                  <textarea
                    rows={3}
                    placeholder="Write a sealed note…"
                    value={draft}
                    onChange={(e) => {
                      setDraft(e.target.value);
                      if (phase === 'sealed') setPhase('compose');
                    }}
                  />
                  <button
                    type="button"
                    className="seal-btn"
                    disabled={sending || !draft.trim()}
                    onClick={handleSend}
                  >
                    {sending ? 'Sealing…' : 'Seal & send'}
                  </button>
                  {status && <p className="hive-status">{status}</p>}
                </div>
              </section>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function Steps({ phase }: { phase: Phase }) {
  const items: { id: Phase; label: string }[] = [
    { id: 'select', label: 'Select' },
    { id: 'compose', label: 'Seal' },
    { id: 'sealed', label: 'Queued' },
  ];
  const idx = items.findIndex((x) => x.id === phase);
  return (
    <ol className="hive-steps" aria-label="Note flow">
      {items.map((item, i) => (
        <li key={item.id} className={i <= idx ? 'on' : ''}>
          <span className="dot" />
          {item.label}
        </li>
      ))}
    </ol>
  );
}

function HexMark({
  label,
  sub,
  tone,
  large,
}: {
  label: string;
  sub: string;
  tone: 'you' | 'hive';
  large?: boolean;
}) {
  return (
    <div className={`hex-mark ${tone} ${large ? 'large' : ''}`}>
      <span className="hex-shape" />
      <span className="hex-label">{label}</span>
      <span className="hex-sub">{sub}</span>
    </div>
  );
}

function HiveStyles() {
  return (
    <style>{`
      .hive {
        --bg0: #030712;
        --bg1: #0a1630;
        --cyan: #5ee7ff;
        --cyan-dim: rgba(94, 231, 255, 0.35);
        --gold: #e8c547;
        --gold-dim: rgba(232, 197, 71, 0.35);
        --cream: #e8eef8;
        --muted: rgba(200, 214, 235, 0.45);
        --err: #ff8f9a;
        --ok: #7dffc8;
        min-height: 100dvh;
        color: var(--cream);
        font-family: var(--font-sans), 'Space Grotesk', system-ui, sans-serif;
        background:
          radial-gradient(ellipse 80% 55% at 50% 18%, rgba(40, 90, 160, 0.28), transparent 60%),
          radial-gradient(ellipse 70% 50% at 50% 100%, rgba(20, 50, 100, 0.35), transparent 55%),
          linear-gradient(180deg, var(--bg1), var(--bg0));
        position: relative;
        overflow-x: hidden;
      }
      .hive::before {
        content: '';
        position: absolute;
        inset: 0;
        background-image: radial-gradient(rgba(94, 231, 255, 0.09) 1px, transparent 1px);
        background-size: 28px 28px;
        mask-image: radial-gradient(ellipse at 50% 40%, black 20%, transparent 70%);
        pointer-events: none;
        opacity: 0.45;
      }
      .hive-stage {
        position: relative;
        z-index: 1;
        max-width: 480px;
        margin: 0 auto;
        padding: 16px 16px 28px;
        min-height: 100dvh;
        display: flex;
        flex-direction: column;
      }
      .hive-eyebrow {
        font-family: var(--font-mono), monospace;
        font-size: 10px;
        letter-spacing: 1.6px;
        text-transform: uppercase;
        color: var(--gold);
        margin: 0 0 6px;
        opacity: 0.85;
      }
      .hive-top {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 10px;
        margin-bottom: 10px;
      }
      .hive-top-title { text-align: center; flex: 1; }
      .hive-top h1, .hive-lock h1 {
        font-family: var(--font-serif), 'Cormorant Garamond', serif;
        font-weight: 400;
        font-size: clamp(1.75rem, 7vw, 2.25rem);
        margin: 0;
        letter-spacing: 0.02em;
      }
      .hive-lede {
        color: var(--muted);
        line-height: 1.45;
        font-size: 0.92rem;
        margin: 10px 0 18px;
        max-width: 22rem;
      }
      .hive-muted { color: var(--muted); font-size: 0.85rem; }
      .hive-err { color: var(--err); font-size: 0.85rem; }
      .hive-status { color: var(--ok); font-size: 0.8rem; margin: 8px 0 0; text-align: center; }
      .center { text-align: center; }
      .hive-link {
        color: var(--cyan);
        text-decoration: none;
        font-size: 0.85rem;
        border-bottom: 1px solid var(--cyan-dim);
      }
      .hive-chip {
        font: inherit;
        font-size: 11px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--cream);
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.18);
        border-radius: 999px;
        padding: 8px 12px;
        text-decoration: none;
        cursor: pointer;
      }

      .hive-steps {
        list-style: none;
        display: flex;
        justify-content: center;
        gap: 10px;
        padding: 0;
        margin: 4px 0 18px;
        flex-wrap: wrap;
      }
      .hive-steps li {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 10px;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: rgba(200, 214, 235, 0.35);
      }
      .hive-steps li.on { color: var(--cyan); }
      .hive-steps .dot {
        width: 6px; height: 6px; border-radius: 50%;
        background: currentColor;
        box-shadow: 0 0 8px currentColor;
      }

      .hive-lock {
        flex: 1;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        text-align: center;
        padding: 24px 8px 40px;
        animation: hive-in 0.7s ease-out both;
      }
      .hive-form {
        width: min(100%, 300px);
        display: flex;
        flex-direction: column;
        gap: 10px;
        margin: 8px 0 20px;
      }
      .hive-form input, .composer textarea {
        font: inherit;
        border-radius: 12px;
        border: 1px solid rgba(94, 231, 255, 0.25);
        background: rgba(3, 10, 24, 0.65);
        color: var(--cream);
        padding: 12px 14px;
        box-shadow: inset 0 0 20px rgba(94, 231, 255, 0.04);
      }
      .hive-form button, .seal-btn {
        font: inherit;
        cursor: pointer;
        border-radius: 12px;
        border: 1px solid var(--gold-dim);
        background: linear-gradient(180deg, rgba(232, 197, 71, 0.18), rgba(232, 197, 71, 0.06));
        color: var(--gold);
        padding: 12px 14px;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        font-size: 12px;
        box-shadow: 0 0 24px rgba(232, 197, 71, 0.12);
      }
      .seal-btn:disabled { opacity: 0.4; cursor: not-allowed; }

      .hive-field {
        flex: 1;
        display: flex;
        flex-direction: column;
        align-items: center;
        min-height: 0;
      }
      .hive-cluster {
        display: flex;
        flex-wrap: wrap;
        justify-content: center;
        gap: 10px 8px;
        max-width: 360px;
        padding: 8px 4px 4px;
        animation: hive-in 0.8s ease-out both;
      }
      .hive-spine {
        width: 2px;
        flex: 0 0 36px;
        background: linear-gradient(180deg, var(--gold), var(--cyan));
        box-shadow: 0 0 12px var(--cyan-dim);
        border-radius: 2px;
        margin: 6px 0;
        opacity: 0.85;
      }
      .hive-you {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 6px;
        margin-bottom: 12px;
        animation: hive-in 0.9s ease-out both;
      }
      .hive-you-name {
        margin: 0;
        font-size: 12px;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: var(--muted);
      }

      .hex-node, .hex-mark {
        position: relative;
        width: 72px;
        height: 84px;
        border: none;
        background: transparent;
        color: var(--cream);
        cursor: pointer;
        padding: 0;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        animation: hex-pop 0.55s ease-out both;
        animation-delay: calc(var(--i, 0) * 35ms);
      }
      .hex-mark { cursor: default; width: 88px; height: 100px; }
      .hex-mark.large { width: 110px; height: 124px; }
      .hex-shape {
        position: absolute;
        inset: 8px 6px 22px;
        background: rgba(8, 20, 42, 0.9);
        clip-path: polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%);
        border: none;
        box-shadow:
          0 0 0 1px var(--gold-dim),
          0 0 18px rgba(232, 197, 71, 0.2);
      }
      .hex-mark.you .hex-shape, .hex-node.is-selected .hex-shape {
        box-shadow:
          0 0 0 1.5px var(--cyan),
          0 0 22px rgba(94, 231, 255, 0.45);
        background: rgba(10, 36, 64, 0.95);
      }
      .hex-node.has-thread .hex-shape {
        box-shadow:
          0 0 0 1px var(--gold),
          0 0 16px rgba(232, 197, 71, 0.35);
      }
      .hex-node.is-agent .hex-shape {
        box-shadow:
          0 0 0 1px rgba(125, 255, 200, 0.45),
          0 0 14px rgba(125, 255, 200, 0.2);
      }
      .hex-node.is-selected {
        transform: translateY(-2px) scale(1.06);
      }
      .hex-label {
        position: relative;
        z-index: 1;
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        max-width: 62px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        margin-top: -6px;
      }
      .hex-mark .hex-label { font-size: 13px; letter-spacing: 0.12em; }
      .hex-mark.large .hex-label { font-size: 15px; }
      .hex-sub {
        position: relative;
        z-index: 1;
        font-size: 8px;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: var(--muted);
        margin-top: 2px;
      }
      .hex-mark.you .hex-sub { color: var(--cyan); }

      .hive-sheet {
        margin-top: 8px;
        border: 1px solid rgba(94, 231, 255, 0.22);
        border-radius: 20px 20px 16px 16px;
        background: rgba(4, 12, 28, 0.88);
        box-shadow: 0 -8px 40px rgba(0, 0, 0, 0.45), 0 0 30px rgba(94, 231, 255, 0.08);
        padding: 14px 14px 16px;
        animation: sheet-up 0.35s ease-out both;
        backdrop-filter: blur(10px);
      }
      .sheet-head {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        margin-bottom: 10px;
      }
      .sheet-head h2 {
        margin: 0;
        font-family: var(--font-serif), 'Cormorant Garamond', serif;
        font-weight: 400;
        font-size: 1.35rem;
      }
      .timeline {
        display: flex;
        flex-direction: column;
        gap: 8px;
        max-height: 28vh;
        overflow-y: auto;
        margin-bottom: 12px;
        padding-right: 2px;
      }
      .bubble {
        max-width: 88%;
        padding: 10px 12px;
        border-radius: 14px;
        border: 1px solid rgba(255,255,255,0.08);
        background: rgba(255,255,255,0.03);
      }
      .bubble p { margin: 0 0 6px; white-space: pre-wrap; font-size: 0.92rem; }
      .bubble time {
        font-size: 9px;
        color: var(--muted);
        font-family: var(--font-mono), monospace;
      }
      .bubble.out {
        align-self: flex-end;
        border-color: rgba(94, 231, 255, 0.28);
        background: rgba(94, 231, 255, 0.07);
      }
      .bubble.in {
        align-self: flex-start;
        border-color: rgba(232, 197, 71, 0.22);
        background: rgba(232, 197, 71, 0.05);
      }
      .composer { display: flex; flex-direction: column; gap: 8px; }

      @keyframes hive-in {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
      }
      @keyframes hex-pop {
        from { opacity: 0; transform: scale(0.7); }
        to { opacity: 1; transform: scale(1); }
      }
      @keyframes sheet-up {
        from { opacity: 0; transform: translateY(24px); }
        to { opacity: 1; transform: translateY(0); }
      }
      @media (prefers-reduced-motion: reduce) {
        .hive-lock, .hive-cluster, .hive-you, .hex-node, .hive-sheet { animation: none; }
      }
      @media (min-width: 720px) {
        .hive-stage { max-width: 560px; padding-top: 28px; }
        .timeline { max-height: 36vh; }
      }
    `}</style>
  );
}
