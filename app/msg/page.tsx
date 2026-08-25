'use client';

// Notes PWA surface (/msg) — Phase 3 rung 1.
// Claim discipline: this is NOTES between admitted contacts, not "messaging".
// Ratcheting (FS/PCS) is not present; see docs/MESSAGING_PRIOR_ART.md.

import { useCallback, useEffect, useState } from 'react';
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

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setUnlockError('');
    try {
      if (!(await hasEncryptedKeys(fingerprint))) {
        setUnlockError('No encrypted keys on this device.');
        return;
      }
      await initSessionKey(passphrase);
      await loadKey(fingerprint); // verifies passphrase against wrapped key material
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

  const handleSend = async () => {
    if (!draft.trim() || !peerFp) return;
    const contact = contacts.find((c) => c.fingerprint === peerFp);
    if (!contact?.public_key) {
      setStatus('Contact needs a public key before you can send a note.');
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
      // Fix display name on thread
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
      setStatus(result.deposited ? 'Note sealed and queued to their mailbox.' : 'Saved locally; mailbox deposit failed.');
      await refresh(fingerprint);
      setNotes(await listNotesForThread(result.thread_id));
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Send failed');
    } finally {
      setSending(false);
    }
  };

  if (gate === 'loading') {
    return <Shell><p className="muted">Loading…</p></Shell>;
  }

  if (gate === 'empty') {
    return (
      <Shell>
        <h1>Notes</h1>
        <p className="lede">No identity on this device yet.</p>
        <Link className="cta" href="/">Create an identity first</Link>
      </Shell>
    );
  }

  if (gate === 'locked') {
    return (
      <Shell>
        <p className="eyebrow">Notes · sealed · ephemeral-by-default</p>
        <h1>{identityName}</h1>
        <p className="lede">Unlock to open notes between contacts you have admitted. Strangers cannot write here.</p>
        <form onSubmit={handleUnlock} className="form">
          <input
            type="password"
            placeholder="Unlock passphrase"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            autoComplete="current-password"
          />
          {unlockError && <p className="err">{unlockError}</p>}
          <button type="submit">Unlock notes</button>
        </form>
        <Link className="back" href="/">← Trust book</Link>
      </Shell>
    );
  }

  const active = threads.find((t) => t.thread_id === activeThreadId) || null;

  return (
    <Shell>
      <header className="top">
        <div>
          <p className="eyebrow">Notes · not messaging yet</p>
          <h1>Between contacts</h1>
        </div>
        <Link className="back" href="/">Book</Link>
      </header>
      <p className="lede">
        Only people and agents whose keys you have added can leave a note. No ratchet yet — classical seal, honest scope.
      </p>

      <div className="layout">
        <aside className="pane">
          <h2>Threads</h2>
          {threads.length === 0 && <p className="muted">No threads yet.</p>}
          <ul>
            {threads.map((t) => {
              const label = t.participants.map((p) => p.display_name).join(', ') || t.thread_id.slice(0, 8);
              return (
                <li key={t.thread_id}>
                  <button
                    type="button"
                    className={t.thread_id === activeThreadId ? 'row active' : 'row'}
                    onClick={() => setActiveThreadId(t.thread_id)}
                  >
                    <span>{label}</span>
                    <span className="kind">{t.kind}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        </aside>

        <section className="pane main">
          <h2>{active ? active.participants.map((p) => p.display_name).join(', ') : 'New note'}</h2>

          <div className="composer">
            <label>
              To (admitted contact)
              <select
                value={peerFp}
                onChange={(e) => {
                  setPeerFp(e.target.value);
                  const existing = threads.find(
                    (t) => t.kind === 'direct' && t.participants.some((p) => p.fingerprint === e.target.value),
                  );
                  setActiveThreadId(existing?.thread_id ?? null);
                }}
              >
                <option value="">Select…</option>
                {contacts.map((c) => (
                  <option key={c.id} value={c.fingerprint}>
                    {c.name || c.fingerprint.slice(0, 12)}
                    {c.metadata?.identity_type === 'agent' ? ' · agent' : ''}
                  </option>
                ))}
              </select>
            </label>
            <textarea
              rows={4}
              placeholder="Write a note…"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
            />
            <button type="button" disabled={sending || !draft.trim() || !peerFp} onClick={handleSend}>
              {sending ? 'Sealing…' : 'Seal & send'}
            </button>
            {status && <p className="status">{status}</p>}
          </div>

          <div className="timeline" data-testid="notes-timeline">
            {notes.map((n) => (
              <article key={n.note_id} className={n.direction === 'outbound' ? 'bubble out' : 'bubble in'}>
                <p>{n.body}</p>
                <time>{new Date(n.sent_at).toLocaleString()}</time>
              </article>
            ))}
            {active && notes.length === 0 && <p className="muted">No notes in this thread yet.</p>}
          </div>
        </section>
      </div>
    </Shell>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="notes-root">
      <style>{`
        .notes-root {
          min-height: 100dvh;
          padding: 28px 20px 48px;
          max-width: 960px;
          margin: 0 auto;
          color: #e8e4d9;
          font-family: var(--font-sans), 'Space Grotesk', sans-serif;
          position: relative;
          z-index: 1;
        }
        .eyebrow {
          font-family: var(--font-mono), monospace;
          font-size: 10px;
          letter-spacing: 1.5px;
          text-transform: uppercase;
          color: rgba(200, 168, 78, 0.7);
          margin: 0 0 8px;
        }
        h1 {
          font-family: var(--font-serif), 'Cormorant Garamond', serif;
          font-weight: 400;
          font-size: clamp(2rem, 5vw, 2.75rem);
          margin: 0 0 12px;
          color: #f2efe6;
        }
        h2 {
          font-size: 0.85rem;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          color: rgba(232, 228, 217, 0.55);
          margin: 0 0 12px;
          font-weight: 500;
        }
        .lede {
          color: rgba(232, 228, 217, 0.65);
          line-height: 1.5;
          max-width: 36rem;
          margin: 0 0 28px;
          font-size: 0.95rem;
        }
        .muted { color: rgba(232, 228, 217, 0.4); font-size: 0.85rem; }
        .err { color: #f0a0a0; font-size: 0.85rem; }
        .status { color: rgba(125, 216, 232, 0.85); font-size: 0.85rem; margin-top: 8px; }
        .top { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }
        .back, .cta {
          color: rgba(200, 168, 78, 0.85);
          text-decoration: none;
          font-size: 0.85rem;
          border-bottom: 1px solid rgba(200, 168, 78, 0.25);
        }
        .cta {
          display: inline-block;
          margin-top: 16px;
          padding: 10px 0;
        }
        .form { display: flex; flex-direction: column; gap: 10px; max-width: 320px; }
        input, textarea, select, button {
          font: inherit;
          border-radius: 8px;
          border: 1px solid rgba(255,255,255,0.12);
          background: rgba(255,255,255,0.03);
          color: #e8e4d9;
          padding: 10px 12px;
        }
        button {
          cursor: pointer;
          background: rgba(200, 168, 78, 0.12);
          border-color: rgba(200, 168, 78, 0.35);
          color: #e8d48a;
        }
        button:disabled { opacity: 0.4; cursor: not-allowed; }
        .layout {
          display: grid;
          grid-template-columns: 1fr;
          gap: 20px;
        }
        @media (min-width: 800px) {
          .layout { grid-template-columns: 240px 1fr; }
        }
        .pane {
          border: 1px solid rgba(255,255,255,0.08);
          border-radius: 12px;
          padding: 16px;
          background: rgba(10, 14, 26, 0.55);
          backdrop-filter: blur(8px);
        }
        ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; }
        .row {
          width: 100%;
          text-align: left;
          display: flex;
          justify-content: space-between;
          gap: 8px;
          background: transparent;
          border-color: transparent;
          color: #e8e4d9;
        }
        .row.active { border-color: rgba(200, 168, 78, 0.4); background: rgba(200, 168, 78, 0.08); }
        .kind { font-size: 10px; color: rgba(232,228,217,0.4); text-transform: uppercase; }
        .composer { display: flex; flex-direction: column; gap: 10px; margin-bottom: 20px; }
        .composer label { display: flex; flex-direction: column; gap: 6px; font-size: 0.8rem; color: rgba(232,228,217,0.55); }
        .timeline { display: flex; flex-direction: column; gap: 10px; }
        .bubble {
          max-width: 85%;
          padding: 10px 12px;
          border-radius: 12px;
          border: 1px solid rgba(255,255,255,0.08);
        }
        .bubble p { margin: 0 0 6px; white-space: pre-wrap; }
        .bubble time { font-size: 10px; color: rgba(232,228,217,0.35); font-family: var(--font-mono), monospace; }
        .bubble.out { align-self: flex-end; background: rgba(93, 202, 165, 0.08); border-color: rgba(93, 202, 165, 0.25); }
        .bubble.in { align-self: flex-start; background: rgba(255,255,255,0.03); }
      `}</style>
      {children}
    </div>
  );
}
