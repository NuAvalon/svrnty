'use client';

// Notes PWA (/msg) — Phase 3 rung 1 · Hive aesthetic (mobile-first).
// Claim discipline: NOTES between admitted contacts — not "messaging".
// Visual language: solar ember field, pointy-top hexes, same as the galaxy.
// No trading/berries mechanics — only the network geometry + palette.

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { readPrivateKey } from 'openpgp';
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
  listRingChannels,
  sendNoteToPeer,
  sendRingNote,
  sendRingHistory,
  putThread,
  putRingChannel,
  createRingChannel,
  addRingMember,
  removeRingMember,
  notesToShare,
  exportNotesBackup,
  newThreadId,
  loadRatchetIdentity,
  ringPeerFromContact,
  mainTimeline,
  sideThread,
  replyCount,
  replyLink,
  type NoteThread,
  type NoteRecord,
  type RingChannel,
  type RingHistoryAccess,
  type RingPeer,
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
  const [rings, setRings] = useState<RingChannel[]>([]);
  const [ringOpen, setRingOpen] = useState(false);
  const [ringLabel, setRingLabel] = useState('');
  const [ringPicks, setRingPicks] = useState<string[]>([]);
  const [activeRingId, setActiveRingId] = useState<string | null>(null);
  const [sideRoot, setSideRoot] = useState<string | null>(null);
  const [freshThread, setFreshThread] = useState(false);
  const [addFp, setAddFp] = useState('');
  const [addHistory, setAddHistory] = useState<RingHistoryAccess>('new');

  const refresh = useCallback(async (fp: string) => {
    const [c, t, r] = await Promise.all([getAllContacts(fp), listThreads(), listRingChannels()]);
    setContacts(c);
    setThreads(t);
    setRings(r);
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
    setActiveRingId(null);
    setSideRoot(null);
    setFreshThread(false);
    setAddFp('');
    setAddHistory('new');
    setPhase('compose');
    setStatus(null);
    const existing = threads.find(
      (t) => t.kind === 'direct' && t.participants.some((p) => p.fingerprint === fp),
    );
    setActiveThreadId(existing?.thread_id ?? null);
  };

  const openThread = (t: NoteThread) => {
    setActiveThreadId(t.thread_id);
    setSideRoot(null);
    setFreshThread(false);
    setStatus(null);
    setPhase('compose');
    setRingOpen(false);
    setAddFp('');
    setAddHistory('new');
    if (t.kind === 'ring' && t.ring_channel_id) {
      setActiveRingId(t.ring_channel_id);
      setPeerFp('');
    } else {
      setActiveRingId(null);
      setPeerFp(t.participants[0]?.fingerprint ?? '');
    }
  };

  const replyFields = () => {
    if (!sideRoot) return {};
    const latest = sideThread(notes, sideRoot).at(-1);
    const link = replyLink(notes, latest?.note_id ?? sideRoot);
    return link ? { replyTo: link.reply_to, threadRoot: link.thread_root } : {};
  };

  const handleSend = async () => {
    if (!draft.trim()) return;
    const ring = rings.find((r) => r.channel_id === activeRingId) ?? null;
    if (!ring && !peerFp) return;
    setSending(true);
    setStatus(null);
    try {
      if (ring) {
        const self = await loadRatchetIdentity(fingerprint);
        if (!self) {
          setStatus('This identity has no hybrid keys yet, so a ring note cannot seal.');
          return;
        }
        const peers: RingPeer[] = [];
        for (const fp of ring.member_fingerprints) {
          if (fp === fingerprint) continue;
          const contact = contacts.find((c) => c.fingerprint === fp);
          if (!contact) {
            setStatus('Someone in this ring is not in your book.');
            return;
          }
          const peer = await ringPeerFromContact(contact);
          if (!peer) {
            setStatus(`${contact.name || 'A member'} has no hybrid key in your book.`);
            return;
          }
          peers.push(peer);
        }
        const threadId = activeThreadId ?? newThreadId();
        const result = await sendRingNote({
          self,
          selfFingerprint: fingerprint,
          participantKind: 'human',
          channel: ring,
          peers,
          body: draft.trim(),
          threadId,
          ...replyFields(),
        });
        setDraft('');
        setFreshThread(false);
        setActiveThreadId(result.thread_id);
        setActiveRingId(result.channel.channel_id);
        setPhase('sealed');
        setStatus(result.deposited ? 'Sealed · queued to each mailbox' : 'Saved locally · a mailbox deposit failed');
        await refresh(fingerprint);
        setNotes(await listNotesForThread(result.thread_id));
        return;
      }

      const contact = contacts.find((c) => c.fingerprint === peerFp);
      if (!contact?.public_key) {
        setStatus('They need a public key in your book before a note can seal.');
        return;
      }
      const key = await loadKey(fingerprint);
      if (!key) throw new Error('Session locked');
      // Sender authentication (Flint #55): sendNoteToPeer signs the note so the recipient can verify
      // WHO sent it, not just decrypt it. Derive the owner's public key from the unlocked private key
      // — its fingerprint equals `fingerprint` by construction, so the recipient's fingerprintMatchesKey
      // binds the carried key to the claimed sender.
      const senderPublicKeyArmored = (await readPrivateKey({ armoredKey: key.privateKey })).toPublic().armor();
      const result = await sendNoteToPeer({
        sender: { fingerprint, participant_kind: 'human' },
        senderPublicKeyArmored,
        senderPrivateKeyArmored: key.privateKey,
        passphrase: key.passphrase,
        peerFingerprint: peerFp,
        peerPublicKeyArmored: contact.public_key,
        body: draft.trim(),
        threadId: freshThread ? undefined : activeThreadId ?? undefined,
        ...replyFields(),
      });
      const tlist = await listThreads();
      const updated = tlist.find((t) => t.thread_id === result.thread_id);
      if (updated && updated.kind === 'direct') {
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
      setFreshThread(false);
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

  const startRing = async () => {
    if (ringPicks.length < 2) {
      setStatus('A ring needs two other admitted people.');
      return;
    }
    const members = [fingerprint, ...ringPicks];
    const channel = createRingChannel(ringLabel, members);
    const now = new Date().toISOString();
    const threadId = newThreadId();
    await putRingChannel(channel);
    await putThread({
      thread_id: threadId,
      kind: 'ring',
      participants: ringPicks.map((fp) => {
        const c = contacts.find((x) => x.fingerprint === fp);
        return {
          fingerprint: fp,
          kind: c?.metadata?.identity_type === 'agent' ? 'agent' as const : 'human' as const,
          display_name: c?.name || fp.slice(0, 8),
        };
      }),
      ring_channel_id: channel.channel_id,
      created_at: now,
      last_activity_at: now,
      retention: { expires_at: null },
    });
    setRingLabel('');
    setRingPicks([]);
    setRingOpen(false);
    await refresh(fingerprint);
    const created = (await listThreads()).find((t) => t.thread_id === threadId);
    if (created) openThread(created);
  };

  const backupNotes = async () => {
    try {
      const backup = await exportNotesBackup();
      const blob = new Blob([JSON.stringify(backup)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'svrnty-notes.json';
      a.click();
      URL.revokeObjectURL(url);
      setStatus('Saved svrnty-notes.json. That file is the notes themselves, not the contact book.');
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Notes backup failed');
    }
  };

  const addToRing = async () => {
    const ring = rings.find((r) => r.channel_id === activeRingId);
    if (!ring || !addFp) return;
    setSending(true);
    setStatus(null);
    try {
      const contact = contacts.find((c) => c.fingerprint === addFp);
      const history = addHistory;
      const next = addRingMember(ring, addFp, history);
      await putRingChannel(next);
      const thread = threads.find((t) => t.ring_channel_id === ring.channel_id);
      if (thread && contact) {
        await putThread({
          ...thread,
          participants: [
            ...thread.participants,
            {
              fingerprint: addFp,
              kind: contact.metadata?.identity_type === 'agent' ? 'agent' as const : 'human' as const,
              display_name: contact.name || addFp.slice(0, 8),
            },
          ],
          last_activity_at: next.rotated_at,
        });
      }
      let message = history === 'new'
        ? 'Added. They will see new notes only.'
        : 'Added. There were no earlier notes on this device to share.';
      if (history === 'previous' && thread && contact) {
        const held = await listNotesForThread(thread.thread_id);
        const share = notesToShare(held, 'previous');
        if (share.length) {
          const self = await loadRatchetIdentity(fingerprint);
          const peer = await ringPeerFromContact(contact);
          if (!self || !peer) {
            message = 'They are in the ring. Earlier notes stayed here — a hybrid key is missing.';
          } else {
            const sent = await sendRingHistory({
              self,
              selfFingerprint: fingerprint,
              channel: next,
              peer,
              history: share,
              threadId: thread.thread_id,
            });
            message = sent.deposited
              ? 'Added. Earlier notes were sealed only to them.'
              : 'Added. The earlier-notes seal did not reach their mailbox.';
          }
        }
      }
      setAddFp('');
      setAddHistory('new');
      setStatus(message);
      await refresh(fingerprint);
      if (thread) setNotes(await listNotesForThread(thread.thread_id));
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Could not add them');
    } finally {
      setSending(false);
    }
  };

  const removeFromRing = async (fp: string) => {
    const ring = rings.find((r) => r.channel_id === activeRingId);
    if (!ring || fp === fingerprint) return;
    const next = ring.member_fingerprints.filter((m) => m !== fp);
    if (next.length < 2) {
      setStatus('A ring needs two people. A direct note is the smaller conversation.');
      return;
    }
    const rotated = removeRingMember(ring, fp);
    await putRingChannel(rotated);
    if (activeThreadId) {
      const t = threads.find((x) => x.thread_id === activeThreadId);
      if (t) {
        await putThread({
          ...t,
          participants: t.participants.filter((p) => p.fingerprint !== fp),
          last_activity_at: rotated.rotated_at,
        });
      }
    }
    await refresh(fingerprint);
    setStatus('They keep notes they already opened. Later notes are not sealed to them.');
  };

  const selected = contacts.find((c) => c.fingerprint === peerFp);
  const activeRing = rings.find((r) => r.channel_id === activeRingId) ?? null;
  const shown = sideRoot ? sideThread(notes, sideRoot) : mainTimeline(notes);
  const threadTitle = (t: NoteThread) => {
    if (t.kind === 'ring') {
      return rings.find((r) => r.channel_id === t.ring_channel_id)?.local_label || 'Ring';
    }
    return t.participants.map((p) => p.display_name).join(', ') || 'Thread';
  };

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
                  setActiveRingId(null);
                  setSideRoot(null);
                  setFreshThread(false);
                  setRingOpen(false);
                  setStatus(null);
                }}
              >
                Reset
              </button>
            </header>

            {status && phase === 'select' && (
              <p className="hive-status" data-testid="notes-status">{status}</p>
            )}

            <Steps phase={phase} />

            <div className="thread-rail" data-testid="notes-thread-list">
              <button type="button" className="hive-chip" data-testid="notes-backup" onClick={backupNotes}>
                Back up notes
              </button>
              <button type="button" className="hive-chip" data-testid="notes-new-ring" onClick={() => { setRingOpen((v) => !v); setStatus(null); }}>
                New ring
              </button>
              {threads.map((t) => (
                <button
                  key={t.thread_id}
                  type="button"
                  className={`hive-chip ${t.thread_id === activeThreadId ? 'is-on' : ''}`}
                  onClick={() => openThread(t)}
                >
                  {t.kind === 'ring' ? 'Ring · ' : ''}{threadTitle(t)}
                </button>
              ))}
              {threads.length === 0 && <span className="hive-muted">No threads yet.</span>}
            </div>

            {ringOpen && (
              <section className="ring-panel" data-testid="notes-ring-create">
                <p className="hive-eyebrow">Ring · admitted only · relay sees separate sealed mail</p>
                <input
                  className="ring-label"
                  placeholder="Local name (stays on this device)"
                  value={ringLabel}
                  onChange={(e) => setRingLabel(e.target.value)}
                />
                <div className="ring-picks">
                  {contacts.map((c) => {
                    const hybrid = Boolean(c.pq_kem_public_key && c.public_key);
                    const on = ringPicks.includes(c.fingerprint);
                    return (
                      <label key={c.id} className={hybrid ? '' : 'is-dim'}>
                        <input
                          type="checkbox"
                          disabled={!hybrid}
                          checked={on}
                          onChange={() => {
                            setRingPicks((prev) =>
                              prev.includes(c.fingerprint)
                                ? prev.filter((fp) => fp !== c.fingerprint)
                                : [...prev, c.fingerprint],
                            );
                          }}
                        />
                        {c.name || c.fingerprint.slice(0, 8)}
                        {!hybrid && <span> · no hybrid key</span>}
                      </label>
                    );
                  })}
                </div>
                <button type="button" className="seal-btn" onClick={startRing} disabled={ringPicks.length < 2}>
                  Start ring
                </button>
              </section>
            )}

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
                        <EmberHex
                          kind={selectedNode ? 'selected' : hasThread ? 'thread' : isAgent ? 'agent' : 'known'}
                        />
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
            {phase !== 'select' && (selected || activeRing) && (
              <section className="hive-sheet" data-testid="notes-compose">
                <div className="sheet-head">
                  <div>
                    <p className="hive-eyebrow">
                      {activeRing ? 'Ring' : selected?.metadata?.identity_type === 'agent' ? 'Agent' : 'Human'}
                      {sideRoot ? ' · thread' : ''}
                    </p>
                    <h2>
                      {activeRing
                        ? activeRing.local_label
                        : freshThread
                          ? `New thread · ${selected?.name || ''}`
                          : selected?.name || selected?.fingerprint.slice(0, 12)}
                    </h2>
                  </div>
                  <button type="button" className="hive-chip" onClick={() => { setPhase('select'); setSideRoot(null); }}>
                    Close
                  </button>
                </div>

                {activeRing && (
                  <div className="ring-members">
                    {activeRing.member_fingerprints.filter((fp) => fp !== fingerprint).map((fp) => {
                      const c = contacts.find((x) => x.fingerprint === fp);
                      return (
                        <span key={fp}>
                          {c?.name || fp.slice(0, 8)}
                          <button type="button" onClick={() => removeFromRing(fp)} aria-label={`Remove ${c?.name || 'member'}`}>
                            Remove
                          </button>
                        </span>
                      );
                    })}
                  </div>
                )}

                {activeRing && (
                  <div className="ring-add" data-testid="notes-ring-add">
                    <p className="hive-muted">
                      Add someone. New notes only, unless you choose earlier notes. A sealed note is not unsent.
                    </p>
                    <select
                      data-testid="notes-ring-add-person"
                      value={addFp}
                      onChange={(e) => setAddFp(e.target.value)}
                    >
                      <option value="">Choose someone</option>
                      {contacts.filter((c) =>
                        c.fingerprint !== fingerprint
                        && !activeRing.member_fingerprints.includes(c.fingerprint)
                        && Boolean(c.pq_kem_public_key && c.public_key),
                      ).map((c) => (
                        <option key={c.id} value={c.fingerprint}>{c.name || c.fingerprint.slice(0, 8)}</option>
                      ))}
                    </select>
                    <label>
                      <input
                        type="radio"
                        name="ring-history"
                        checked={addHistory === 'new'}
                        onChange={() => setAddHistory('new')}
                      />
                      New notes only
                    </label>
                    <label>
                      <input
                        type="radio"
                        name="ring-history"
                        checked={addHistory === 'previous'}
                        onChange={() => setAddHistory('previous')}
                      />
                      Earlier notes too
                    </label>
                    <button
                      type="button"
                      className="hive-chip"
                      data-testid="notes-ring-add-confirm"
                      disabled={!addFp || sending}
                      onClick={addToRing}
                    >
                      Add
                    </button>
                    <p className="hive-muted">
                      Removing someone leaves them the notes they already opened. Later notes are not sealed to them.
                    </p>
                  </div>
                )}

                {!activeRing && selected && (
                  <button
                    type="button"
                    className="hive-chip"
                    data-testid="notes-new-thread"
                    onClick={() => {
                      setFreshThread(true);
                      setActiveThreadId(null);
                      setSideRoot(null);
                      setNotes([]);
                      setStatus(null);
                      setPhase('compose');
                    }}
                  >
                    New thread
                  </button>
                )}

                {sideRoot && (
                  <button type="button" className="hive-chip" data-testid="notes-side-back" onClick={() => setSideRoot(null)}>
                    Back to timeline
                  </button>
                )}

                <div className="timeline" data-testid="notes-timeline">
                  {shown.map((n) => {
                    const replies = n.thread_root ? 0 : replyCount(notes, n.note_id);
                    return (
                      <article key={n.note_id} className={n.direction === 'outbound' ? 'bubble out' : 'bubble in'}>
                        <p>{n.body}</p>
                        <time>{new Date(n.sent_at).toLocaleString()}</time>
                        {!sideRoot && replies > 0 && (
                          <button type="button" className="thread-jump" data-testid="notes-open-thread" onClick={() => setSideRoot(n.note_id)}>
                            {replies} in thread
                          </button>
                        )}
                        {!n.thread_root && (
                          <button
                            type="button"
                            className="thread-jump"
                            data-testid="notes-reply"
                            onClick={() => setSideRoot(n.note_id)}
                          >
                            Thread
                          </button>
                        )}
                      </article>
                    );
                  })}
                  {shown.length === 0 && (
                    <p className="hive-muted">{sideRoot ? 'No replies in this thread yet.' : 'No notes in this thread yet.'}</p>
                  )}
                </div>

                <div className="composer">
                  <textarea
                    rows={3}
                    placeholder={sideRoot ? 'Reply in this thread…' : 'Write a sealed note…'}
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

/** Pointy-top hex, same vertices as the galaxy map. */
function hexPoints(cx: number, cy: number, r: number): string {
  const pts: string[] = [];
  for (let i = 0; i < 6; i++) {
    const a = -Math.PI / 2 + (i * Math.PI) / 3;
    pts.push(`${(cx + r * Math.cos(a)).toFixed(2)},${(cy + r * Math.sin(a)).toFixed(2)}`);
  }
  return pts.join(' ');
}

function EmberHex({
  kind,
  large,
}: {
  kind: 'you' | 'thread' | 'known' | 'agent' | 'selected';
  large?: boolean;
}) {
  const w = large ? 96 : kind === 'you' ? 84 : 68;
  const h = large ? 108 : kind === 'you' ? 94 : 76;
  const cx = w / 2;
  const cy = h / 2 - 2;
  const r = large ? 36 : kind === 'you' ? 30 : 24;
  const lit = kind === 'you' || kind === 'thread' || kind === 'selected';
  const fill = kind === 'you'
    ? 'var(--se-bg)'
    : kind === 'thread' || kind === 'selected'
      ? 'color-mix(in srgb, var(--se-accent2) 22%, var(--se-bg))'
      : kind === 'agent'
        ? 'color-mix(in srgb, var(--se-accent2) 12%, transparent)'
        : 'color-mix(in srgb, var(--se-accent) 18%, var(--se-bg))';
  const stroke = kind === 'thread' || kind === 'agent' ? 'var(--se-accent2)' : 'var(--se-accent)';
  return (
    <svg className="ember-hex" width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden>
      {kind === 'you' && (
        <polygon
          points={hexPoints(cx, cy, r + 8)}
          fill="none"
          stroke="var(--se-accent)"
          strokeWidth={0.85}
          opacity={0.38}
        />
      )}
      {(kind === 'thread' || kind === 'selected') && (
        <polygon
          points={hexPoints(cx, cy, r + 4)}
          fill="none"
          stroke="#fff8ee"
          strokeOpacity={0.28}
          strokeWidth={1.05}
        />
      )}
      <polygon
        points={hexPoints(cx, cy, r)}
        fill={fill}
        stroke={stroke}
        strokeWidth={lit ? 1.7 : 1.45}
      />
      {lit && (
        <>
          <circle cx={cx} cy={cy} r={r * 0.42} fill="#fff8ee" opacity={0.16} />
          <circle className="ember-core" cx={cx} cy={cy} r={Math.max(2.4, r * 0.22)} fill="#fffef8" />
        </>
      )}
      {!lit && (
        <circle cx={cx} cy={cy} r={Math.max(1.8, r * 0.18)} fill={stroke} opacity={0.85} />
      )}
    </svg>
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
      <EmberHex kind={tone === 'you' ? 'you' : 'known'} large={large} />
      <span className="hex-label">{label}</span>
      <span className="hex-sub">{sub}</span>
    </div>
  );
}

function HiveStyles() {
  return (
    <style>{`
      .hive {
        --cream: var(--se-text);
        --muted: var(--se-muted);
        --gold: var(--se-accent);
        --err: var(--se-danger);
        --ok: var(--se-ok);
        accent-color: var(--se-accent);
        min-height: 100dvh;
        color: var(--se-text);
        font-family: var(--font-sans), 'Space Grotesk', system-ui, sans-serif;
        background: var(--se-bg-css);
        position: relative;
        overflow-x: hidden;
      }
      .hive::before {
        content: '';
        position: absolute;
        inset: 0;
        background-image: radial-gradient(color-mix(in srgb, var(--se-accent) 35%, transparent) 1px, transparent 1px);
        background-size: 22px 22px;
        mask-image: radial-gradient(ellipse at 50% 42%, black 12%, transparent 70%);
        pointer-events: none;
        opacity: 0.28;
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
        color: var(--se-accent);
        text-decoration: none;
        font-size: 0.85rem;
        border-bottom: 1px solid var(--se-border-lit);
      }
      .hive-chip {
        font: inherit;
        font-size: 11px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--se-muted);
        background: var(--se-surface);
        border: 1px solid var(--se-border);
        border-radius: 999px;
        padding: 8px 12px;
        text-decoration: none;
        cursor: pointer;
      }
      .hive-chip.is-on {
        border-color: var(--se-border-lit);
        color: var(--se-accent);
        background: color-mix(in srgb, var(--se-accent) 14%, transparent);
      }
      .thread-rail, .ring-picks, .ring-members {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        align-items: center;
        margin: 0 0 14px;
      }
      .ring-panel {
        border: 1px solid var(--se-border);
        border-radius: 16px;
        padding: 12px;
        margin-bottom: 14px;
        background: var(--se-surface-solid);
        box-shadow: var(--se-glass-shadow);
        backdrop-filter: blur(20px);
      }
      .ring-label {
        width: 100%;
        box-sizing: border-box;
        font: inherit;
        border-radius: 12px;
        border: 1px solid var(--se-border);
        background: var(--se-input-bg);
        color: var(--se-text);
        padding: 12px 14px;
        margin: 8px 0 12px;
      }
      .ring-label::placeholder,
      .hive-form input::placeholder,
      .composer textarea::placeholder { color: color-mix(in srgb, var(--se-dim) 80%, transparent); }
      .ring-picks label, .ring-members span {
        font-size: 12px;
        color: var(--cream);
        display: inline-flex;
        gap: 6px;
        align-items: center;
      }
      .ring-picks label.is-dim { color: var(--muted); }
      .ring-add {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        align-items: center;
        margin: 0 0 12px;
      }
      .ring-add select {
        font: inherit;
        color: var(--se-text);
        background: var(--se-input-bg);
        border: 1px solid var(--se-border);
        border-radius: 12px;
        padding: 8px 10px;
      }
      .ring-add label {
        font-size: 12px;
        color: var(--cream);
        display: inline-flex;
        gap: 6px;
        align-items: center;
      }
      .ring-add .hive-muted { flex-basis: 100%; margin: 0; }
      .ring-members button, .thread-jump {
        font: inherit;
        font-size: 10px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--gold);
        background: transparent;
        border: none;
        cursor: pointer;
        padding: 0;
      }
      .thread-jump { display: block; margin-top: 6px; }

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
        color: var(--se-dim);
      }
      .hive-steps li.on { color: var(--se-accent); }
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
        border: 1px solid var(--se-border);
        background: var(--se-input-bg);
        color: var(--se-text);
        padding: 12px 14px;
      }
      .hive-form input:focus, .composer textarea:focus, .ring-label:focus, .ring-add select:focus {
        outline: none;
        border-color: var(--se-border-lit);
        box-shadow: 0 0 0 2px color-mix(in srgb, var(--se-accent) 18%, transparent);
      }
      .hive-form button, .seal-btn {
        font: inherit;
        cursor: pointer;
        border-radius: 12px;
        border: 1px solid var(--se-border-lit);
        background: color-mix(in srgb, var(--se-accent) 16%, transparent);
        color: var(--se-accent);
        padding: 12px 14px;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        font-size: 12px;
        box-shadow: var(--se-glass-shadow);
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
        background: linear-gradient(180deg, var(--se-accent), var(--se-accent2));
        box-shadow: 0 0 12px color-mix(in srgb, var(--se-accent) 45%, transparent);
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
        border: none;
        background: transparent;
        color: var(--se-text);
        cursor: pointer;
        padding: 0;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 1px;
        animation: hex-pop 0.55s ease-out both;
        animation-delay: calc(var(--i, 0) * 35ms);
      }
      .hex-mark { cursor: default; }
      .ember-hex { display: block; overflow: visible; }
      .ember-core {
        transform-box: fill-box;
        transform-origin: center;
        animation: ember-breathe 3.6s ease-in-out infinite;
      }
      .hex-node.is-selected { transform: translateY(-2px); }
      .hex-label {
        font-size: 10px;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        max-width: 76px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        color: var(--se-text);
      }
      .hex-mark .hex-label { font-size: 12px; letter-spacing: 0.16em; }
      .hex-mark.large .hex-label { font-size: 13px; }
      .hex-sub {
        font-size: 8px;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: var(--se-dim);
      }
      .hex-mark.you .hex-sub { color: var(--se-accent); }

      .hive-sheet {
        margin-top: 8px;
        border: 1px solid var(--se-border);
        border-radius: 16px;
        background: var(--se-surface-solid);
        box-shadow: var(--se-glass-shadow);
        padding: 14px 14px 16px;
        animation: sheet-up 0.35s ease-out both;
        backdrop-filter: blur(20px);
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
        border: 1px solid var(--se-border);
        background: var(--se-surface);
      }
      .bubble p { margin: 0 0 6px; white-space: pre-wrap; font-size: 0.92rem; }
      .bubble time {
        font-size: 9px;
        color: var(--muted);
        font-family: var(--font-mono), monospace;
      }
      .bubble.out {
        align-self: flex-end;
        border-color: var(--se-border-lit);
        background: color-mix(in srgb, var(--se-accent) 12%, transparent);
      }
      .bubble.in {
        align-self: flex-start;
        border-color: color-mix(in srgb, var(--se-accent2) 45%, transparent);
        background: color-mix(in srgb, var(--se-accent2) 10%, transparent);
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
        from { transform: translateY(16px); }
        to { transform: translateY(0); }
      }
      @keyframes ember-breathe {
        0%, 100% { opacity: 0.72; }
        50% { opacity: 1; }
      }
      @media (prefers-reduced-motion: reduce) {
        .hive-lock, .hive-cluster, .hive-you, .hex-node, .hive-sheet, .ember-core { animation: none; }
      }
      @media (min-width: 720px) {
        .hive-stage { max-width: 560px; padding-top: 28px; }
        .timeline { max-height: 36vh; }
      }
    `}</style>
  );
}
