// src/components/JoinerCeremony.tsx
'use client';
//
// The joiner's side of the 9/10 connection ceremony (task #482). Mirror of the initiator
// component (src/components/Ceremony.tsx): the SAME proven state machine
// (src/lib/ceremony/machine.ts) drives both devices — role affects rendering, not the
// transition graph ("one impl, not two").
//
// Perspective: this instance runs on the JOINER's device (the receiver — arrives via the
// /c/[code] relay link, receives the card, persists the edge, watches their own lattice
// light up). The three middle steps (card, edge, lattice) are the joiner's REAL local
// actions here (the mirror of the initiator, where those three are "on their device"). The
// handshake already happened the moment they opened this link; the tear (step 5) happens on
// the GIVER's device, so it carries the "on their device" framing.
//
// Honest-scoping: the relay is a single-use dead-drop (src/lib/sync/relay.ts) — one code
// carries one payload. A CARD link walks the full stepper. A SHARD link ("the tear" landing
// on this device) is one meaningful act — accepting a recovery piece — so it gets a focused
// accept panel rather than being forced through a card-shaped 5-step rail. Nothing here
// touches prod; all state is local (IndexedDB) or the client-side relay.

import { useCallback, useEffect, useRef, useState } from 'react';
import { resolveRelay } from '@/lib/sync/relay';
import {
  getActiveFingerprint,
  loadIdentity,
  addContact,
  getContactByFingerprint,
  getAllContacts,
  storeHeldShard,
  SHARD_CUSTODY_TYPE,
} from '@/lib/identity/client-store';
import { fingerprintMatchesKey } from '@/lib/identity/fingerprint';
import { TrustMap } from '@/components/TrustMap';
import { useCeremony } from '@/lib/ceremony/useCeremony';
import { stepLabel, CEREMONY_STEP_ORDER, type CeremonyStepId } from '@/lib/ceremony/machine';
import type { TrustEdge } from '@/lib/trust/types';

// Emerald/gold palette — matches the initiator (Ceremony.tsx) so the two devices read as
// one ceremony.
const C = {
  bg: '#0a0a0f',
  panel: 'rgba(10, 14, 12, 0.92)',
  emerald: '#34d399',
  emeraldDim: 'rgba(52, 211, 153, 0.15)',
  gold: '#c8a84e',
  ink: '#e8e4d9',
  faint: 'rgba(255,255,255,0.35)',
  err: '#ef4444',
};

// Which device each step happens on, from the JOINER's perspective — the mirror of the
// initiator's STEP_LOCUS. The middle three are the joiner's own actions; the tear is the
// giver's.
const STEP_LOCUS: Record<CeremonyStepId, 'you' | 'them' | 'done'> = {
  handshake: 'you',
  card: 'you',
  edge: 'you',
  lattice: 'you',
  tear: 'them',
  complete: 'done',
};

// Same ContactRecord -> TrustEdge shape app/page.tsx uses to feed the TrustMap.
function contactToEdge(c: any): TrustEdge {
  return {
    id: c.id,
    peer_fingerprint: c.peer_fingerprint || c.fingerprint || c.id,
    peer_name: c.peer_name || c.name,
    peer_email: c.peer_email || c.email || '',
    peer_public_key: c.peer_public_key || c.public_key || '',
    trusted: c.trusted ?? (c.trust_level === 'verified' || c.trust_level === 'trusted'),
    trusted_since: c.trusted_since || c.verified_at || null,
    last_interaction: c.last_interaction || c.verified_at || c.added_at || new Date().toISOString(),
    decay_days: c.decay_days || 730,
    trust_history: c.trust_history || [],
    verification: c.verification || { method: 'none', verified_at: null },
    mutual: c.mutual || { they_trust_me: null, last_sync: null, reciprocal: false },
    tags: c.tags || c.metadata?.tags || [],
    notes: c.notes || c.metadata?.notes || '',
    connection_channels: c.connection_channels || [],
    added_at: c.added_at || new Date().toISOString(),
  } as TrustEdge;
}

interface PeerCard {
  name: string;
  fingerprint: string;
  publicKey: string;
  pqPublicKey: string;
  email: string;
}

export function JoinerCeremony({ code, keyFragment }: { code: string; keyFragment: string }) {
  const ceremony = useCeremony('joiner');
  const { state } = ceremony;
  // Stable action identities (useCallback deps [] in useCeremony) — safe as effect deps.
  const { handshakeEstablished, fail } = ceremony;

  const [kind, setKind] = useState<'card' | 'shard' | null>(null);
  const [peer, setPeer] = useState<PeerCard | null>(null);
  const [ownerFp, setOwnerFp] = useState<string | null>(null);
  const [ownerName, setOwnerName] = useState<string>('You');
  const [contacts, setContacts] = useState<TrustEdge[]>([]);
  const [alreadyKnown, setAlreadyKnown] = useState(false);

  // Shard ("the tear") landing on this device.
  const [shardFrom, setShardFrom] = useState<string>('Someone');
  const [shardState, setShardState] = useState<'idle' | 'accepting' | 'accepted' | 'exists'>('idle');
  const [shardMsg, setShardMsg] = useState<string>('');

  const startedRef = useRef(false);

  // --- Mount: get our identity, resolve + decrypt the relay, classify the payload. ---
  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;
    let cancelled = false;

    (async () => {
      try {
        const fp = await getActiveFingerprint();
        if (cancelled) return;
        if (!fp) {
          fail('No active identity found. Set up your identity on the main page first, then revisit this link.');
          return;
        }
        setOwnerFp(fp);
        loadIdentity(fp)
          .then((id) => {
            if (!cancelled && id) {
              setOwnerName(id?.identity?.display_name || id?.identity?.name || id?.name || 'You');
            }
          })
          .catch(() => {});

        const decrypted = await resolveRelay(code, keyFragment);
        if (cancelled) return;

        const parsed = JSON.parse(decrypted);
        if (parsed?.type === SHARD_CUSTODY_TYPE) {
          setKind('shard');
          setShardFrom(parsed?.from?.name || 'Someone');
          // Stash for the accept action.
          setPeer(null);
          (window as any).__svrnty_shard = parsed;
        } else {
          const p = parsed.identity || parsed;
          const claimedFp = p.fingerprint || p.peer_fingerprint || '';
          const publicKey = p.public_key || p.publicKey || '';
          // C2 / Invariant-1: verify the fingerprint↔key binding BEFORE showing the reassuring
          // fingerprint box or persisting anything. Refuse a card whose fingerprint does not match
          // its key — otherwise the out-of-band "is this your fingerprint?" ritual would falsely
          // pass while the stored key is an attacker's.
          const bound = await fingerprintMatchesKey(claimedFp, publicKey);
          if (cancelled) return;
          if (!bound) {
            fail(
              'This card could not be verified — its fingerprint does not match its key, so it was not imported. Ask them to send you a fresh link.',
            );
            return;
          }
          setKind('card');
          setPeer({
            name: p.display_name || p.name || p.peer_name || 'Unknown',
            fingerprint: claimedFp,
            publicKey,
            pqPublicKey: p.pq_public_key || p.pqPublicKey || '',
            email: p.email || '',
          });
        }
        handshakeEstablished(code); // machine: handshake -> card
      } catch (err: any) {
        if (cancelled) return;
        fail(err?.message || 'This link has expired or already been used.');
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [code, keyFragment, handshakeEstablished, fail]);

  // --- Card ceremony actions ---
  const receiveCard = useCallback(() => {
    if (!peer) return;
    ceremony.cardConveyed(peer.fingerprint, peer.name); // card -> edge
  }, [peer, ceremony]);

  const persistEdge = useCallback(async () => {
    if (!peer || !ownerFp) return;
    try {
      // Idempotent: if we already know them, don't double-add — advance with the existing edge.
      const existing = peer.fingerprint
        ? await getContactByFingerprint(ownerFp, peer.fingerprint)
        : null;
      let edgeId: string;
      if (existing) {
        setAlreadyKnown(true);
        edgeId = existing.id;
      } else {
        const contact = await addContact(ownerFp, {
          name: peer.name,
          fingerprint: peer.fingerprint,
          public_key: peer.publicKey,
          pq_public_key: peer.pqPublicKey,
          trust_level: 'pending',
          email: peer.email,
        } as any);
        edgeId = contact.id;
      }
      // Load the constellation for the lattice step (includes the new facet).
      try {
        const raw = await getAllContacts(ownerFp);
        setContacts(raw.map(contactToEdge));
      } catch { /* non-fatal — lattice will just show the owner */ }
      ceremony.edgePersisted(edgeId); // edge -> lattice
    } catch (err: any) {
      ceremony.fail(err?.message || 'Could not write the edge.');
    }
  }, [peer, ownerFp, ceremony]);

  // --- Shard ("the tear") accept ---
  const acceptShard = useCallback(async () => {
    if (!ownerFp) return;
    const raw = (window as any).__svrnty_shard;
    if (!raw || !raw.shard) {
      setShardMsg('The piece could not be read.');
      return;
    }
    setShardState('accepting');
    try {
      await storeHeldShard(ownerFp, {
        owner_fingerprint: raw.from?.fingerprint || raw.shard.identity_fingerprint || '',
        owner_name: raw.from?.name || 'Unknown',
        shard: raw.shard,
        threshold: raw.threshold || raw.shard.threshold || 0,
        total: raw.total || 0,
      } as any);
      setShardMsg(
        `You are now holding a piece of ${raw.from?.name || 'their'} recovery. Keep it safe — any few keepers together can help them restore.`,
      );
      setShardState('accepted');
      try { delete (window as any).__svrnty_shard; } catch { /* ignore */ }
    } catch (err: any) {
      setShardMsg(err?.message || 'Could not accept the piece.');
      setShardState('idle');
    }
  }, [ownerFp]);

  // ============================ SHARD LINK — focused accept ============================
  if (kind === 'shard') {
    return (
      <Shell>
        <Badge tone="gold" label="A piece entrusted to you" />
        {shardState !== 'accepted' ? (
          <>
            <h2 style={headingStyle}>{shardFrom} tore off a piece</h2>
            <p style={subStyle}>
              They entrusted a shard of their recovery to you — a piece of their survivability,
              held by someone they trust. It was decrypted on your device; the server never saw it.
            </p>
            <button
              style={primaryBtnStyle}
              disabled={shardState === 'accepting'}
              onClick={acceptShard}
            >
              {shardState === 'accepting' ? 'Accepting…' : 'Accept the piece'}
            </button>
            {shardMsg && shardState === 'idle' && (
              <p style={{ color: C.err, marginTop: 14, fontSize: 13 }}>{shardMsg}</p>
            )}
          </>
        ) : (
          <>
            <div style={{ fontSize: 34, marginBottom: 8 }}>🜂</div>
            <h2 style={headingStyle}>You are a keeper</h2>
            <p style={subStyle}>{shardMsg}</p>
            <a href="/" style={linkBtnStyle}>Open SVRNTY</a>
          </>
        )}
        {state.error && <ErrorLine text={state.error} />}
      </Shell>
    );
  }

  // ================================ CARD LINK — full stepper ================================
  const idx = CEREMONY_STEP_ORDER.indexOf(state.step);

  return (
    <Shell wide>
      {/* Progress rail */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 28 }}>
        {CEREMONY_STEP_ORDER.filter((s) => s !== 'complete').map((s, i) => {
          const done = i < idx;
          const active = CEREMONY_STEP_ORDER[i] === state.step;
          return (
            <div key={s} style={{ flex: 1, textAlign: 'center' }}>
              <div
                style={{
                  height: 3,
                  borderRadius: 2,
                  background: done || active ? C.emerald : C.emeraldDim,
                  opacity: done ? 0.6 : active ? 1 : 0.4,
                }}
              />
              <div
                style={{
                  marginTop: 6,
                  fontSize: 10,
                  letterSpacing: 1,
                  textTransform: 'uppercase',
                  color: active ? C.emerald : C.faint,
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              >
                {stepLabel(s)}
              </div>
            </div>
          );
        })}
      </div>

      <div
        style={{
          background: C.panel,
          border: `1px solid ${C.emeraldDim}`,
          borderRadius: 16,
          padding: 32,
          textAlign: 'center',
        }}
      >
        {STEP_LOCUS[state.step] === 'them' && <LocusTag />}

        {/* handshake — arriving / retrieving */}
        {state.step === 'handshake' && !state.error && (
          <div>
            <Spinner />
            <h2 style={headingStyle}>Opening the secure channel…</h2>
            <p style={subStyle}>Retrieving and decrypting their card. Code: {code}</p>
          </div>
        )}

        {/* card — their card has reached your device */}
        {state.step === 'card' && peer && (
          <div>
            <h2 style={headingStyle}>{peer.name} shared their card</h2>
            <p style={subStyle}>
              An identity card reached your device through the one-time relay. Nothing was
              sent to a server.
            </p>
            <div style={cardBoxStyle}>
              <div style={{ fontSize: 10, color: C.faint, letterSpacing: 1, marginBottom: 4 }}>FINGERPRINT</div>
              <code style={{ color: C.emerald, fontSize: 12, wordBreak: 'break-all' }}>
                {peer.fingerprint || '—'}
              </code>
            </div>
            <button style={primaryBtnStyle} onClick={receiveCard}>Receive their card →</button>
          </div>
        )}

        {/* edge — persist the connection locally */}
        {state.step === 'edge' && peer && (
          <div>
            <h2 style={headingStyle}>Make the edge live</h2>
            <p style={subStyle}>
              Add {peer.name} to your network — a trust edge written to your device, a persisted
              connection between the two of you.
            </p>
            <button style={primaryBtnStyle} onClick={persistEdge}>Add to my network →</button>
          </div>
        )}

        {/* lattice — your constellation gains a facet */}
        {state.step === 'lattice' && (
          <div>
            <h2 style={headingStyle}>A facet lights up</h2>
            <p style={subStyle}>
              {peer?.name ? `${peer.name} now appears in your constellation.` : 'A new facet appears in your constellation.'}
              {alreadyKnown ? ' You were already connected.' : ''}
            </p>
            <div style={{ margin: '16px auto', maxWidth: 360 }}>
              <TrustMap ownerFingerprint={ownerFp || ''} ownerName={ownerName} contacts={contacts} />
            </div>
            <button style={primaryBtnStyle} onClick={() => ceremony.latticeRendered()}>
              The facet is lit →
            </button>
          </div>
        )}

        {/* tear — the giver's local act (on their device) */}
        {state.step === 'tear' && (
          <div>
            <h2 style={headingStyle}>They may tear off a piece</h2>
            <p style={subStyle}>
              On {peer?.name || 'their'} device, they can tear off a shard of their recovery and
              entrust it to you. If they do, it arrives as its own link — open it to become a keeper.
            </p>
            <button style={primaryBtnStyle} onClick={() => ceremony.shardGiven()}>Finish →</button>
          </div>
        )}

        {/* complete */}
        {state.step === 'complete' && (
          <div>
            <div style={{ fontSize: 40, marginBottom: 8 }}>🜂</div>
            <h2 style={headingStyle}>You are connected</h2>
            <p style={subStyle}>A card received, an edge live, a facet lit in your constellation.</p>
            <a href="/" style={linkBtnStyle}>Open SVRNTY</a>
          </div>
        )}

        {state.error && (
          <ErrorLine text={state.error} />
        )}
      </div>
    </Shell>
  );
}

// ------------------------------- small presentational helpers -------------------------------

function Shell({ children, wide }: { children: React.ReactNode; wide?: boolean }) {
  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 24,
        background: C.bg,
        color: C.ink,
      }}
    >
      <div style={{ width: '100%', maxWidth: wide ? 640 : 440 }}>
        <div style={{ textAlign: 'center', marginBottom: 20 }}>
          <div style={{ fontSize: 18, fontWeight: 700, letterSpacing: 6, color: C.gold }}>SVRNTY</div>
          <div style={{ fontSize: 11, color: C.faint, letterSpacing: 1 }}>Secure Identity Exchange</div>
        </div>
        {!wide ? (
          <div
            style={{
              background: C.panel,
              border: `1px solid ${C.emeraldDim}`,
              borderRadius: 16,
              padding: 32,
              textAlign: 'center',
            }}
          >
            {children}
          </div>
        ) : (
          children
        )}
      </div>
    </div>
  );
}

function Badge({ tone, label }: { tone: 'gold' | 'emerald'; label: string }) {
  const col = tone === 'gold' ? C.gold : C.emerald;
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginBottom: 14 }}>
      <div style={{ width: 8, height: 8, borderRadius: 999, background: col }} />
      <span style={{ fontSize: 11, fontWeight: 500, letterSpacing: 1, color: col }}>{label}</span>
    </div>
  );
}

function LocusTag() {
  return (
    <div
      style={{
        display: 'inline-block',
        fontSize: 10,
        letterSpacing: 2,
        textTransform: 'uppercase',
        color: C.gold,
        border: '1px solid rgba(200,168,78,0.3)',
        borderRadius: 999,
        padding: '3px 10px',
        marginBottom: 16,
        fontFamily: "'JetBrains Mono', monospace",
      }}
    >
      On their device
    </div>
  );
}

function Spinner() {
  return (
    <div
      className="animate-spin"
      style={{
        display: 'inline-block',
        width: 24,
        height: 24,
        borderRadius: '50%',
        border: '2px solid rgba(52,211,153,0.2)',
        borderTopColor: C.emerald,
        marginBottom: 16,
      }}
    />
  );
}

function ErrorLine({ text }: { text: string }) {
  return (
    <p style={{ color: C.err, marginTop: 18, fontSize: 13 }}>
      {text}{' '}
      <a href="/" style={{ color: C.emerald, textDecoration: 'underline' }}>Go to SVRNTY</a>
    </p>
  );
}

const headingStyle: React.CSSProperties = {
  fontFamily: "'Cormorant Garamond', serif",
  fontSize: 26,
  fontWeight: 300,
  color: C.ink,
  letterSpacing: 1,
  margin: '0 0 8px',
};
const subStyle: React.CSSProperties = {
  fontFamily: "'Space Grotesk', sans-serif",
  fontSize: 14,
  color: C.faint,
  lineHeight: 1.6,
  maxWidth: 420,
  margin: '0 auto',
};
const cardBoxStyle: React.CSSProperties = {
  background: 'rgba(6, 10, 8, 0.8)',
  border: `1px solid ${C.emeraldDim}`,
  borderRadius: 8,
  padding: '12px 16px',
  margin: '16px auto 4px',
  maxWidth: 360,
};
const primaryBtnStyle: React.CSSProperties = {
  background: 'rgba(52, 211, 153, 0.12)',
  border: '1px solid rgba(52, 211, 153, 0.3)',
  borderRadius: 8,
  padding: '12px 22px',
  color: C.emerald,
  fontSize: 12,
  fontWeight: 500,
  letterSpacing: 2,
  textTransform: 'uppercase',
  fontFamily: "'Space Grotesk', sans-serif",
  cursor: 'pointer',
  marginTop: 20,
};
const linkBtnStyle: React.CSSProperties = {
  display: 'inline-block',
  background: 'rgba(180, 160, 100, 0.08)',
  border: '1px solid rgba(180, 160, 100, 0.15)',
  borderRadius: 8,
  padding: '12px 22px',
  color: C.faint,
  fontSize: 12,
  letterSpacing: 1,
  textTransform: 'uppercase',
  fontFamily: "'Space Grotesk', sans-serif",
  textDecoration: 'none',
  marginTop: 20,
};
