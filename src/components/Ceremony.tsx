// src/components/Ceremony.tsx
'use client';
//
// The 9/10 connection ceremony — one guided flow over the five canon steps (task #482).
// This is the sequencer the feasibility gap-map named as the missing piece: the five
// primitives already exist but were scattered across four surfaces. Here they become one
// walk-through, driven by the proven ceremony state machine (src/lib/ceremony/machine.ts).
//
// Perspective: this instance runs on the INITIATOR's device (the giver — shows the card,
// gives the shard). The two LOCAL milestones (step 1 handshake, step 5 tear) are real
// actions wired to the live surfaces. The three middle steps happen on the JOINER's
// device (the existing /c/[code] receive route); the initiator guides the other person
// through them, so they advance manually with clear "on their device" framing.
//
// Honored here — Peter's #113925 "QR code and short link": step 1 offers BOTH entry modes
// off a single relay handshake (scan the QR, or open/enter the short link — same code).
// Deferred (tracked): the in-app camera SCANNER (#485; short-link is the can't-fail floor),
// full live 2-device auto-advance (needs a live relay channel back — the current relay is a
// single-use dead-drop), and real-device e2e (#486). Nothing here touches prod.

import { useCallback, useEffect, useRef, useState } from 'react';
import { createRelay } from '@/lib/sync/relay';
import { shareUrlShort } from '@/lib/config/domain';
import { SimpleQRCode } from '@/components/SimpleQRCode';
import { ShardGiveDialog } from '@/components/ShardGiveDialog';
import { TrustMap } from '@/components/TrustMap';
import { useCeremony } from '@/lib/ceremony/useCeremony';
import { stepLabel, CEREMONY_STEP_ORDER, type CeremonyStepId } from '@/lib/ceremony/machine';
import type { TrustEdge } from '@/lib/trust/types';

interface CeremonyProps {
  identity: any;
  /** The owner's existing contacts — context for the lattice step + the tear target. */
  contacts?: TrustEdge[];
  /** Exit the ceremony (back to the main tabs). */
  onClose?: () => void;
}

// Emerald/gold palette matching the app shell (app/page.tsx).
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

// Which device each step happens on — drives the "on their device" framing.
const STEP_LOCUS: Record<CeremonyStepId, 'you' | 'them' | 'done'> = {
  handshake: 'you',
  card: 'them',
  edge: 'them',
  lattice: 'them',
  tear: 'you',
  complete: 'done',
};

export function Ceremony({ identity, contacts = [], onClose }: CeremonyProps) {
  const ceremony = useCeremony('initiator');
  const { state } = ceremony;

  const ownerFingerprint: string = identity?.identity?.fingerprint ?? '';
  const ownerName: string =
    identity?.identity?.name || identity?.identity?.display_name || identity?.identity?.slug || 'a keeper';

  // Step 1 — the relay handshake (QR + short link off one code).
  const [relay, setRelay] = useState<{ url: string; code: string; expiresAt: string } | null>(null);
  const [creatingRelay, setCreatingRelay] = useState(false);
  const relayStartedRef = useRef(false);

  const buildCardPackage = useCallback(() => {
    // Same shape ContactManagement.handleShareIdentity produces (type: 'identity-exchange').
    return JSON.stringify({
      version: '1.0',
      type: 'identity-exchange',
      created_at: new Date().toISOString(),
      identity: {
        fingerprint: identity.identity.fingerprint,
        display_name: identity.identity.display_name || identity.identity.slug,
        public_key: identity.identity.public_key,
        email: identity.identity.email,
      },
    });
  }, [identity]);

  const startHandshake = useCallback(async () => {
    if (relayStartedRef.current) return;
    relayStartedRef.current = true;
    setCreatingRelay(true);
    ceremony.clearError();
    try {
      const result = await createRelay(buildCardPackage());
      setRelay({ url: result.url, code: result.code, expiresAt: result.expiresAt });
      ceremony.handshakeEstablished(result.code); // machine advances handshake -> card
    } catch (err: any) {
      relayStartedRef.current = false; // allow retry
      ceremony.fail(err?.message || 'Could not create the handshake link.');
    } finally {
      setCreatingRelay(false);
    }
  }, [buildCardPackage, ceremony]);

  // Auto-generate the handshake the moment the ceremony opens on the handshake step.
  useEffect(() => {
    if (state.step === 'handshake' && !relay && !creatingRelay) {
      void startHandshake();
    }
  }, [state.step, relay, creatingRelay, startHandshake]);

  // Step 5 — the tear.
  const [showTear, setShowTear] = useState(false);
  const firstContact = contacts[0]; // demo target; a fuller build lets the giver choose
  const tearTarget = firstContact
    ? { id: firstContact.id, name: firstContact.peer_name, fingerprint: firstContact.peer_fingerprint }
    : null;

  // Manual advance for the JOINER-local middle steps (initiator guiding the other person).
  const advanceMiddle = useCallback(() => {
    switch (state.step) {
      case 'card':
        ceremony.cardConveyed('pending'); // initiator learns the peer fp only on reciprocation
        break;
      case 'edge':
        ceremony.edgePersisted('their-device'); // the edge is persisted on the joiner's device
        break;
      case 'lattice':
        ceremony.latticeRendered();
        break;
    }
  }, [state.step, ceremony]);

  const restart = useCallback(() => {
    relayStartedRef.current = false;
    setRelay(null);
    setShowTear(false);
    ceremony.reset();
  }, [ceremony]);

  return (
    <div style={{ maxWidth: 640, margin: '0 auto', padding: '8px 4px' }}>
      {/* Progress rail */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 28 }}>
        {CEREMONY_STEP_ORDER.filter((s) => s !== 'complete').map((s, i) => {
          const idx = CEREMONY_STEP_ORDER.indexOf(state.step);
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

      {/* Panel */}
      <div
        style={{
          background: C.panel,
          border: `1px solid ${C.emeraldDim}`,
          borderRadius: 16,
          padding: 32,
          textAlign: 'center',
        }}
      >
        {STEP_LOCUS[state.step] === 'them' && (
          <div
            style={{
              display: 'inline-block',
              fontSize: 10,
              letterSpacing: 2,
              textTransform: 'uppercase',
              color: C.gold,
              border: `1px solid rgba(200,168,78,0.3)`,
              borderRadius: 999,
              padding: '3px 10px',
              marginBottom: 16,
              fontFamily: "'JetBrains Mono', monospace",
            }}
          >
            On their device
          </div>
        )}

        {/* STEP 1 — handshake: QR + short link (Peter's #113925) */}
        {state.step === 'handshake' && (
          <div>
            <h2 style={headingStyle}>Show them your card</h2>
            <p style={subStyle}>They scan the code, or open the short link. Same handshake, either way.</p>
            {creatingRelay && <p style={{ color: C.faint, marginTop: 20 }}>Preparing the handshake…</p>}
            {relay && (
              <>
                <div style={{ margin: '20px auto', width: 'fit-content' }}>
                  <SimpleQRCode value={relay.url} size={220} />
                </div>
                <div style={linkBoxStyle}>
                  <div style={{ fontSize: 10, color: C.faint, letterSpacing: 1, marginBottom: 4 }}>SHORT LINK</div>
                  <code style={{ color: C.emerald, fontSize: 13, wordBreak: 'break-all' }}>
                    {shareUrlShort(relay.code)}
                  </code>
                </div>
                <button style={copyBtnStyle} onClick={() => navigator.clipboard?.writeText(relay.url)}>
                  Copy link
                </button>
              </>
            )}
          </div>
        )}

        {/* STEPS 2–4 — the joiner's device (guided) */}
        {state.step === 'card' && (
          <StepNarration
            heading="They receive your card"
            body="On their device your card appears — name, fingerprint, public key. Nothing is sent to a server; it travels through the one-time relay you just created."
            cta="They've opened it →"
            onAdvance={advanceMiddle}
          />
        )}
        {state.step === 'edge' && (
          <StepNarration
            heading="The edge goes live"
            body="They tap Connect. A trust edge is written to their device — a persisted connection between the two of you."
            cta="They've connected →"
            onAdvance={advanceMiddle}
          />
        )}
        {state.step === 'lattice' && (
          <div>
            <h2 style={headingStyle}>You appear in their constellation</h2>
            <p style={subStyle}>A new facet lights up in their trust map. Here is the constellation they are joining.</p>
            <div style={{ margin: '16px auto', maxWidth: 360 }}>
              <TrustMap ownerFingerprint={ownerFingerprint} ownerName={ownerName} contacts={contacts} />
            </div>
            <button style={primaryBtnStyle} onClick={advanceMiddle}>
              The facet is lit →
            </button>
          </div>
        )}

        {/* STEP 5 — the tear */}
        {state.step === 'tear' && (
          <div>
            <h2 style={headingStyle}>Tear off a piece</h2>
            <p style={subStyle}>
              Give them a shard of your recovery — a piece of your survivability held by someone you trust.
            </p>
            {tearTarget ? (
              <button style={primaryBtnStyle} onClick={() => setShowTear(true)}>
                Give a piece to {tearTarget.name}
              </button>
            ) : (
              <p style={{ color: C.faint, marginTop: 16, fontSize: 13 }}>
                Add them as a contact first, then return here to give a piece.
              </p>
            )}
            <ShardGiveDialog
              open={showTear}
              onClose={() => setShowTear(false)}
              ownerFingerprint={ownerFingerprint}
              ownerName={ownerName}
              contact={tearTarget}
              onGiven={() => {
                setShowTear(false);
                ceremony.shardGiven(); // machine advances tear -> complete
              }}
            />
          </div>
        )}

        {/* COMPLETE */}
        {state.step === 'complete' && (
          <div>
            <div style={{ fontSize: 40, marginBottom: 8 }}>🜂</div>
            <h2 style={headingStyle}>The ceremony is complete</h2>
            <p style={subStyle}>A card given, an edge live, a facet lit, a piece torn and entrusted.</p>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'center', marginTop: 20 }}>
              <button style={copyBtnStyle} onClick={restart}>
                Begin another
              </button>
              {onClose && (
                <button style={primaryBtnStyle} onClick={onClose}>
                  Done
                </button>
              )}
            </div>
          </div>
        )}

        {state.error && (
          <p style={{ color: C.err, marginTop: 18, fontSize: 13 }}>
            {state.error}{' '}
            <button
              onClick={() => {
                ceremony.clearError();
                if (state.step === 'handshake') void startHandshake();
              }}
              style={{ background: 'none', border: 'none', color: C.emerald, cursor: 'pointer', textDecoration: 'underline' }}
            >
              retry
            </button>
          </p>
        )}
      </div>

      {onClose && state.step !== 'complete' && (
        <div style={{ textAlign: 'center', marginTop: 16 }}>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.2)', fontSize: 12, cursor: 'pointer' }}
          >
            Leave ceremony
          </button>
        </div>
      )}
    </div>
  );
}

function StepNarration({
  heading,
  body,
  cta,
  onAdvance,
}: {
  heading: string;
  body: string;
  cta: string;
  onAdvance: () => void;
}) {
  return (
    <div>
      <h2 style={headingStyle}>{heading}</h2>
      <p style={subStyle}>{body}</p>
      <button style={primaryBtnStyle} onClick={onAdvance}>
        {cta}
      </button>
    </div>
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
const linkBoxStyle: React.CSSProperties = {
  background: 'rgba(6, 10, 8, 0.8)',
  border: `1px solid ${C.emeraldDim}`,
  borderRadius: 8,
  padding: '12px 16px',
  margin: '16px auto 12px',
  maxWidth: 360,
};
const primaryBtnStyle: React.CSSProperties = {
  background: 'rgba(52, 211, 153, 0.12)',
  border: `1px solid rgba(52, 211, 153, 0.3)`,
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
const copyBtnStyle: React.CSSProperties = {
  background: 'none',
  border: `1px solid ${C.emeraldDim}`,
  borderRadius: 8,
  padding: '10px 18px',
  color: C.faint,
  fontSize: 11,
  letterSpacing: 1,
  textTransform: 'uppercase',
  fontFamily: "'JetBrains Mono', monospace",
  cursor: 'pointer',
};
