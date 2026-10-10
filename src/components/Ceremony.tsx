// src/components/Ceremony.tsx
'use client';
//
// The 9/10 connection ceremony — one guided flow over the five canon steps.
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
// Honored here — "QR code and short link": step 1 offers BOTH entry modes
// off a single relay handshake (scan the QR, or open/enter the short link — same code).
// Deferred (tracked): the in-app camera SCANNER (short-link is the can't-fail floor),
// full live 2-device auto-advance (needs a live relay channel back — the current relay is a
// single-use dead-drop), and real-device e2e. Nothing here touches prod.

import { useCallback, useEffect, useRef, useState, type CSSProperties } from 'react';
import { createRelay } from '@/lib/sync/relay';
import { loadKey } from '@/lib/identity/client-store';
import { buildSignedIdentityCard } from '@/lib/identity/identity-card-sign';
import { shareUrlShort } from '@/lib/config/domain';
import { SimpleQRCode } from '@/components/SimpleQRCode';
import { ShardGiveDialog } from '@/components/ShardGiveDialog';
import { TrustMap } from '@/components/TrustMap';
import { useCeremony } from '@/lib/ceremony/useCeremony';
import { stepLabel, CEREMONY_STEP_ORDER, type CeremonyStepId } from '@/lib/ceremony/machine';
import type { TrustEdge } from '@/lib/trust/types';
import { solarEmber as E } from '@/components/recovery/solar-ember';

interface CeremonyProps {
  identity: any;
  /** The owner's existing contacts — context for the lattice step + the tear target. */
  contacts?: TrustEdge[];
  /** Exit the ceremony (back to the main tabs). */
  onClose?: () => void;
}

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

  // Build + SIGN the identity-exchange card (same shape ContactManagement produces). The signature
  // binds pq_kem/pq_sig to the classical key so a receiver on an untrusted carrier (QR/relay) can
  // re-verify they weren't swapped — an unsigned card is the HNDL hole. Signing needs the private
  // key ⇒ the session must be unlocked; buildSignedIdentityCard carries pq from identity.post_quantum.
  const buildCardPackage = useCallback(async () => {
    const fp = identity.identity.fingerprint;
    const key = await loadKey(fp);
    if (!key) throw new Error('Unlock your identity first to share a signed card.');
    const signed = await buildSignedIdentityCard(identity, key.privateKey, key.passphrase);
    return JSON.stringify(signed);
  }, [identity]);

  const startHandshake = useCallback(async () => {
    if (relayStartedRef.current) return;
    relayStartedRef.current = true;
    setCreatingRelay(true);
    ceremony.clearError();
    try {
      const result = await createRelay(await buildCardPackage());
      setRelay({ url: result.url, code: result.code, expiresAt: result.expiresAt });
      // Stay on 'handshake' so the QR + short link + Copy link stay visible for the hand-off.
      // Advance is manual now (button below), once the other person has scanned/opened it.
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
    <div style={{ maxWidth: 640, margin: '0 auto', padding: '8px 4px', fontFamily: E.fontSans }}>
      <div style={{ textAlign: 'center', marginBottom: 22 }}>
        <p
          style={{
            margin: 0,
            fontSize: 11,
            letterSpacing: '0.22em',
            textTransform: 'uppercase',
            color: E.accent,
            fontFamily: E.fontSans,
            fontWeight: 500,
          }}
        >
          Connection ceremony
        </p>
        <h1
          style={{
            margin: '8px 0 0',
            fontFamily: E.fontSerif,
            fontWeight: 300,
            fontSize: 28,
            letterSpacing: '0.04em',
            color: E.text,
          }}
        >
          Meet in the lattice
        </h1>
      </div>

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
                  background: done || active ? E.accent : 'rgba(249,168,37,0.12)',
                  opacity: done ? 0.55 : active ? 1 : 0.35,
                }}
              />
              <div
                style={{
                  marginTop: 6,
                  fontSize: 10,
                  letterSpacing: '0.12em',
                  textTransform: 'uppercase',
                  color: active ? E.accent : E.dim,
                  fontFamily: E.fontMono,
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
          background: E.surfaceSolid,
          border: `1px solid ${E.borderLit}`,
          borderRadius: 16,
          padding: 32,
          textAlign: 'center',
          boxShadow: '0 0 48px rgba(249,168,37,.06)',
          backdropFilter: 'blur(20px)',
        }}
      >
        {STEP_LOCUS[state.step] === 'them' && (
          <div
            style={{
              display: 'inline-block',
              fontSize: 10,
              letterSpacing: '0.16em',
              textTransform: 'uppercase',
              color: E.accent,
              border: `1px solid ${E.borderLit}`,
              borderRadius: 999,
              padding: '4px 12px',
              marginBottom: 16,
              fontFamily: E.fontMono,
            }}
          >
            On their device
          </div>
        )}

        {/* STEP 1 — handshake: QR + short link */}
        {state.step === 'handshake' && (
          <div>
            <h2 style={headingStyle}>Show them your card</h2>
            <p style={subStyle}>They scan the code, or open the short link. Same handshake, either way.</p>
            {creatingRelay && <p style={{ color: E.dim, marginTop: 20, fontFamily: E.fontSans }}>Preparing the handshake…</p>}
            {relay && (
              <>
                <div style={{ margin: '20px auto', width: 'fit-content' }}>
                  <SimpleQRCode value={relay.url} size={220} />
                </div>
                <div style={linkBoxStyle}>
                  <div style={{ fontSize: 10, color: E.dim, letterSpacing: '0.14em', marginBottom: 4, fontFamily: E.fontSans }}>
                    SHORT LINK
                  </div>
                  <code style={{ color: E.accent, fontSize: 13, wordBreak: 'break-all', fontFamily: E.fontMono }}>
                    {shareUrlShort(relay.code)}
                  </code>
                </div>
                <button style={copyBtnStyle} onClick={() => navigator.clipboard?.writeText(relay.url)}>
                  Copy link
                </button>
                <div style={{ marginTop: 20 }}>
                  <button style={primaryBtnStyle} onClick={() => ceremony.handshakeEstablished(relay.code)}>
                    They&apos;ve scanned it →
                  </button>
                </div>
              </>
            )}
          </div>
        )}

        {/* STEPS 2–4 — the joiner's device (guided) */}
        {state.step === 'card' && (
          <StepNarration
            heading="They receive your card"
            body="On their device, your card appears — name, fingerprint, public key. It reached them through the relay, encrypted; no server could read it."
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
              <p style={{ color: E.dim, marginTop: 16, fontSize: 13, fontFamily: E.fontSans }}>
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
            <div
              style={{
                width: 48,
                height: 48,
                margin: '0 auto 12px',
                borderRadius: '50%',
                border: `1px solid ${E.borderLit}`,
                boxShadow: `0 0 24px rgba(249,168,37,.2)`,
                background: 'rgba(249,168,37,.08)',
              }}
              aria-hidden
            />
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
          <p style={{ color: E.danger, marginTop: 18, fontSize: 13, fontFamily: E.fontSans }}>
            {state.error}{' '}
            <button
              onClick={() => {
                ceremony.clearError();
                if (state.step === 'handshake') void startHandshake();
              }}
              style={{ background: 'none', border: 'none', color: E.accent, cursor: 'pointer', textDecoration: 'underline', fontFamily: E.fontSans }}
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
            style={{ background: 'none', border: 'none', color: E.dim, fontSize: 12, cursor: 'pointer', fontFamily: E.fontMono, letterSpacing: '0.06em' }}
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

const headingStyle: CSSProperties = {
  fontFamily: E.fontSerif,
  fontSize: 26,
  fontWeight: 300,
  color: E.text,
  letterSpacing: '0.03em',
  margin: '0 0 8px',
};
const subStyle: CSSProperties = {
  fontFamily: E.fontSans,
  fontSize: 14,
  fontWeight: 300,
  color: E.muted,
  lineHeight: 1.65,
  maxWidth: 420,
  margin: '0 auto',
};
const linkBoxStyle: CSSProperties = {
  background: E.inputBg,
  border: `1px solid ${E.border}`,
  borderRadius: 8,
  padding: '12px 16px',
  margin: '16px auto 12px',
  maxWidth: 360,
};
const primaryBtnStyle: CSSProperties = {
  background: 'color-mix(in srgb, var(--se-accent) 12%, transparent)',
  border: `1px solid ${E.borderLit}`,
  borderRadius: 8,
  padding: '12px 22px',
  color: E.accent,
  fontSize: 12,
  fontWeight: 500,
  letterSpacing: '0.14em',
  textTransform: 'uppercase',
  fontFamily: E.fontSans,
  cursor: 'pointer',
  marginTop: 20,
};
const copyBtnStyle: CSSProperties = {
  background: 'none',
  border: `1px solid ${E.border}`,
  borderRadius: 8,
  padding: '10px 18px',
  color: E.muted,
  fontSize: 11,
  letterSpacing: '0.1em',
  textTransform: 'uppercase',
  fontFamily: E.fontMono,
  cursor: 'pointer',
};
