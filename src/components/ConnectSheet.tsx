'use client';

// src/components/ConnectSheet.tsx
//
// Connect-UX — the one-step grow-link flow (CURSOR_QUEUE.md #3).
// Paste a connect link → resolve → the newcomer lands in your GATE (pending)
// → ONE tap promotes to Known. Replaces the multi-step ceremony on the
// in-app paste/scan path; the /c/ route's JoinerCeremony still owns direct
// link landings (Apollo rewires post-flip).
//
// Everything trust-touching goes through ConnectAddLogic — this file never
// implements resolve/gate/trust plumbing itself.
//
// INVARIANTS (queue §TRUST-MODEL — render-honored, not restated):
//   • Gate-not-Known on arrival — the card view's only consent action is the
//     explicit "Add to Known" tap; nothing promotes implicitly.
//   • Adding is LOCAL + one-sided — your disclosure choice, never a mutual
//     assertion. The copy below says exactly that.
//   • The link carries the newcomer's consent-to-be-added (invitation, not
//     capture) — resolve only reads what they published.
//   • Entity-type is labeled "attested" (never "verified"); absent type shows
//     "not yet attested" — an honest UNKNOWN, never a guess.
//   • Card fields are UNTRUSTED — rendered escaped + bounded, never
//     dangerouslySetInnerHTML, never echoed raw input (the fragment is key
//     material: never rendered, never logged).

import { useCallback, useEffect, useRef, useState, type CSSProperties } from 'react';
import {
  createConnectAddLogic,
  type ConnectAddLogic,
  type ConnectLinkCard,
  type ConnectLinkParse,
  type ConnectResolveRefusal,
  type GateLanding,
} from '@/lib/connect/add-logic';
import { dismissGateArrival } from '@/lib/trust/grow-gate';
import { formatFingerprintForVerify } from '@/lib/trust/trust-recipe';
import { solarEmber as E } from '@/components/recovery/solar-ember';

type Phase = 'paste' | 'resolving' | 'card' | 'done' | 'error';

type Props = {
  open: boolean;
  onClose: () => void;
  ownerFp: string;
  /** Pre-parsed link (from the Grow paste field / scan). When absent the sheet
   *  shows its own paste field (standalone use). */
  link?: ConnectLinkParse | null;
  /** Injectable for tests — defaults to the real seam. */
  logic?: ConnectAddLogic;
  /** Fired after a promote so the parent can refresh the book/galaxy. */
  onAdmitted?: (fingerprint: string) => void;
};

// Fixed, non-leaky refusal copy. `resolve-failed` may append the relay's own
// honest message; nothing else ever interpolates card or input data.
const REFUSAL_COPY: Record<ConnectResolveRefusal, string> = {
  'bad-link': "That doesn't look like a svrnty connect link. Paste the full link or the code.",
  unwired:
    "That link's format isn't live yet — ask them for their full connect link (it carries the key after the #).",
  'resolve-failed':
    "This link isn't available. It may have expired, been copied incompletely, or no longer be held by the relay. Ask them for a new one.",
  'unverified-card':
    'This card could not be verified — its fingerprint does not match its key, so nothing was added. Ask them for a fresh link.',
  'not-a-card':
    "That link opens something else — not a connect card. If it's a recovery piece, open it in your browser.",
};

const ENTITY_COPY: Record<ConnectLinkCard['entityType'], string> = {
  human: 'human · attested',
  agent: 'agent · attested',
  organization: 'organization · attested',
  unknown: 'not yet attested',
};

const fieldStyle: CSSProperties = {
  marginTop: 6,
  width: '100%',
  boxSizing: 'border-box',
  background: E.inputBg,
  border: `1px solid ${E.border}`,
  borderRadius: 8,
  color: E.text,
  padding: '10px 12px',
  fontFamily: E.fontMono,
  fontSize: 12,
  resize: 'vertical',
};

const btnStyle = (primary?: boolean, enabled = true): CSSProperties => ({
  width: '100%',
  padding: '12px 14px',
  borderRadius: 8,
  border: `1px solid ${primary && enabled ? E.borderLit : E.border}`,
  background: primary && enabled ? 'rgba(249,168,37,0.14)' : 'rgba(249,168,37,0.04)',
  color: primary && enabled ? E.accent : E.dim,
  cursor: enabled ? 'pointer' : 'default',
  fontFamily: E.fontSans,
  fontSize: 12,
  fontWeight: 500,
  letterSpacing: '0.12em',
  textTransform: 'uppercase',
});

const linklessBtn: CSSProperties = {
  width: '100%',
  padding: '10px',
  border: 'none',
  background: 'none',
  color: E.dim,
  cursor: 'pointer',
  fontFamily: E.fontSans,
  fontSize: 12,
};

export function ConnectSheet({ open, onClose, ownerFp, link, logic, onAdmitted }: Props) {
  const [logicRef] = useState<ConnectAddLogic>(() => logic ?? createConnectAddLogic());
  const [phase, setPhase] = useState<Phase>(link ? 'resolving' : 'paste');
  const [input, setInput] = useState('');
  const [pasteError, setPasteError] = useState<string | null>(null);
  const [card, setCard] = useState<ConnectLinkCard | null>(null);
  const [landing, setLanding] = useState<GateLanding | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const cancelRef = useRef(0);

  const reset = useCallback(() => {
    cancelRef.current += 1;
    setPhase(link ? 'resolving' : 'paste');
    setInput('');
    setPasteError(null);
    setCard(null);
    setLanding(null);
    setError(null);
    setBusy(false);
  }, [link]);

  useEffect(() => {
    if (!open) reset();
  }, [open, reset]);

  // The single flow: resolve → auto-land in the Gate (the spec's step 3 — a
  // pending holding room, never a trust act; the only consent action is the
  // promote tap).
  const runFlow = useCallback(
    async (parsed: ConnectLinkParse) => {
      const ticket = ++cancelRef.current;
      setPhase('resolving');
      try {
        const r = await logicRef.resolve(parsed);
        if (ticket !== cancelRef.current) return;
        if (!r.ok) {
          setError(
            r.refusal === 'resolve-failed' && r.detail
              ? `${REFUSAL_COPY['resolve-failed']} ${r.detail}`
              : REFUSAL_COPY[r.refusal],
          );
          setPhase('error');
          return;
        }
        const land = await logicRef.landInGate(ownerFp, r.card);
        if (ticket !== cancelRef.current) return;
        if (land.kind === 'refused') {
          setError('This card is missing its identity — nothing was added.');
          setPhase('error');
          return;
        }
        setCard(r.card);
        setLanding(land);
        setPhase('card');
      } catch {
        if (ticket !== cancelRef.current) return;
        setError(REFUSAL_COPY['resolve-failed']);
        setPhase('error');
      }
    },
    [logicRef, ownerFp],
  );

  // A pre-parsed link (Grow paste / scan mount) drives the flow once per open.
  const linkRanRef = useRef(false);
  useEffect(() => {
    if (!open) linkRanRef.current = false;
    if (!open || !link || linkRanRef.current) return;
    linkRanRef.current = true;
    void runFlow(link);
  }, [open, link, runFlow]);

  const handlePasteJoin = () => {
    const parsed = logicRef.parseConnectLink(input);
    if (!parsed) {
      // fixed string — never echoes the pasted raw (it may carry the #key)
      setPasteError(REFUSAL_COPY['bad-link']);
      return;
    }
    setPasteError(null);
    void runFlow(parsed);
  };

  const promote = useCallback(async () => {
    if (busy || !landing || landing.kind === 'already-known' || landing.kind === 'refused') return;
    setBusy(true);
    setError(null);
    try {
      const rec = await logicRef.promoteToKnown(ownerFp, landing.arrival, {});
      onAdmitted?.(rec.fingerprint ?? landing.arrival.fingerprint);
      setPhase('done');
    } catch (e) {
      setError(e instanceof Error && e.message ? e.message : 'Could not add them to Known.');
    } finally {
      setBusy(false);
    }
  }, [busy, landing, logicRef, ownerFp, onAdmitted]);

  const dismiss = useCallback(async () => {
    if (busy || !landing || landing.kind === 'already-known' || landing.kind === 'refused') return;
    setBusy(true);
    try {
      await dismissGateArrival(ownerFp, landing.arrival.fingerprint);
      onClose();
    } catch (e) {
      setError(e instanceof Error && e.message ? e.message : 'Could not dismiss.');
    } finally {
      setBusy(false);
    }
  }, [busy, landing, ownerFp, onClose]);

  if (!open) return null;

  const body = (
    <>
      {phase === 'paste' && (
        <>
          <p style={{ margin: 0, fontSize: 11, letterSpacing: '0.2em', textTransform: 'uppercase', color: E.accent }}>
            Add a connection
          </p>
          <h2 style={{ margin: '8px 0 0', fontSize: 22, fontWeight: 400, color: E.text }}>Connect by link</h2>
          <p style={{ margin: '10px 0 0', fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
            Paste their connect link — they land in your Gate, never straight into your book. You decide
            who becomes Known.
          </p>
          <label htmlFor="connect-link-input" style={{ display: 'block', marginTop: 18, fontSize: 13, color: E.muted }}>
            Paste a connect link
          </label>
          <textarea
            id="connect-link-input"
            data-testid="connect-link-input"
            value={input}
            onChange={(e) => {
              setInput(e.target.value);
              if (pasteError) setPasteError(null);
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey && input.trim()) {
                e.preventDefault();
                handlePasteJoin();
              }
            }}
            placeholder="svrnty.is/c/…"
            rows={3}
            aria-label="Paste a connect link"
            autoFocus
            style={{ ...fieldStyle, border: `1px solid ${pasteError ? E.danger : E.border}` }}
          />
          {pasteError && (
            <p style={{ margin: '10px 0 0', fontSize: 12, color: E.danger, lineHeight: 1.5 }}>{pasteError}</p>
          )}
          <button
            type="button"
            data-testid="connect-link-join"
            onClick={handlePasteJoin}
            disabled={!input.trim()}
            style={{ ...btnStyle(true, Boolean(input.trim())), marginTop: 16 }}
          >
            Connect
          </button>
        </>
      )}

      {phase === 'resolving' && (
        <div style={{ textAlign: 'center', padding: '24px 0' }}>
          <h2 style={{ margin: '8px 0 0', fontSize: 20, fontWeight: 400, color: E.text }}>
            Opening the secure channel…
          </h2>
          <p style={{ margin: '10px 0 0', fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
            Retrieving and decrypting their card.
          </p>
        </div>
      )}

      {phase === 'card' && card && (
        <>
          <p style={{ margin: 0, fontSize: 11, letterSpacing: '0.2em', textTransform: 'uppercase', color: E.accent }}>
            {landing?.kind === 'already-known' ? 'Already in your book' : 'At your Gate'}
          </p>
          <h2 style={{ margin: '8px 0 0', fontSize: 22, fontWeight: 400, color: E.text }}>
            {card.displayName || 'Unknown'} wants to connect
          </h2>
          <p style={{ margin: '10px 0 0', fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
            {landing?.kind === 'already-known'
              ? "They're already in your book — nothing new was added."
              : 'They shared their card with you. They wait at your Gate — not a star yet. Adding is your call alone.'}
          </p>

          <div
            style={{
              marginTop: 16,
              padding: '12px 14px',
              borderRadius: 10,
              border: `1px solid ${E.border}`,
              background: 'rgba(249,168,37,0.05)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 8 }}>
              <span style={{ fontSize: 11, letterSpacing: '0.12em', color: E.dim, textTransform: 'uppercase' }}>
                Fingerprint
              </span>
              <span
                data-testid="connect-entity-type"
                style={{ fontSize: 11, color: card.entityType === 'unknown' ? E.dim : E.accent }}
              >
                {ENTITY_COPY[card.entityType]}
              </span>
            </div>
            <code
              data-testid="connect-card-fp"
              style={{
                display: 'block',
                marginTop: 6,
                fontSize: 12,
                color: E.accent,
                wordBreak: 'break-all',
                fontFamily: E.fontMono,
              }}
            >
              {formatFingerprintForVerify(card.fingerprint)}
            </code>
          </div>

          {error && <p style={{ color: E.danger, fontSize: 13, marginTop: 12 }}>{error}</p>}

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 18 }}>
            {landing?.kind === 'already-known' ? (
              <button type="button" data-testid="connect-done-close" onClick={onClose} style={btnStyle(true)}>
                Done
              </button>
            ) : (
              <>
                <button
                  type="button"
                  data-testid="connect-promote-known"
                  disabled={busy}
                  onClick={() => void promote()}
                  style={btnStyle(true, !busy)}
                >
                  {busy ? '…' : 'Add to Known'}
                </button>
                <button type="button" data-testid="connect-leave-gate" disabled={busy} onClick={onClose} style={btnStyle()}>
                  Leave at the Gate
                </button>
                <button
                  type="button"
                  data-testid="connect-dismiss"
                  disabled={busy}
                  onClick={() => void dismiss()}
                  style={linklessBtn}
                >
                  Dismiss — not for me
                </button>
              </>
            )}
          </div>
        </>
      )}

      {phase === 'done' && card && (
        <div style={{ textAlign: 'center', padding: '16px 0' }}>
          <h2 style={{ margin: '8px 0 0', fontSize: 22, fontWeight: 400, color: E.text }}>
            {card.displayName || 'They'} is a star you Know
          </h2>
          <p style={{ margin: '10px 0 0', fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
            Verify is a later tap — it stays yours. Trust needs both sides.
          </p>
          <button
            type="button"
            data-testid="connect-done-close"
            onClick={onClose}
            style={{ ...btnStyle(true), marginTop: 18 }}
          >
            Done
          </button>
        </div>
      )}

      {phase === 'error' && (
        <>
          <h2 style={{ margin: '8px 0 0', fontSize: 20, fontWeight: 400, color: E.text }}>
            Couldn&apos;t connect
          </h2>
          <p style={{ margin: '10px 0 0', fontSize: 13, color: E.danger, lineHeight: 1.5 }}>{error}</p>
          <button type="button" data-testid="connect-error-back" onClick={reset} style={{ ...btnStyle(), marginTop: 18 }}>
            Back
          </button>
        </>
      )}

      {phase === 'paste' && (
        <button type="button" onClick={onClose} style={{ ...linklessBtn, marginTop: 12 }}>
          Cancel
        </button>
      )}
    </>
  );

  return (
    <div
      role="dialog"
      aria-label="Connect by link"
      data-testid="connect-sheet"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 92,
        background: 'rgba(8,5,3,.78)',
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        padding: '72px 16px 24px',
      }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: 420,
          maxHeight: 'calc(100vh - 96px)',
          overflowY: 'auto',
          background: E.surfaceSolid,
          border: `1px solid ${E.borderLit}`,
          borderRadius: 16,
          padding: 24,
          boxShadow: '0 0 48px rgba(249,168,37,.08)',
          fontFamily: E.fontSans,
        }}
      >
        {body}
      </div>
    </div>
  );
}
