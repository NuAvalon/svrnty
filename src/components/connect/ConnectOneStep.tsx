'use client';

/**
 * One-step Connect-UX — paste a grow-link, see the card at the Gate, one tap
 * to Known. Persist is behind the add-logic stub (Apollo post-flip).
 *
 * Does not replace the live JoinerCeremony on /c/{code} until
 * isConnectAddLogicLive() flips.
 */

import { useCallback, useEffect, useRef, useState, type CSSProperties, type FormEvent } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import {
  landInGate,
  promoteGateToKnown,
  resolveConnectLink,
  type ConnectCard,
} from '@/lib/connect/add-logic';
import { parseConnectLink } from '@/lib/connect/parse-connect-link';
import { CONNECT_COPY } from '@/lib/connect/copy';
import { ConnectArrivalCard } from './ConnectArrivalCard';

type View = 'paste' | 'resolving' | 'arrival' | 'no_identity';

type Props = {
  hasIdentity: boolean;
  /** Skip the paste field — used when the /c/{code} route already parsed a link. */
  initialCode?: string;
  initialKeyFragment?: string | null;
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

const btnStyle = (primary?: boolean, disabled?: boolean): CSSProperties => ({
  width: '100%',
  marginTop: 12,
  padding: '12px 14px',
  borderRadius: 8,
  border: `1px solid ${primary && !disabled ? E.borderLit : E.border}`,
  background:
    primary && !disabled
      ? 'rgba(249,168,37,0.14)'
      : 'rgba(249,168,37,0.04)',
  color: primary && !disabled ? E.accent : E.dim,
  cursor: disabled ? 'default' : 'pointer',
  fontFamily: E.fontSans,
  fontSize: 12,
  fontWeight: 500,
  letterSpacing: '0.12em',
  textTransform: 'uppercase',
});

export function ConnectOneStep({
  hasIdentity,
  initialCode,
  initialKeyFragment = null,
}: Props) {
  const [input, setInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<View>(() => {
    if (!hasIdentity) return 'no_identity';
    if (initialCode) return 'resolving';
    return 'paste';
  });
  const [card, setCard] = useState<ConnectCard | null>(null);
  const [landed, setLanded] = useState(false);
  const [persistLive, setPersistLive] = useState(false);
  const startedRef = useRef(false);

  const reset = () => {
    setInput('');
    setError(null);
    setCard(null);
    setLanded(false);
    setPersistLive(false);
    startedRef.current = false;
    setView(hasIdentity ? 'paste' : 'no_identity');
  };

  const runResolve = useCallback(async (code: string, keyFragment: string | null) => {
    setView('resolving');
    setError(null);
    const resolved = await resolveConnectLink({ code, keyFragment });
    if (!resolved.ok) {
      if (resolved.reason === 'not_wired') {
        setCard(null);
        setLanded(false);
        setPersistLive(false);
        setView('arrival');
        return;
      }
      setError(
        resolved.reason === 'invalid' ? CONNECT_COPY.invalidLink : CONNECT_COPY.unavailable,
      );
      setView('paste');
      return;
    }
    setCard(resolved.card);
    const land = await landInGate(resolved.card);
    setLanded(land.ok && land.state === 'gate');
    setPersistLive(land.ok);
    setView('arrival');
  }, []);

  useEffect(() => {
    if (!hasIdentity) {
      setView('no_identity');
      return;
    }
    if (!initialCode || startedRef.current) return;
    startedRef.current = true;
    void runResolve(initialCode, initialKeyFragment ?? null);
  }, [hasIdentity, initialCode, initialKeyFragment, runResolve]);

  const onOpen = (e?: FormEvent) => {
    e?.preventDefault();
    if (!hasIdentity) {
      setView('no_identity');
      return;
    }
    const parsed = parseConnectLink(input);
    if (!parsed) {
      // INV-5: fixed string — never interpolate the paste (it may carry a #key).
      setError(CONNECT_COPY.invalidLink);
      return;
    }
    setError(null);
    void runResolve(parsed.code, parsed.keyFragment);
  };

  const onAddKnown = async () => {
    if (!card?.fingerprint || !persistLive) return;
    const r = await promoteGateToKnown(card.fingerprint, 'known');
    if (!r.ok) {
      setPersistLive(false);
    }
  };

  if (view === 'no_identity') {
    return (
      <div data-testid="connect-one-step">
        <p
          style={{
            margin: 0,
            fontSize: 11,
            letterSpacing: '0.2em',
            textTransform: 'uppercase',
            color: E.accent,
          }}
        >
          {CONNECT_COPY.kicker}
        </p>
        <h2 style={{ margin: '8px 0 0', fontSize: 22, fontWeight: 400, color: E.text }}>
          {CONNECT_COPY.noIdentityTitle}
        </h2>
        <p style={{ margin: '10px 0 0', fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
          {CONNECT_COPY.noIdentityBody}
        </p>
        <a href="/" style={{ ...btnStyle(true), display: 'block', textAlign: 'center', textDecoration: 'none' }}>
          {CONNECT_COPY.createIdentity}
        </a>
      </div>
    );
  }

  if (view === 'resolving') {
    return (
      <div data-testid="connect-one-step">
        <p style={{ margin: 0, fontSize: 13, color: E.muted }}>{CONNECT_COPY.resolving}</p>
      </div>
    );
  }

  if (view === 'arrival') {
    const canPromote = persistLive && landed && Boolean(card?.fingerprint);
    return (
      <div data-testid="connect-one-step">
        <p
          style={{
            margin: 0,
            fontSize: 11,
            letterSpacing: '0.2em',
            textTransform: 'uppercase',
            color: E.accent,
          }}
        >
          {CONNECT_COPY.kicker}
        </p>
        <h2
          data-testid="connect-arrival"
          style={{ margin: '8px 0 0', fontSize: 22, fontWeight: 400, color: E.text }}
        >
          {CONNECT_COPY.waitingAtGate}
        </h2>
        <p style={{ margin: '10px 0 0', fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
          {CONNECT_COPY.addToKnownHint}
        </p>
        <p style={{ margin: '8px 0 0', fontSize: 12, color: E.dim, lineHeight: 1.5 }}>
          {CONNECT_COPY.localOnly}
        </p>
        <p style={{ margin: '8px 0 0', fontSize: 12, color: E.dim, lineHeight: 1.5 }}>
          {CONNECT_COPY.invitationNotCapture}
        </p>
        {!persistLive ? (
          <p
            data-testid="connect-not-wired"
            style={{ margin: '12px 0 0', fontSize: 13, color: E.muted, lineHeight: 1.5 }}
          >
            {CONNECT_COPY.notWired}
          </p>
        ) : null}
        <ConnectArrivalCard card={card} />
        <button
          type="button"
          data-testid="connect-add-known"
          disabled={!canPromote}
          onClick={() => void onAddKnown()}
          style={btnStyle(true, !canPromote)}
        >
          {canPromote ? CONNECT_COPY.addToKnown : CONNECT_COPY.notWiredButton}
        </button>
        <button type="button" onClick={reset} style={btnStyle(false)}>
          {CONNECT_COPY.back}
        </button>
      </div>
    );
  }

  return (
    <form data-testid="connect-one-step" onSubmit={onOpen}>
      <p
        style={{
          margin: 0,
          fontSize: 11,
          letterSpacing: '0.2em',
          textTransform: 'uppercase',
          color: E.accent,
        }}
      >
        {CONNECT_COPY.kicker}
      </p>
      <h2 style={{ margin: '8px 0 0', fontSize: 22, fontWeight: 400, color: E.text }}>
        {CONNECT_COPY.pasteLabel}
      </h2>
      <p style={{ margin: '10px 0 0', fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
        {CONNECT_COPY.pasteHint}
      </p>
      <label
        htmlFor="connect-paste-input"
        style={{ display: 'block', marginTop: 16, fontSize: 13, color: E.muted }}
      >
        {CONNECT_COPY.pasteLabel}
      </label>
      <textarea
        id="connect-paste-input"
        data-testid="connect-paste-input"
        value={input}
        onChange={(e) => {
          setInput(e.target.value);
          if (error) setError(null);
        }}
        placeholder="https://svrnty.is/c/…"
        rows={3}
        aria-label={CONNECT_COPY.pasteLabel}
        style={{
          ...fieldStyle,
          border: `1px solid ${error ? E.danger : E.border}`,
        }}
      />
      {error ? (
        <p style={{ margin: '10px 0 0', fontSize: 12, color: E.danger, lineHeight: 1.5 }}>
          {error}
        </p>
      ) : null}
      <button
        type="submit"
        data-testid="connect-open"
        disabled={!input.trim()}
        style={btnStyle(true, !input.trim())}
      >
        {CONNECT_COPY.open}
      </button>
    </form>
  );
}
