'use client';

/**
 * The sign card, the refusal card and the hand-back. PRESENTATIONAL: it renders what buildCardModel / buildHandBackModel return and holds no decision.
 * Every rule about WHETHER Approve exists lives in compose-card-model.ts; this file only has to never draw one the model did not offer.
 *
 * What the screen guarantees (Hypatia §3/§4, Flint S2/R2/R3/G1):
 *   - The body is shown in FULL, in a pre-wrap block: no truncation, no inner scroll box, no "show more". The dialog itself scrolls on a small screen.
 *   - Approve comes AFTER the end of the body (and after the words and the footnote), never above or beside it.
 *   - Default focus is "Don't sign", never Approve, so Enter/Space cannot sign by reflex. Escape = don't sign.
 *   - Approve is disabled for the first APPROVE_ARM_MS after EVERY card change (the timer is keyed on the card's nonce), so a stray tap as a card slides in
 *     is ignored. This is anti-misclick UI ONLY, NOT a security boundary (Flint's ruling, lane:portal #1485): the real control is controller.approve(nonce),
 *     which signs nothing unless the nonce is the card the person SAW. No test may treat the delay as a security property.
 *   - A refusal card has ONE button, Close. There is no way to sign from it.
 *   - The hand-back never says posted, sent or delivered; it says "Signed. Not posted yet."
 */

import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { solarEmber as E, solarGlass } from '@/components/recovery/solar-ember';
import type { CardModel, SignCardModel, RefusedCardModel } from '@/lib/compose/compose-card-model';
import { CARD_COPY } from '@/lib/compose/compose-card-copy';
import type { HandBackModel } from '@/lib/compose/compose-handback';

/** How long a freshly shown card ignores Approve. */
export const APPROVE_ARM_MS = 600;

const overlay: React.CSSProperties = {
  position: 'fixed',
  inset: 0,
  zIndex: 90,
  background: 'rgba(8, 5, 3, 0.78)',
  display: 'flex',
  alignItems: 'flex-start',
  justifyContent: 'center',
  padding: 16,
  overflowY: 'auto',
};

const dialog: React.CSSProperties = {
  ...solarGlass,
  width: '100%',
  maxWidth: 520,
  margin: 'auto',
  padding: '22px 22px 18px',
  color: E.text,
  fontFamily: E.fontSans,
  textAlign: 'left',
};

const btn = (primary: boolean): React.CSSProperties => ({
  flex: 1,
  minHeight: 44,
  background: primary ? 'color-mix(in srgb, var(--se-accent) 14%, transparent)' : 'transparent',
  border: `1px solid ${primary ? E.borderLit : E.border}`,
  borderRadius: 8,
  color: primary ? E.accent : E.muted,
  cursor: 'pointer',
  fontFamily: E.fontSans,
  fontWeight: 600,
});

function Shell({ testId, labelId, onEscape, children }: { testId: string; labelId: string; onEscape: () => void; children: React.ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    // Focus the safe button if there is one, else the dialog itself. NEVER an Approve.
    const safe = ref.current?.querySelector<HTMLElement>('[data-default-focus="true"]');
    (safe ?? ref.current)?.focus();
  }, []);
  return createPortal(
    <div role="presentation" style={overlay} data-testid={`${testId}-overlay`}>
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelId}
        tabIndex={-1}
        data-testid={testId}
        onKeyDown={(e) => {
          if (e.key === 'Escape') {
            e.stopPropagation();
            onEscape();
          }
        }}
        style={dialog}
      >
        {children}
      </div>
    </div>,
    document.body,
  );
}

function SignCard({ card, nonce, busy, onApprove, onDecline }: { card: SignCardModel; nonce: string | null; busy: boolean; onApprove: () => void; onDecline: () => void }) {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    setArmed(false);
    const t = setTimeout(() => setArmed(true), APPROVE_ARM_MS);
    return () => clearTimeout(t);
  }, [nonce]);
  return (
    <Shell testId="compose-card" labelId="compose-card-title" onEscape={onDecline}>
      <h2 id="compose-card-title" style={{ margin: '0 0 8px', fontSize: 16, color: E.text }}>{card.title}</h2>
      <p data-testid="compose-card-intro" style={{ margin: '0 0 10px', fontSize: 13, lineHeight: 1.45, color: E.muted }}>{card.intro}</p>
      {card.location !== null ? <p data-testid="compose-card-location" style={{ margin: '0 0 10px', fontSize: 13, color: E.text }}>{card.location}</p> : null}
      {card.toLine !== null ? <p data-testid="compose-card-to" style={{ margin: '0 0 6px', fontSize: 13, color: E.text }}>{card.toLine}</p> : null}
      {card.taskTitle !== null ? <p data-testid="compose-card-task-title" style={{ margin: '0 0 10px', fontSize: 14, fontWeight: 600, color: E.text, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{card.taskTitle}</p> : null}
      <div
        data-testid="compose-card-body"
        style={{ margin: '0 0 12px', padding: '10px 12px', border: `1px solid ${E.border}`, borderRadius: 8, background: E.inputBg, fontSize: 14, lineHeight: 1.5, color: E.text, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}
      >
        {card.body}
      </div>
      {card.linkedLine !== null ? <p data-testid="compose-card-linked" style={{ margin: '0 0 10px', fontSize: 13, color: E.muted }}>{card.linkedLine}</p> : null}
      {card.wordsLine !== null ? <p data-testid="compose-card-words" style={{ margin: '0 0 10px', fontSize: 14, fontWeight: 600, color: E.accent }}>{card.wordsLine}</p> : null}
      {card.noWordsNotice !== null ? <p data-testid="compose-card-no-words" role="status" style={{ margin: '0 0 10px', fontSize: 13, color: E.muted }}>{card.noWordsNotice}</p> : null}
      {card.weftNotice !== null ? <p data-testid="compose-card-weft" role="status" style={{ margin: '0 0 10px', fontSize: 13, color: E.muted }}>{card.weftNotice}</p> : null}
      <p data-testid="compose-card-footnote" style={{ margin: '0 0 16px', fontSize: 12, lineHeight: 1.45, color: E.muted }}>{card.footnote}</p>
      <div style={{ display: 'flex', gap: 8 }}>
        <button type="button" data-testid="compose-decline" data-default-focus="true" onClick={onDecline} style={btn(false)}>{card.decline}</button>
        {card.approve !== null ? (
          <button
            type="button"
            data-testid="compose-approve"
            disabled={!armed || busy}
            onClick={onApprove}
            style={{ ...btn(true), opacity: armed && !busy ? 1 : 0.55, cursor: armed && !busy ? 'pointer' : 'default' }}
          >
            {card.approve}
          </button>
        ) : null}
      </div>
    </Shell>
  );
}

function RefusedCard({ card, onClose }: { card: RefusedCardModel; onClose: () => void }) {
  return (
    <Shell testId="compose-refused" labelId="compose-refused-title" onEscape={onClose}>
      <h2 id="compose-refused-title" style={{ margin: '0 0 8px', fontSize: 16, color: E.text }}>{card.title}</h2>
      <p data-testid="compose-refused-notice" style={{ margin: '0 0 10px', fontSize: 13, lineHeight: 1.45, color: E.muted }}>{card.notice}</p>
      {card.segments.length > 0 ? (
        <div
          data-testid="compose-refused-text"
          style={{ margin: '0 0 16px', padding: '10px 12px', border: `1px solid ${E.border}`, borderRadius: 8, background: E.inputBg, fontSize: 14, lineHeight: 1.5, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}
        >
          {card.segments.map((s, i) =>
            s.marker ? (
              <span key={i} data-testid="compose-refused-marker" style={{ color: E.danger, fontWeight: 700 }}>{s.text}</span>
            ) : (
              <span key={i} style={{ color: E.text }}>{s.text}</span>
            ),
          )}
        </div>
      ) : null}
      <div style={{ display: 'flex', gap: 8 }}>
        <button type="button" data-testid="compose-close" data-default-focus="true" onClick={onClose} style={btn(false)}>{card.close}</button>
      </div>
    </Shell>
  );
}

/** A signature attempt failed (Hypatia §6d): fixed text and ONE Close. Never the error's own text; nothing here says anything was signed or posted. */
export function ComposeFailedCard({ notice, close, onClose }: { notice: string; close: string; onClose: () => void }) {
  return (
    <Shell testId="compose-failed" labelId="compose-failed-title" onEscape={onClose}>
      <h2 id="compose-failed-title" style={{ margin: '0 0 8px', fontSize: 16, color: E.text }}>{CARD_COPY.post.title}</h2>
      <p data-testid="compose-failed-notice" style={{ margin: '0 0 16px', fontSize: 13, lineHeight: 1.45, color: E.muted }}>{notice}</p>
      <div style={{ display: 'flex', gap: 8 }}>
        <button type="button" data-testid="compose-failed-close" data-default-focus="true" onClick={onClose} style={btn(false)}>{close}</button>
      </div>
    </Shell>
  );
}

export function ComposeHandBack({ model, onDone }: { model: HandBackModel; onDone: () => void }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(model.json);
      setCopied(true);
    } catch {
      setCopied(false); // never claim "Copied." when the browser refused; the text above stays selectable
    }
  };
  return (
    <Shell testId="compose-handback" labelId="compose-handback-title" onEscape={onDone}>
      <h2 id="compose-handback-title" style={{ margin: '0 0 8px', fontSize: 16, color: E.text }}>{model.title}</h2>
      <p data-testid="compose-handback-body" style={{ margin: '0 0 10px', fontSize: 13, lineHeight: 1.45, color: E.muted }}>{model.body}</p>
      <pre
        data-testid="compose-handback-json"
        style={{ margin: '0 0 12px', padding: '10px 12px', border: `1px solid ${E.border}`, borderRadius: 8, background: E.inputBg, fontFamily: E.fontMono, fontSize: 12, lineHeight: 1.45, color: E.text, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', userSelect: 'all' }}
      >
        {model.json}
      </pre>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <button type="button" data-testid="compose-handback-copy" data-default-focus="true" onClick={() => void copy()} style={btn(true)}>{model.copy}</button>
        <button type="button" data-testid="compose-handback-done" onClick={onDone} style={btn(false)}>Close</button>
      </div>
      {copied ? <p data-testid="compose-handback-copied" role="status" style={{ margin: '10px 0 0', fontSize: 12, color: E.ok }}>{model.copied}</p> : null}
    </Shell>
  );
}

export function ComposeCardView({
  card,
  nonce,
  busy,
  onApprove,
  onDecline,
}: {
  card: CardModel;
  nonce: string | null;
  busy: boolean;
  onApprove: () => void;
  onDecline: () => void;
}) {
  return card.mode === 'sign' ? (
    <SignCard card={card} nonce={nonce} busy={busy} onApprove={onApprove} onDecline={onDecline} />
  ) : (
    <RefusedCard card={card} onClose={onDecline} />
  );
}
