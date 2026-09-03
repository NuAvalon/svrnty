'use client';

/**
 * Join by link — Component A of the in-page join.
 *
 * Paste an invite link someone shared → parse it through the ONE security boundary
 * (parseInviteUrl, INV-4) → mount the SAME <JoinerCeremony> INLINE (no router nav → also
 * sidesteps the /c/ post-join session-lock T2.6). This is the manual-entry counterpart to
 * opening a /c/ link, and the permanent fallback for when a camera scan isn't available.
 *
 * INVARIANTS:
 *  INV-1  one join path — we ONLY mount JoinerCeremony; zero parallel join/verify/trust logic.
 *  INV-2  perception ≠ trust — parsing confers no trust; the human COMMIT inside the ceremony
 *         is the sole trust-conferring act. We never auto-commit.
 *  INV-4  parseInviteUrl is the security boundary — total + host-pinned; rejects BEFORE mount.
 *  INV-5  keyFragment is key material — this component NEVER logs / echoes the raw input or the
 *         parsed keyFragment. The error text is a FIXED string (no interpolation of user input),
 *         so a pasted full URL can never leak its #fragment into the DOM, a toast, or telemetry.
 *  INV-6  no silent loss — an unparseable paste surfaces an explicit, honest inline error.
 */

import { useState } from 'react';
import { JoinerCeremony } from '@/components/JoinerCeremony';
import { parseInviteUrl, type ParsedInvite } from '@/lib/invite/parseInviteUrl';
import { solarEmber as E } from '@/components/recovery/solar-ember';

type Props = {
  open: boolean;
  /** Called on close. Parent should refresh contacts here so a just-joined edge appears. */
  onClose: () => void;
};

export function JoinByCode({ open, onClose }: Props) {
  const [input, setInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [invite, setInvite] = useState<ParsedInvite | null>(null);

  const reset = () => {
    setInput('');
    setError(null);
    setInvite(null);
  };

  const handleClose = () => {
    reset();
    onClose();
  };

  const handleJoin = () => {
    // INV-4: the untrusted paste crosses the trust boundary here and only here.
    const parsed = parseInviteUrl(input);
    if (!parsed) {
      // INV-5: fixed message — NEVER echo `input` (it carries the #key). Surface no fragment.
      setError(
        "That doesn't look like a svrnty invite link. Paste the whole link — it includes the key after the # (e.g. svrnty.is/c/…#…).",
      );
      return;
    }
    setError(null);
    setInvite(parsed); // INV-2: this only MOUNTS the ceremony; the human still commits inside it.
  };

  if (!open) return null;

  // Joining: mount the SAME ceremony the /c/ route uses, full-screen, no nav (INV-1).
  if (invite) {
    return (
      <div
        style={{
          position: 'fixed',
          inset: 0,
          zIndex: 90,
          overflowY: 'auto',
          background: E.bgCss,
        }}
      >
        <button
          type="button"
          onClick={handleClose}
          aria-label="Close"
          style={{
            position: 'fixed',
            top: 16,
            left: 16,
            zIndex: 91,
            padding: '6px 12px',
            borderRadius: 999,
            border: `1px solid ${E.borderLit}`,
            background: 'rgba(8,5,3,.72)',
            color: E.text,
            cursor: 'pointer',
            fontFamily: E.fontSans,
            fontSize: 12,
          }}
        >
          ← Back
        </button>
        <JoinerCeremony code={invite.code} keyFragment={invite.keyFragment} />
      </div>
    );
  }

  // Paste view.
  return (
    <div
      role="dialog"
      aria-label="Join by link"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 80,
        background: 'rgba(8,5,3,.72)',
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        padding: '72px 16px 24px',
      }}
      onClick={handleClose}
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
        <p
          style={{
            margin: 0,
            fontSize: 11,
            letterSpacing: '0.2em',
            textTransform: 'uppercase',
            color: E.accent,
          }}
        >
          Add a connection
        </p>
        <h2 style={{ margin: '8px 0 0', fontSize: 22, fontWeight: 400, color: E.text }}>
          Join by link
        </h2>
        <p style={{ margin: '10px 0 0', fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
          Paste an invite link someone shared with you. It opens the same connection ceremony as
          tapping the link — right here, without leaving the page.
        </p>

        <label
          htmlFor="join-invite-input"
          style={{ display: 'block', marginTop: 18, fontSize: 13, color: E.muted }}
        >
          Invite link
        </label>
        <textarea
          id="join-invite-input"
          value={input}
          onChange={(e) => {
            setInput(e.target.value);
            if (error) setError(null);
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey && input.trim()) {
              e.preventDefault();
              handleJoin();
            }
          }}
          placeholder="https://svrnty.is/c/…#…"
          rows={3}
          aria-label="Paste your invite link"
          autoFocus
          style={{
            marginTop: 6,
            width: '100%',
            boxSizing: 'border-box',
            background: E.inputBg,
            border: `1px solid ${error ? E.danger : E.border}`,
            borderRadius: 8,
            color: E.text,
            padding: '10px 12px',
            fontFamily: E.fontMono,
            fontSize: 12,
            resize: 'vertical',
          }}
        />

        {error && (
          <p style={{ margin: '10px 0 0', fontSize: 12, color: E.danger, lineHeight: 1.5 }}>
            {error}
          </p>
        )}

        <button
          type="button"
          onClick={handleJoin}
          disabled={!input.trim()}
          style={{
            marginTop: 16,
            width: '100%',
            padding: '12px 14px',
            borderRadius: 8,
            border: `1px solid ${input.trim() ? E.borderLit : E.border}`,
            background: input.trim() ? 'rgba(249,168,37,0.14)' : 'rgba(249,168,37,0.04)',
            color: input.trim() ? E.accent : E.dim,
            cursor: input.trim() ? 'pointer' : 'default',
            fontFamily: E.fontSans,
            fontSize: 12,
            fontWeight: 500,
            letterSpacing: '0.12em',
            textTransform: 'uppercase',
          }}
        >
          Join
        </button>

        <button
          type="button"
          onClick={handleClose}
          style={{
            marginTop: 12,
            width: '100%',
            padding: '10px',
            border: 'none',
            background: 'none',
            color: E.dim,
            cursor: 'pointer',
            fontFamily: E.fontSans,
          }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
