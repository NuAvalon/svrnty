'use client';

/**
 * Join by link — Component A of the in-page join.
 *
 * Scan an invite QR (ScanToJoin) or paste an invite link → parse it through the ONE
 * security boundary (INV-4) → route to the ONE in-app join path (connect-ux wiring,
 * svrnty#365): <ConnectSheet>. JoinerCeremony keeps the /c/{code} direct-landing route
 * (re-routed post-flip, separate PR) and the shard shapes its own focused panel owns.
 * Paste is the permanent fallback for when a camera scan isn't available.
 *
 * INVARIANTS:
 *  INV-1  one join path — we ONLY mount ConnectSheet; zero parallel join/verify/trust logic.
 *         The route decision is a single point AFTER the parse, never before.
 *  INV-2  perception ≠ trust — parsing confers no trust; the human COMMIT inside the ceremony
 *         is the sole trust-conferring act. We never auto-commit.
 *  INV-4  parseInviteUrl is the security boundary — total + host-pinned; rejects BEFORE mount.
 *  INV-5  keyFragment is key material — this component NEVER logs / echoes the raw input or the
 *         parsed keyFragment. The error text is a FIXED string (no interpolation of user input),
 *         so a pasted or scanned full URL can never leak its #fragment into the DOM, a toast, or telemetry.
 *  INV-6  no silent loss — an unparseable paste surfaces an explicit, honest inline error.
 */

import { useCallback, useEffect, useState } from 'react';
import { ConnectSheet } from '@/components/ConnectSheet';
import { ScanToJoin } from '@/components/ScanToJoin';
import { createConnectAddLogic, type ConnectLinkParse } from '@/lib/connect/add-logic';
import { getActiveFingerprint } from '@/lib/identity/client-store';
import { solarEmber as E } from '@/components/recovery/solar-ember';

type Props = {
  open: boolean;
  /** Called on close. Parent should refresh contacts here so a just-joined edge appears. */
  onClose: () => void;
  /** Skip overlay chrome — hosted inside GrowSurface tabs. */
  embedded?: boolean;
};

export function JoinByCode({ open, onClose, embedded = false }: Props) {
  const [input, setInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [link, setLink] = useState<ConnectLinkParse | null>(null);
  const [ownerFp, setOwnerFp] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [logic] = useState(() => createConnectAddLogic());

  const reset = () => {
    setInput('');
    setError(null);
    setLink(null);
    setScanning(false);
  };

  const handleClose = () => {
    reset();
    onClose();
  };

  // The ONE route decision (INV-1): a parsed connect link mounts ConnectSheet
  // — always after the parse, never before. No active identity → stash the
  // link (the ceremony's pending-connect contract) so it resumes post-unlock;
  // without a fragment there's nothing resumable, so the sheet mounts and
  // refuses honestly instead.
  const routeParsed = useCallback(async (parsed: ConnectLinkParse) => {
    setError(null);
    const fp = await getActiveFingerprint();
    if (!fp) {
      try {
        if (parsed.keyFragment) {
          sessionStorage.setItem('svrnty:pending-connect', JSON.stringify(parsed));
        }
      } catch { /* storage unavailable — mount anyway, the sheet refuses honestly */ }
    }
    setOwnerFp(fp ?? '');
    setLink(parsed); // INV-2: this only MOUNTS the sheet; the human still commits inside it.
  }, []);

  const handleScannedInvite = useCallback((parsed: ConnectLinkParse) => {
    setScanning(false);
    void routeParsed(parsed);
  }, [routeParsed]);

  useEffect(() => {
    if (open) return;
    setInput('');
    setError(null);
    setLink(null);
    setScanning(false);
  }, [open]);

  const handleJoin = () => {
    // INV-4: the untrusted paste crosses the trust boundary here and only here —
    // parseConnectLink is the connect-link parser (fragment optional, so a bare
    // code reaches the sheet and refuses 'unwired' honestly instead of dying on
    // the invite's fragment-required parse).
    const parsed = logic.parseConnectLink(input);
    if (!parsed) {
      // INV-5: fixed message — NEVER echo `input` (it carries the #key). Surface no fragment.
      setError(
        "That doesn't look like a svrnty connect link. Paste the whole link: it includes the key after the #.",
      );
      return;
    }
    void routeParsed(parsed);
  };

  if (!open) return null;

  // Joining: mount the ONE in-app join path (INV-1) — ConnectSheet renders its own
  // dialog chrome; the parent refreshes the book after a promote.
  if (link) {
    return (
      <ConnectSheet
        open
        onClose={handleClose}
        ownerFp={ownerFp ?? ''}
        link={link}
        logic={logic}
        onAdmitted={onClose}
      />
    );
  }

  // Paste view (ScanToJoin replaces the body while the camera is live).
  const body = scanning ? (
    <ScanToJoin onInvite={handleScannedInvite} onClose={() => setScanning(false)} />
  ) : (
    <>
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
          Scan their invite QR, or paste the link. It opens the same connection ceremony as
          tapping the link — right here, without leaving the page.
        </p>

        <button
          type="button"
          data-testid="scan-invite-button"
          onClick={() => {
            setError(null);
            setScanning(true);
          }}
          style={{
            marginTop: 18,
            width: '100%',
            padding: '12px 14px',
            borderRadius: 8,
            border: `1px solid ${E.borderLit}`,
            background: 'rgba(249,168,37,0.14)',
            color: E.accent,
            cursor: 'pointer',
            fontFamily: E.fontSans,
            fontSize: 12,
            fontWeight: 500,
            letterSpacing: '0.12em',
            textTransform: 'uppercase',
          }}
        >
          Scan
        </button>

        <p
          style={{
            margin: '16px 0 0',
            fontSize: 11,
            letterSpacing: '0.18em',
            textTransform: 'uppercase',
            color: E.dim,
            textAlign: 'center',
          }}
        >
          or paste
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
    </>
  );

  if (embedded) return body;

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
        {body}
      </div>
    </div>
  );
}
