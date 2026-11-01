'use client';

/**
 * Join by link — Component A of the in-page join.
 *
 * Scan an invite QR (ScanToJoin) or paste a connect link → mount the ONE
 * connect flow inline (<ConnectSheet> — the one-step grow-link flow from
 * CURSOR_QUEUE.md #3: resolve → land in GATE → one tap to Known). No router
 * nav → also sidesteps the /c/ post-join session-lock T2.6. Paste is the
 * permanent fallback for when a camera scan isn't available.
 *
 * INVARIANTS:
 *  INV-1  one in-app join path — paste and scan both mount ConnectSheet; zero
 *         parallel join/verify/trust logic. (JoinerCeremony still owns the
 *         /c/[code] ROUTE — direct link landings — until Apollo's post-flip.)
 *  INV-2  perception ≠ trust — resolving confers no trust; the newcomer lands
 *         in the GATE pending and the owner's explicit tap is the sole
 *         trust-conferring act. Nothing promotes implicitly.
 *  INV-4  parseConnectLink is the security boundary — total + host-pinned;
 *         rejects BEFORE mount. (Fragment-optional by design: a bare-code
 *         link parses, then refuses 'unwired' honestly at resolve.)
 *  INV-5  keyFragment is key material — this component NEVER logs / echoes the
 *         raw input or the parsed keyFragment. The error text is a FIXED
 *         string (no interpolation), so a pasted or scanned full URL can
 *         never leak its #fragment into the DOM, a toast, or telemetry.
 *  INV-6  no silent loss — an unparseable paste surfaces an explicit, honest
 *         inline error.
 */

import { useCallback, useEffect, useState } from 'react';
import { ConnectSheet } from '@/components/ConnectSheet';
import { ScanToJoin } from '@/components/ScanToJoin';
import {
  createConnectAddLogic,
  type ConnectLinkParse,
} from '@/lib/connect/add-logic';
import { solarEmber as E } from '@/components/recovery/solar-ember';

type Props = {
  open: boolean;
  /** Called on close. Parent should refresh contacts here so a just-joined edge appears. */
  onClose: () => void;
  /** Skip overlay chrome — hosted inside GrowSurface tabs. */
  embedded?: boolean;
  /** Owner fingerprint — needed to land arrivals in the owner's Gate. */
  ownerFp: string;
};

export function JoinByCode({ open, onClose, embedded = false, ownerFp }: Props) {
  const [input, setInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [invite, setInvite] = useState<ConnectLinkParse | null>(null);
  const [scanning, setScanning] = useState(false);
  const [logic] = useState(() => createConnectAddLogic());

  const reset = () => {
    setInput('');
    setError(null);
    setInvite(null);
    setScanning(false);
  };

  const handleClose = () => {
    reset();
    onClose();
  };

  const handleScannedInvite = useCallback((parsed: ConnectLinkParse) => {
    setError(null);
    setScanning(false);
    setInvite(parsed); // INV-2: this only MOUNTS the connect flow; the owner's tap still confers trust.
  }, []);

  useEffect(() => {
    if (open) return;
    setInput('');
    setError(null);
    setInvite(null);
    setScanning(false);
  }, [open]);

  const handleJoin = () => {
    // INV-4: the untrusted paste crosses the trust boundary here and only here.
    const parsed = logic.parseConnectLink(input);
    if (!parsed) {
      // INV-5: fixed message — NEVER echo `input` (it carries the #key). Surface no fragment.
      setError(
        "That doesn't look like a svrnty connect link. Paste the whole link — it includes the key after the # (e.g. svrnty.is/c/…#…) — or the bare code.",
      );
      return;
    }
    setError(null);
    setInvite(parsed); // INV-2: this only MOUNTS the connect flow; the owner's tap still confers trust.
  };

  if (!open) return null;

  // Joining: mount the ONE connect flow, full-screen, no nav (INV-1).
  if (invite) {
    return (
      <ConnectSheet
        open
        onClose={handleClose}
        ownerFp={ownerFp}
        link={invite}
        logic={logic}
        onAdmitted={handleClose}
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
