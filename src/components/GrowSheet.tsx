'use client';

/**
 * Grow — QR + short link over the Galaxy.
 * Handshake is still a single-use dead-drop (fleet). Cap 7 / history = glass intent until relay counts.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { createRelay } from '@/lib/sync/relay';
import { loadKey, recordIssuedGrowCode } from '@/lib/identity/client-store';
import { buildSignedIdentityCard } from '@/lib/identity/identity-card-sign';
import { SimpleQRCode } from '@/components/SimpleQRCode';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { GROW_INVITE_MAX, clampGrowCap, TRUST_RECIPE_COPY } from '@/lib/trust/trust-recipe';

type Props = {
  open: boolean;
  onClose: () => void;
  identity: any;
};

export function GrowSheet({ open, onClose, identity }: Props) {
  const [relay, setRelay] = useState<{ url: string; code: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [uses, setUses] = useState(1);
  const started = useRef(false);

  const mint = useCallback(async () => {
    if (!identity?.identity?.fingerprint) return;
    setBusy(true);
    setError(null);
    try {
      const fp = identity.identity.fingerprint;
      const key = await loadKey(fp);
      if (!key) throw new Error('Unlock your identity first.');
      const signed = await buildSignedIdentityCard(identity, key.privateKey, key.passphrase);
      const result = await createRelay(JSON.stringify(signed));
      setRelay({ url: result.url, code: result.code });
      // The issued shortcode is recorded (with its per-code cap) by the effect below — which also keeps
      // the cap in sync when the issuer adjusts the toggle. Kept out of mint so the two paths don't race.
    } catch (e: any) {
      started.current = false;
      setError(e?.message || 'Could not prepare the invite.');
    } finally {
      setBusy(false);
    }
  }, [identity]);

  useEffect(() => {
    if (!open) {
      started.current = false;
      setRelay(null);
      setError(null);
      return;
    }
    if (started.current) return;
    started.current = true;
    void mint();
  }, [open, mint]);

  // Record the issued code with its per-code cap (giver-side R1 anti-replay + the distinct-joiner
  // ceiling). Fires when the code is minted (relay.code set) and whenever the issuer adjusts the cap —
  // the link/code never changes, only its stored cap (recordIssuedGrowCode preserves already-accepted
  // joiners). Best-effort: a persistence hiccup must never block sharing the invite.
  useEffect(() => {
    const fp = identity?.identity?.fingerprint;
    if (!fp || !relay?.code) return;
    void recordIssuedGrowCode(fp, relay.code, uses).catch(() => { /* non-fatal */ });
  }, [uses, relay?.code, identity]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-label="Grow your galaxy"
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
        <p
          style={{
            margin: 0,
            fontSize: 11,
            letterSpacing: '0.2em',
            textTransform: 'uppercase',
            color: E.accent,
          }}
        >
          Grow
        </p>
        <h2 style={{ margin: '8px 0 0', fontSize: 22, fontWeight: 400, color: E.text }}>
          Show them your card
        </h2>
        <p style={{ margin: '10px 0 0', fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
          {TRUST_RECIPE_COPY.growHint}
        </p>
        <p style={{ margin: '8px 0 0', fontSize: 12, color: E.dim, lineHeight: 1.5 }}>
          {TRUST_RECIPE_COPY.mycelial}
        </p>

        <label style={{ display: 'block', marginTop: 18, fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
          How many people can join with this link?
        </label>
        <input
          type="number"
          min={1}
          max={GROW_INVITE_MAX}
          value={uses}
          onChange={(e) => setUses(clampGrowCap(e.target.value))}
          aria-label="Number of people who can join with this link"
          style={{
            marginTop: 6,
            width: '100%',
            background: E.inputBg,
            border: `1px solid ${E.border}`,
            borderRadius: 8,
            color: E.text,
            padding: '10px 12px',
            fontFamily: E.fontSans,
          }}
        />
        <p style={{ margin: '6px 0 0', fontSize: 11, color: E.dim, lineHeight: 1.5 }}>
          Default is 1 (single-use). Turn it up to share one link with a group, up to {GROW_INVITE_MAX}.
        </p>
        <p style={{ margin: '8px 0 0', fontSize: 12, color: E.muted }}>
          {uses === 1
            ? 'Single-use: one person can join with this link.'
            : `Up to ${uses} people can join with this link.`}{' '}
          This link works for 7 days.
        </p>

        {busy && <p style={{ color: E.dim, marginTop: 20 }}>Preparing…</p>}
        {error && <p style={{ color: E.danger, marginTop: 16, fontSize: 13 }}>{error}</p>}
        {relay && (
          <>
            <div style={{ margin: '20px auto', width: 'fit-content' }}>
              <SimpleQRCode value={relay.url} size={180} />
            </div>
            <p style={{ fontSize: 11, color: E.dim, letterSpacing: '0.12em' }}>SHARE LINK</p>
            <code
              style={{
                display: 'block',
                color: E.accent,
                fontSize: 13,
                wordBreak: 'break-all',
                fontFamily: E.fontMono,
                marginTop: 4,
              }}
            >
              {relay.url}
            </code>
            <button
              type="button"
              onClick={() => navigator.clipboard?.writeText(relay.url)}
              style={{
                marginTop: 14,
                width: '100%',
                padding: '10px 14px',
                borderRadius: 8,
                border: `1px solid ${E.borderLit}`,
                background: 'transparent',
                color: E.text,
                cursor: 'pointer',
                fontFamily: E.fontSans,
              }}
            >
              Copy link
            </button>
          </>
        )}

        <button
          type="button"
          onClick={onClose}
          style={{
            marginTop: 20,
            width: '100%',
            padding: '10px',
            border: 'none',
            background: 'none',
            color: E.dim,
            cursor: 'pointer',
            fontFamily: E.fontSans,
          }}
        >
          Back to Galaxy
        </button>
      </div>
    </div>
  );
}
