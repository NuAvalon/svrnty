'use client';

/**
 * Grow — QR + short link over the Galaxy.
 * Handshake is still a single-use dead-drop (fleet). Cap 7 / history = glass intent until relay counts.
 *
 * Channel: In person (forced cap 1, regen after use) vs Remote (viral cap 1–1000).
 * Switching channel remints. Remote arrivals wait at the Gate on the giver's device.
 */

import { useCallback, useEffect, useRef, useState, type CSSProperties } from 'react';
import { createRelay } from '@/lib/sync/relay';
import {
  issuedCodeSpent,
  loadIssuedCodeMap,
  loadKey,
  recordIssuedGrowCode,
  type GrowMintChannel,
} from '@/lib/identity/client-store';
import { buildSignedIdentityCard } from '@/lib/identity/identity-card-sign';
import { SimpleQRCode } from '@/components/SimpleQRCode';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { GROW_INVITE_MAX, clampGrowCap, TRUST_RECIPE_COPY } from '@/lib/trust/trust-recipe';
import { GATE_COPY } from '@/lib/trust/grow-gate';

type Props = {
  open: boolean;
  onClose: () => void;
  identity: any;
  /** Skip overlay chrome — hosted inside GrowSurface tabs. */
  embedded?: boolean;
};

const channelBtn = (active: boolean): CSSProperties => ({
  flex: 1,
  padding: '10px 12px',
  borderRadius: 8,
  border: `1px solid ${active ? E.borderLit : E.border}`,
  background: active ? 'color-mix(in srgb, var(--se-accent) 14%, transparent)' : 'transparent',
  color: active ? E.text : E.muted,
  cursor: 'pointer',
  fontFamily: E.fontSans,
  fontSize: 13,
});

export function GrowSheet({ open, onClose, identity, embedded = false }: Props) {
  const [relay, setRelay] = useState<{ url: string; code: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [uses, setUses] = useState(1);
  const [channel, setChannel] = useState<GrowMintChannel>('remote');
  const [spent, setSpent] = useState(false);
  const [mintNonce, setMintNonce] = useState(0);
  const usesRef = useRef(uses);
  const channelRef = useRef(channel);
  usesRef.current = uses;
  channelRef.current = channel;

  const mint = useCallback(async () => {
    if (!identity?.identity?.fingerprint) return;
    setBusy(true);
    setError(null);
    setSpent(false);
    try {
      const fp = identity.identity.fingerprint;
      const key = await loadKey(fp);
      if (!key) throw new Error('Unlock your identity first.');
      const signed = await buildSignedIdentityCard(identity, key.privateKey, key.passphrase);
      const result = await createRelay(JSON.stringify(signed));
      const ch = channelRef.current;
      const cap = ch === 'in_person' ? 1 : usesRef.current;
      setRelay({ url: result.url, code: result.code });
      try {
        await recordIssuedGrowCode(fp, result.code, cap, ch);
      } catch {
        /* non-fatal */
      }
    } catch (e: any) {
      setError(e?.message || 'Could not prepare the invite.');
    } finally {
      setBusy(false);
    }
  }, [identity]);

  const mintRef = useRef(mint);
  mintRef.current = mint;

  useEffect(() => {
    if (!open) {
      setRelay(null);
      setError(null);
      setSpent(false);
      return;
    }
    void mintRef.current();
  }, [open, channel, mintNonce]);

  useEffect(() => {
    const fp = identity?.identity?.fingerprint;
    if (!fp || !relay?.code) return;
    if (channel === 'in_person') return; // cap locked at mint
    void recordIssuedGrowCode(fp, relay.code, uses).catch(() => {
      /* non-fatal — preserves prior channel */
    });
  }, [uses, relay?.code, identity, channel]);

  useEffect(() => {
    const fp = identity?.identity?.fingerprint;
    if (!open || !fp || !relay?.code || channel !== 'in_person') return;
    let cancelled = false;
    const tick = async () => {
      try {
        const map = await loadIssuedCodeMap();
        if (!cancelled && issuedCodeSpent(map, fp, relay.code)) setSpent(true);
      } catch {
        /* non-fatal */
      }
    };
    void tick();
    const id = setInterval(tick, 4000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [open, identity, relay?.code, channel]);

  if (!open) return null;

  const pickChannel = (ch: GrowMintChannel) => {
    if (ch === channel) return;
    setChannel(ch);
    if (ch === 'in_person') setUses(1);
    setRelay(null);
    setSpent(false);
  };

  const body = (
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

        <p style={{ margin: '18px 0 8px', fontSize: 12, letterSpacing: '0.12em', textTransform: 'uppercase', color: E.dim }}>
          How are they joining?
        </p>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            type="button"
            data-testid="grow-channel-in-person"
            aria-pressed={channel === 'in_person'}
            onClick={() => pickChannel('in_person')}
            style={channelBtn(channel === 'in_person')}
          >
            {GATE_COPY.inPerson}
          </button>
          <button
            type="button"
            data-testid="grow-channel-remote"
            aria-pressed={channel === 'remote'}
            onClick={() => pickChannel('remote')}
            style={channelBtn(channel === 'remote')}
          >
            {GATE_COPY.remote}
          </button>
        </div>
        <p style={{ margin: '8px 0 0', fontSize: 12, color: E.dim, lineHeight: 1.5 }}>
          {channel === 'in_person' ? GATE_COPY.inPersonHint : GATE_COPY.remoteHint}
        </p>

        {channel === 'remote' && (
          <>
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
          </>
        )}

        {channel === 'in_person' && (
          <p style={{ margin: '12px 0 0', fontSize: 12, color: E.muted, lineHeight: 1.5 }}>
            This code works for 7 days on the relay — mint it when they are in front of you. Single-use.
          </p>
        )}

        {busy && <p style={{ color: E.dim, marginTop: 20 }}>Preparing…</p>}
        {error && <p style={{ color: E.danger, marginTop: 16, fontSize: 13 }}>{error}</p>}
        {relay && !spent && (
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
        {spent && channel === 'in_person' && (
          <div data-testid="grow-in-person-spent" style={{ marginTop: 20 }}>
            <p style={{ margin: 0, fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
              {GATE_COPY.spentInPerson}
            </p>
            <button
              type="button"
              data-testid="grow-regen"
              onClick={() => setMintNonce((n) => n + 1)}
              style={{
                marginTop: 12,
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
              {GATE_COPY.regen}
            </button>
          </div>
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
    </>
  );

  if (embedded) return body;

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
        {body}
      </div>
    </div>
  );
}
