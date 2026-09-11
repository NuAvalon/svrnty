'use client';

/**
 * Recovery — Guardians, seed, password, Distress.
 * Sender Distress is Coming (not live). Fleet owns the envelope.
 */

import { useEffect, useMemo, useState, type CSSProperties } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { DISTRESS_COMING_COPY } from '@/components/recovery/distress-coming';
import { TRUST_RECIPE_COPY } from '@/lib/trust/trust-recipe';
import type { TrustEdge } from '@/lib/trust/types';
import { loadShards } from '@/lib/identity/client-store';
import { ShardGiveDialog } from '@/components/ShardGiveDialog';

type Panel = 'menu' | 'guardians' | 'rotate' | 'seed' | 'password' | 'distress';

type Props = {
  open: boolean;
  onClose: () => void;
  identity: { identity?: { fingerprint?: string; name?: string } };
  contacts: TrustEdge[];
};

export function RecoverySheet({ open, onClose, identity, contacts }: Props) {
  const [panel, setPanel] = useState<Panel>('menu');
  const [password, setPassword] = useState('');
  const [password2, setPassword2] = useState('');
  const [seedAck, setSeedAck] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [holders, setHolders] = useState<{ name: string; fingerprint: string }[]>([]);
  const [giveTo, setGiveTo] = useState<TrustEdge | null>(null);

  const fp = identity?.identity?.fingerprint || '';
  const ownerName = identity?.identity?.name || 'you';
  const guardians = useMemo(
    () => contacts.filter((c) => c.trusted && !c.blocked),
    [contacts],
  );

  useEffect(() => {
    if (!open) {
      setPanel('menu');
      setNote(null);
      setPassword('');
      setPassword2('');
      setSeedAck(false);
    }
  }, [open]);

  useEffect(() => {
    if (!open || panel !== 'rotate' || !fp) return;
    let cancelled = false;
    void loadShards(fp).then((data) => {
      if (cancelled) return;
      const given = (data?.shards || [])
        .map((s: { given_to?: { name?: string; fingerprint?: string } }) => s.given_to)
        .filter(Boolean)
        .map((g: { name?: string; fingerprint?: string }) => ({
          name: g.name || 'Guardian',
          fingerprint: g.fingerprint || '',
        }));
      setHolders(given);
    });
    return () => {
      cancelled = true;
    };
  }, [open, panel, fp]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-label="Recovery"
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
          Recovery
        </p>

        {panel === 'menu' && (
          <>
            <h2 style={{ margin: '8px 0 0', fontSize: 22, fontWeight: 400, color: E.text }}>
              Keep the pieces
            </h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 18 }}>
              {(
                [
                  ['guardians', TRUST_RECIPE_COPY.recoverySelect],
                  ['rotate', TRUST_RECIPE_COPY.recoveryRotate],
                  ['seed', TRUST_RECIPE_COPY.recoverySeed],
                  ['password', TRUST_RECIPE_COPY.recoveryPassword],
                  ['distress', DISTRESS_COMING_COPY.menuLabel],
                ] as const
              ).map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  data-testid={id === 'distress' ? 'distress-coming-menu' : undefined}
                  onClick={() => { setNote(null); setPanel(id); }}
                  style={itemBtn(false)}
                >
                  {id === 'distress' ? label : label.split('.')[0]}
                </button>
              ))}
            </div>
          </>
        )}

        {panel === 'guardians' && (
          <>
            <h2 style={{ margin: '8px 0 12px', fontSize: 20, fontWeight: 400, color: E.text }}>
              Select Guardians
            </h2>
            <p style={{ margin: 0, fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
              {TRUST_RECIPE_COPY.recoverySelect}
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 16 }}>
              {guardians.length === 0 && (
                <p style={{ color: E.dim, fontSize: 13 }}>Trust someone before they can hold a piece.</p>
              )}
              {guardians.map((g) => (
                <button
                  key={g.peer_fingerprint}
                  type="button"
                  onClick={() => setGiveTo(g)}
                  style={itemBtn(false)}
                >
                  Give a piece · {g.peer_name}
                </button>
              ))}
            </div>
          </>
        )}

        {panel === 'rotate' && (
          <>
            <h2 style={{ margin: '8px 0 12px', fontSize: 20, fontWeight: 400, color: E.text }}>
              Rotate Guardians
            </h2>
            <p style={{ margin: 0, fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
              {TRUST_RECIPE_COPY.recoveryRotate}
            </p>
            <div style={{ marginTop: 16 }}>
              {holders.length === 0 ? (
                <p style={{ color: E.dim, fontSize: 13 }}>No pieces given yet.</p>
              ) : (
                holders.map((h) => (
                  <p key={h.fingerprint} style={{ margin: '0 0 8px', color: E.text, fontSize: 14 }}>
                    {h.name}
                  </p>
                ))
              )}
              <p style={{ margin: '12px 0 0', fontSize: 12, color: E.dim }}>
                Replacing a holder on the vault is fleet. This list is who already has a piece.
              </p>
            </div>
          </>
        )}

        {panel === 'seed' && (
          <>
            <h2 style={{ margin: '8px 0 12px', fontSize: 20, fontWeight: 400, color: E.text }}>
              Change Seed
            </h2>
            <p style={{ margin: 0, fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
              {TRUST_RECIPE_COPY.recoverySeed}
            </p>
            <label style={{ display: 'flex', gap: 8, marginTop: 16, color: E.text, fontSize: 13 }}>
              <input type="checkbox" checked={seedAck} onChange={(e) => setSeedAck(e.target.checked)} />
              The old seed will not open this vault.
            </label>
            <button
              type="button"
              disabled={!seedAck}
              onClick={() => setNote('New seed is fleet. Not a click yet.')}
              style={{ ...itemBtn(true), marginTop: 16, opacity: seedAck ? 1 : 0.45 }}
            >
              Change Seed
            </button>
          </>
        )}

        {panel === 'password' && (
          <>
            <h2 style={{ margin: '8px 0 12px', fontSize: 20, fontWeight: 400, color: E.text }}>
              Change Password
            </h2>
            <p style={{ margin: 0, fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
              {TRUST_RECIPE_COPY.recoveryPassword}
            </p>
            <input
              type="password"
              placeholder="New unlock"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={field()}
            />
            <input
              type="password"
              placeholder="Confirm"
              value={password2}
              onChange={(e) => setPassword2(e.target.value)}
              style={{ ...field(), marginTop: 8 }}
            />
            <button
              type="button"
              onClick={() => {
                if (password.length < 12 || password !== password2) {
                  setNote('Twelve characters, twice, matching.');
                  return;
                }
                setNote('Re-wrap is fleet. Not a click yet.');
              }}
              style={{ ...itemBtn(true), marginTop: 16 }}
            >
              Change Password
            </button>
          </>
        )}

        {panel === 'distress' && (
          <>
            <h2 style={{ margin: '8px 0 12px', fontSize: 20, fontWeight: 400, color: E.text }}>
              {DISTRESS_COMING_COPY.heading}
            </h2>
            <p style={{ margin: 0, fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
              {DISTRESS_COMING_COPY.body}
            </p>
            <button
              type="button"
              data-testid="distress-coming-control"
              disabled={true}
              aria-disabled={true}
              style={{ ...itemBtn(false), marginTop: 18, opacity: 0.4, cursor: 'not-allowed' }}
            >
              {DISTRESS_COMING_COPY.controlLabel}
            </button>
          </>
        )}

        {note && panel !== 'distress' && (
          <p style={{ margin: '12px 0 0', fontSize: 12, color: E.dim }}>{note}</p>
        )}

        <button
          type="button"
          onClick={() => (panel === 'menu' ? onClose() : setPanel('menu'))}
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
          {panel === 'menu' ? 'Back to Galaxy' : 'Back'}
        </button>
      </div>

      <ShardGiveDialog
        open={!!giveTo}
        onClose={() => setGiveTo(null)}
        ownerFingerprint={fp}
        ownerName={ownerName}
        contact={
          giveTo
            ? { id: giveTo.id, name: giveTo.peer_name, fingerprint: giveTo.peer_fingerprint }
            : null
        }
      />
    </div>
  );
}

function itemBtn(lit: boolean): CSSProperties {
  return {
    width: '100%',
    textAlign: 'left',
    padding: '12px 14px',
    borderRadius: 10,
    border: `1px solid ${lit ? E.borderLit : E.border}`,
    background: lit ? 'color-mix(in srgb, var(--se-accent) 12%, transparent)' : 'transparent',
    color: E.text,
    cursor: 'pointer',
    fontFamily: E.fontSans,
    fontSize: 14,
  };
}

function field(): CSSProperties {
  return {
    marginTop: 16,
    width: '100%',
    background: E.inputBg,
    border: `1px solid ${E.border}`,
    borderRadius: 8,
    color: E.text,
    padding: '10px 12px',
    fontFamily: E.fontSans,
    boxSizing: 'border-box',
  };
}
