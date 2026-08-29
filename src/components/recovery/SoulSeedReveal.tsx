'use client';

// One-time soul-seed / recovery-phrase reveal after forge.
// Shows the phrase produced by createKeyVault (hex groups today) — does not invent crypto.

import { useState } from 'react';
import { solarEmber as E, solarGlass } from './solar-ember';
import { IdentitySeal } from '@/components/identity/IdentitySeal';

export function SoulSeedReveal({
  seedPhrase,
  fingerprint,
  threshold,
  shardCount,
  acked,
  onAckChange,
  onContinue,
}: {
  seedPhrase: string;
  fingerprint: string;
  threshold: number;
  shardCount: number;
  acked: boolean;
  onAckChange: (v: boolean) => void;
  onContinue: () => void;
}) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(seedPhrase);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      /* ignore */
    }
  };

  return (
    <div
      style={{
        minHeight: '100%',
        padding: '28px 18px 40px',
        background: E.bgCss,
        color: E.text,
        fontFamily: E.fontSans,
      }}
    >
      <div
        style={{
          ...solarGlass,
          maxWidth: 420,
          margin: '0 auto',
          padding: '28px 22px',
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: 18 }}>
          <IdentitySeal fingerprint={fingerprint} size={88} label="Your seal" />
        </div>
        <p
          style={{
            fontFamily: E.fontMono,
            fontSize: 10,
            letterSpacing: '0.16em',
            textTransform: 'uppercase',
            color: E.accent,
            margin: '0 0 8px',
            textAlign: 'center',
          }}
        >
          Recovery phrase · shown once
        </p>
        <h1
          style={{
            fontFamily: E.fontSerif,
            fontWeight: 400,
            fontSize: '1.85rem',
            margin: '0 0 10px',
            textAlign: 'center',
            color: E.text,
          }}
        >
          Write this down.
        </h1>
        <p style={{ color: E.muted, fontSize: 13, lineHeight: 1.5, margin: '0 0 16px', textAlign: 'center' }}>
          Your 12-word recovery phrase. Write it down and keep it somewhere safe you&apos;ll still have if you lose your passphrase. If you lose your passphrase, the phrase unlocks your backup without it. Shown once — this is <strong style={{ color: E.text }}>not</strong> your everyday passphrase.
        </p>
        <p style={{ color: E.dim, fontSize: 12, lineHeight: 1.45, margin: '0 0 16px', textAlign: 'center' }}>
          Social-recovery shards ({threshold}-of-{shardCount}) stay local for the tear ceremony.
        </p>

        <div
          style={{
            background: 'rgba(15,10,6,.85)',
            border: `1px solid ${E.borderLit}`,
            borderRadius: 12,
            padding: 16,
            fontFamily: E.fontMono,
            fontSize: 13,
            color: E.text,
            wordBreak: 'break-all',
            lineHeight: 1.75,
            marginBottom: 10,
            userSelect: 'all',
            boxShadow: `inset 0 0 24px ${E.accent}14`,
          }}
        >
          {seedPhrase}
        </div>

        <button
          type="button"
          onClick={copy}
          style={{
            width: '100%',
            marginBottom: 14,
            padding: '10px 12px',
            borderRadius: 10,
            border: `1px solid ${E.border}`,
            background: 'transparent',
            color: E.muted,
            fontFamily: E.fontSans,
            fontSize: 12,
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            cursor: 'pointer',
          }}
        >
          {copied ? 'Copied' : 'Copy phrase'}
        </button>

        <label
          style={{
            display: 'flex',
            gap: 10,
            alignItems: 'flex-start',
            fontSize: 12,
            color: E.muted,
            marginBottom: 16,
            cursor: 'pointer',
          }}
        >
          <input
            type="checkbox"
            checked={acked}
            onChange={(e) => onAckChange(e.target.checked)}
            style={{ marginTop: 2 }}
          />
          <span>I have written this down offline. I understand there is no email recovery.</span>
        </label>

        <button
          type="button"
          onClick={onContinue}
          disabled={!acked}
          style={{
            width: '100%',
            padding: '14px 16px',
            borderRadius: 12,
            border: `1px solid ${E.borderLit}`,
            background: `linear-gradient(180deg, ${E.accent}33, ${E.accent2}22)`,
            color: E.accent,
            fontFamily: E.fontSans,
            fontSize: 13,
            letterSpacing: '0.1em',
            textTransform: 'uppercase',
            cursor: acked ? 'pointer' : 'not-allowed',
            opacity: acked ? 1 : 0.45,
            boxShadow: acked ? `0 0 28px ${E.accent}22` : 'none',
          }}
        >
          I have it. Continue.
        </button>
      </div>
    </div>
  );
}
