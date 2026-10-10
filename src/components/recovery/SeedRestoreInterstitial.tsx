'use client';

// Post-success contacts-honesty interstitial after v4 seed-only restore.
// DEFINITIVE no-CTA: Continue only. No "restore from another backup" link.

import { solarEmber as E, solarGlass } from './solar-ember';
import { IdentitySeal } from '@/components/identity/IdentitySeal';

export function SeedRestoreInterstitial({
  fingerprint,
  pqSecretsRecovered,
  onContinue,
}: {
  fingerprint: string;
  /** When true, show one-line PQ honesty note (secrets restored; publics re-derive later). */
  pqSecretsRecovered: boolean;
  onContinue: () => void;
}) {
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

        <h1
          style={{
            fontFamily: E.fontSerif,
            fontWeight: 400,
            fontSize: '1.85rem',
            margin: '0 0 14px',
            textAlign: 'center',
            color: E.text,
            lineHeight: 1.25,
          }}
        >
          Your identity is back.
        </h1>

        <p
          style={{
            margin: '0 0 18px',
            fontSize: 14,
            lineHeight: 1.55,
            color: E.muted,
            textAlign: 'center',
          }}
        >
          Your keys and identity are recovered. Your contacts and trust connections
          weren&apos;t restored — they were sealed with the passphrase you lost, and
          your recovery code can&apos;t unlock them. You&apos;ll rebuild your
          connections as you reconnect with people.
        </p>

        {pqSecretsRecovered && (
          <p
            style={{
              margin: '0 0 18px',
              fontSize: 12,
              lineHeight: 1.5,
              color: E.dim,
              textAlign: 'center',
            }}
          >
            Post-quantum keys re-derive on next card publish.
          </p>
        )}

        <button
          type="button"
          onClick={onContinue}
          style={{
            width: '100%',
            padding: '14px 18px',
            borderRadius: 12,
            border: `1px solid ${E.borderLit}`,
            background: `linear-gradient(135deg, ${E.accent}, ${E.accent2})`,
            color: E.bg,
            fontFamily: E.fontSans,
            fontSize: 15,
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          Continue
        </button>
      </div>
    </div>
  );
}
