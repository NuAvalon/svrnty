'use client';

// Lab: compare IdentitySeal variants, randomize fingerprints, ±1 digit shifts.
// Not a production surface — UI acceleration playground.

import { useCallback, useMemo, useState, type CSSProperties } from 'react';
import {
  IdentitySeal,
  SEAL_VARIANTS,
  type SealVariant,
  fingerprintHex,
  randomFingerprint,
  shiftFingerprintDigit,
  foldFromFingerprint,
  HABIT_LABEL,
  composePhiSeal,
} from '@/components/identity/IdentitySeal';
import { solarEmber as E } from '@/components/recovery/solar-ember';

const SAMPLES = [
  '5408785bfc9f6fa84bb8e44c90c0c03eaaaaaaaa',
  'deadbeefcafebabe0123456789abcdef01234567',
  '0000000000000000000000000000000000000001',
  'ffffffffffffffffffffffffffffffffffffffff',
  'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
  '13579bdf2468ace02468ace013579bdf0f1e2d3c',
];

function fmtGroups(fp: string): string {
  return fingerprintHex(fp).match(/.{1,4}/g)?.join('·') ?? fp;
}

function habitBlurb(fp: string): string {
  const g = composePhiSeal(fp);
  return `${g.fold}-fold · ${g.figure}`;
}

const btn: CSSProperties = {
  background: 'rgba(249,168,37,0.1)',
  border: `1px solid ${E.borderLit}`,
  color: E.accent,
  borderRadius: 8,
  padding: '8px 12px',
  fontFamily: E.fontSans,
  fontSize: 12,
  letterSpacing: '0.06em',
  cursor: 'pointer',
};

const ghost: React.CSSProperties = {
  ...btn,
  background: 'transparent',
  border: `1px solid ${E.border}`,
  color: E.muted,
};

export default function SealLabPage() {
  const [fp, setFp] = useState(SAMPLES[0]);
  const [digitIndex, setDigitIndex] = useState(0);
  const [gallerySeed, setGallerySeed] = useState(() =>
    Array.from({ length: 8 }, () => randomFingerprint())
  );

  const hex = fingerprintHex(fp);
  const neighbors = useMemo(
    () => ({
      base: hex,
      firstPlus: shiftFingerprintDigit(hex, 0, 1),
      firstMinus: shiftFingerprintDigit(hex, 0, -1),
      lastPlus: shiftFingerprintDigit(hex, hex.length - 1, 1),
      lastMinus: shiftFingerprintDigit(hex, hex.length - 1, -1),
      atPlus: shiftFingerprintDigit(hex, digitIndex, 1),
      atMinus: shiftFingerprintDigit(hex, digitIndex, -1),
    }),
    [hex, digitIndex]
  );

  const randomize = useCallback(() => setFp(randomFingerprint()), []);
  const reshuffleGallery = useCallback(
    () => setGallerySeed(Array.from({ length: 8 }, () => randomFingerprint())),
    []
  );

  return (
    <div
      style={{
        minHeight: '100vh',
        background: E.bgCss,
        color: E.text,
        fontFamily: E.fontSans,
        padding: '28px 20px 64px',
      }}
    >
      <div style={{ maxWidth: 1100, margin: '0 auto' }}>
        <p style={{ margin: 0, color: E.accent, letterSpacing: '0.2em', fontSize: 11, textTransform: 'uppercase' }}>
          Dev lab · IdentitySeal
        </p>
        <h1 style={{ margin: '8px 0 6px', fontSize: 28, fontWeight: 600 }}>Seal playground</h1>
        <p style={{ margin: '0 0 24px', color: E.muted, maxWidth: 640, lineHeight: 1.55, fontSize: 14 }}>
          Fingerprint seeds fold (3–9) and a sacred-geometry figure: hexagrams (compound ★),
          unicursal hexagrams, pentagrams, heptagrams, inversions, triquetra, vesica. φ measures
          the crystal cascade. Randomize to walk the catalog.
        </p>

        {/* Controls */}
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 10,
            alignItems: 'center',
            marginBottom: 18,
            padding: 14,
            borderRadius: 14,
            background: E.surface,
            border: `1px solid ${E.border}`,
          }}
        >
          <input
            value={hex}
            onChange={(e) => setFp(e.target.value)}
            spellCheck={false}
            style={{
              flex: '1 1 280px',
              minWidth: 200,
              background: 'rgba(12,8,5,0.85)',
              border: `1px solid ${E.border}`,
              borderRadius: 8,
              padding: '10px 12px',
              color: E.text,
              fontFamily: E.fontMono,
              fontSize: 12,
              outline: 'none',
            }}
          />
          <button type="button" style={btn} onClick={randomize}>
            Randomize
          </button>
          <button type="button" style={ghost} onClick={() => setFp(neighbors.firstPlus)}>
            First digit +1
          </button>
          <button type="button" style={ghost} onClick={() => setFp(neighbors.firstMinus)}>
            First digit −1
          </button>
          <button type="button" style={ghost} onClick={() => setFp(neighbors.lastPlus)}>
            Last digit +1
          </button>
          <button type="button" style={ghost} onClick={() => setFp(neighbors.lastMinus)}>
            Last digit −1
          </button>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, color: E.dim, fontSize: 12 }}>
            Digits[{digitIndex}]
            <input
              type="range"
              min={0}
              max={39}
              value={digitIndex}
              onChange={(e) => setDigitIndex(Number(e.target.value))}
              style={{ width: 120 }}
            />
          </label>
          <button type="button" style={ghost} onClick={() => setFp(neighbors.atPlus)}>
            At cursor +1
          </button>
          <button type="button" style={ghost} onClick={() => setFp(neighbors.atMinus)}>
            At cursor −1
          </button>
        </div>
        <p style={{ margin: '0 0 28px', fontFamily: E.fontMono, fontSize: 11, color: E.dim }}>
          key · {fmtGroups(hex)}
          {' · '}
          {habitBlurb(hex)}
        </p>

        {/* All variants for current FP */}
        <h2 style={sectionTitle}>Variants · this fingerprint</h2>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
            gap: 16,
            marginBottom: 36,
          }}
        >
          {SEAL_VARIANTS.map((v) => (
            <VariantCard key={v.id} variant={v.id} title={v.title} blurb={v.blurb} fingerprint={hex} size={120} />
          ))}
        </div>

        {/* ±1 digit sensitivity for φ */}
        <h2 style={sectionTitle}>φ sensitivity · ±1 hex digit</h2>
        <p style={{ margin: '0 0 14px', color: E.dim, fontSize: 13 }}>
          Tiny input change → visibly different sigil (rotation / chord gating). Same grammar.
        </p>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
            gap: 14,
            marginBottom: 36,
          }}
        >
          <VariantCard variant="phi" title="Current" blurb={habitBlurb(neighbors.base)} fingerprint={neighbors.base} />
          <VariantCard variant="phi" title="First −1" blurb={habitBlurb(neighbors.firstMinus)} fingerprint={neighbors.firstMinus} />
          <VariantCard variant="phi" title="First +1" blurb={habitBlurb(neighbors.firstPlus)} fingerprint={neighbors.firstPlus} />
          <VariantCard variant="phi" title="Last −1" blurb={habitBlurb(neighbors.lastMinus)} fingerprint={neighbors.lastMinus} />
          <VariantCard variant="phi" title="Last +1" blurb={habitBlurb(neighbors.lastPlus)} fingerprint={neighbors.lastPlus} />
        </div>

        {/* Card with / without seal */}
        <h2 style={sectionTitle}>Card · with seal vs without</h2>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: 24,
            marginBottom: 40,
            alignItems: 'start',
          }}
        >
          <div>
            <p style={miniLabel}>With φ seal (production)</p>
            <MiniCard fingerprint={hex} showSeal />
          </div>
          <div>
            <p style={miniLabel}>Without seal</p>
            <MiniCard fingerprint={hex} showSeal={false} />
          </div>
        </div>

        {/* Sample gallery */}
        <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 12, marginBottom: 12 }}>
          <h2 style={{ ...sectionTitle, margin: 0 }}>Sample gallery · φ</h2>
          <button type="button" style={ghost} onClick={reshuffleGallery}>
            Reshuffle
          </button>
        </div>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(120px, 1fr))',
            gap: 12,
            marginBottom: 16,
          }}
        >
          {[...SAMPLES, ...gallerySeed].map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setFp(s)}
              style={{
                background: fingerprintHex(s) === hex ? 'rgba(249,168,37,0.12)' : 'rgba(12,8,5,0.45)',
                border: `1px solid ${fingerprintHex(s) === hex ? E.borderLit : E.border}`,
                borderRadius: 12,
                padding: '12px 8px',
                cursor: 'pointer',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: 8,
              }}
            >
              <IdentitySeal fingerprint={s} variant="phi" size={72} />
              <span style={{ fontFamily: E.fontMono, fontSize: 9, color: E.dim, wordBreak: 'break-all' }}>
                {foldFromFingerprint(s)}·{fingerprintHex(s).slice(0, 6)}…
              </span>
            </button>
          ))}
        </div>

        <p style={{ marginTop: 32, color: E.dim, fontSize: 12 }}>
          <a href="/" style={{ color: E.muted }}>← back to app</a>
          {' · '}
          Lab fingerprints are random hex for viewing — not real keys.
        </p>
      </div>
    </div>
  );
}

const sectionTitle: CSSProperties = {
  margin: '0 0 12px',
  fontSize: 15,
  letterSpacing: '0.12em',
  textTransform: 'uppercase',
  color: E.accent,
  fontWeight: 500,
};

const miniLabel: CSSProperties = {
  margin: '0 0 10px',
  fontSize: 11,
  letterSpacing: '0.14em',
  textTransform: 'uppercase',
  color: E.dim,
};

function VariantCard({
  variant,
  title,
  blurb,
  fingerprint,
  size = 100,
}: {
  variant: SealVariant;
  title: string;
  blurb: string;
  fingerprint: string;
  size?: number;
}) {
  return (
    <div
      style={{
        padding: '16px 12px',
        borderRadius: 14,
        background: 'rgba(12,8,5,0.5)',
        border: `1px solid ${E.border}`,
        textAlign: 'center',
      }}
    >
      <IdentitySeal fingerprint={fingerprint} variant={variant} size={size} />
      <div style={{ marginTop: 10, fontSize: 13, color: E.text, fontWeight: 500 }}>{title}</div>
      <div style={{ marginTop: 4, fontSize: 11, color: E.dim, lineHeight: 1.4 }}>{blurb}</div>
    </div>
  );
}

function MiniCard({ fingerprint, showSeal }: { fingerprint: string; showSeal: boolean }) {
  // Lightweight stand-in so lab doesn't depend on full claimed-slug state.
  return (
    <div
      style={{
        borderRadius: 20,
        border: `1px solid ${E.borderLit}`,
        background: 'linear-gradient(165deg, rgba(36,24,12,.72), rgba(18,12,7,.88))',
        padding: '22px 18px',
        textAlign: 'center',
      }}
    >
      {showSeal ? (
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 12 }}>
          <IdentitySeal fingerprint={fingerprint} variant="phi" size={88} />
        </div>
      ) : (
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 12 }}>
          <IdentitySeal fingerprint={fingerprint} variant="none" size={88} />
        </div>
      )}
      <div style={{ fontSize: 20, fontWeight: 600, color: E.text, marginBottom: 4 }}>Sample Name</div>
      <div style={{ fontFamily: E.fontMono, fontSize: 13, color: E.accent, marginBottom: 8 }}>@lab.svrnty.is</div>
      <div style={{ fontFamily: E.fontMono, fontSize: 10, color: E.dim }}>key · {fmtGroups(fingerprint).slice(0, 39)}</div>
    </div>
  );
}
