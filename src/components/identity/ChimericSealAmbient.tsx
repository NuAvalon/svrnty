'use client';

// Pre-identity home ambient — chimeric seal that slowly morphs until forge/restore.
// Not a real identity (I-6 only applies once a fingerprint is chosen).

import { useEffect, useState } from 'react';
import { IdentitySeal, randomFingerprint, shiftFingerprintDigit } from './IdentitySeal';
import { solarEmber as E } from '../recovery/solar-ember';

export function ChimericSealAmbient({ size = 148 }: { size?: number }) {
  const [fp, setFp] = useState(() => randomFingerprint());
  const [visible, setVisible] = useState(true);
  const [reduceMotion, setReduceMotion] = useState(false);

  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduceMotion(mq.matches);
    const onChange = () => setReduceMotion(mq.matches);
    mq.addEventListener?.('change', onChange);
    return () => mq.removeEventListener?.('change', onChange);
  }, []);

  useEffect(() => {
    if (reduceMotion) return;
    let alive = true;

    const nudge = () => {
      setVisible(false);
      window.setTimeout(() => {
        if (!alive) return;
        setFp((cur) => {
          // Mostly ±1 digit walks (smooth chimera); occasional leap
          if (Math.random() < 0.18) return randomFingerprint();
          const idx = Math.floor(Math.random() * cur.length);
          const delta = Math.random() < 0.5 ? 1 : -1;
          return shiftFingerprintDigit(cur, idx, delta);
        });
        setVisible(true);
      }, 480);
    };

    const id = window.setInterval(nudge, 2800);
    return () => {
      alive = false;
      window.clearInterval(id);
    };
  }, [reduceMotion]);

  return (
    <div
      aria-hidden
      style={{
        position: 'relative',
        width: size,
        height: size,
        margin: '0 auto',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        animation: reduceMotion ? undefined : 'chimera-breathe 7s ease-in-out infinite',
      }}
    >
      <style>{`
        @keyframes chimera-breathe {
          0%, 100% { transform: scale(1); filter: drop-shadow(0 0 14px ${E.accent}28); }
          50% { transform: scale(1.04); filter: drop-shadow(0 0 22px ${E.accent}45); }
        }
        @keyframes chimera-orbit {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
      {/* Soft orbiting ring */}
      {!reduceMotion && (
        <div
          style={{
            position: 'absolute',
            inset: -6,
            borderRadius: '50%',
            border: `1px solid ${E.accent}22`,
            animation: 'chimera-orbit 28s linear infinite',
            pointerEvents: 'none',
          }}
        />
      )}
      <div
        style={{
          opacity: visible ? 1 : 0.15,
          transition: reduceMotion ? undefined : 'opacity 0.45s ease',
          transform: reduceMotion ? undefined : `rotate(${visible ? 0 : 8}deg)`,
        }}
      >
        <IdentitySeal fingerprint={fp} size={size} variant="phi" />
      </div>
    </div>
  );
}
