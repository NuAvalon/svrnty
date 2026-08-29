'use client';

// Entropy meter — UI guidance only. Does not derive keys.
// Used on unlock passphrase (forge) and future user-set soul-seed entry.

import { solarEmber as E } from './solar-ember';

const COMMON = [
  'password', 'passphrase', '123456', 'qwerty', 'letmein', 'welcome',
  'iloveyou', 'admin', 'monkey', 'dragon', 'master', 'sunshine',
  'to be or not to be', 'the quick brown fox',
];

export type EntropyLevel = 'empty' | 'weak' | 'fair' | 'strong' | 'excellent';

export function scorePassphrase(input: string): {
  level: EntropyLevel;
  score: number; // 0–100
  hint: string;
} {
  const s = input.trim();
  if (!s) return { level: 'empty', score: 0, hint: 'Enter a passphrase' };

  const lower = s.toLowerCase();
  if (COMMON.some((c) => lower === c || lower.includes(c))) {
    return { level: 'weak', score: 12, hint: 'Too common — a famous quote is guessable. Make it personal and unique.' };
  }

  let score = 0;
  score += Math.min(40, s.length * 2.2); // length
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((r) => r.test(s)).length;
  score += classes * 10;
  if (s.length >= 12) score += 8;
  if (s.length >= 20) score += 10;
  // Wordiness (spaces) — personal phrases often better than short complexity
  const words = s.split(/\s+/).filter(Boolean);
  if (words.length >= 4 && words.every((w) => w.length >= 3)) score += 12;

  score = Math.max(0, Math.min(100, Math.round(score)));

  if (score < 35) return { level: 'weak', score, hint: 'Too simple — aim for 12+ characters, personal and unique.' };
  if (score < 55) return { level: 'fair', score, hint: 'Fair — longer or more unusual is safer.' };
  if (score < 75) return { level: 'strong', score, hint: 'Strong — this works as a device unlock factor.' };
  return { level: 'excellent', score, hint: 'Excellent — unique and hard to guess.' };
}

const LEVEL_COLOR: Record<EntropyLevel, string> = {
  empty: E.dim,
  weak: E.danger,
  fair: E.accent2,
  strong: E.accent,
  excellent: E.ok,
};

export function EntropyMeter({ value, label = 'Strength' }: { value: string; label?: string }) {
  const { level, score, hint } = scorePassphrase(value);
  const color = LEVEL_COLOR[level];
  return (
    <div style={{ marginTop: 8 }} aria-live="polite">
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
        <span style={{ fontSize: 10, letterSpacing: '0.12em', textTransform: 'uppercase', color: E.dim, fontFamily: E.fontMono }}>
          {label}
        </span>
        <span style={{ fontSize: 10, color, fontFamily: E.fontMono }}>{level === 'empty' ? '—' : level}</span>
      </div>
      <div style={{ height: 4, borderRadius: 2, background: 'rgba(255,190,120,.08)', overflow: 'hidden' }}>
        <div
          style={{
            width: `${score}%`,
            height: '100%',
            background: color,
            boxShadow: `0 0 12px ${color}55`,
            transition: 'width .25s ease, background .25s ease',
          }}
        />
      </div>
      <p style={{ margin: '6px 0 0', fontSize: 11, color: E.muted, lineHeight: 1.4 }}>{hint}</p>
    </div>
  );
}
