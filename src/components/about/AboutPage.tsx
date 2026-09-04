'use client';

import Link from 'next/link';
import { solarEmber as E, solarGlass } from '@/components/recovery/solar-ember';
import { ABOUT_COPY, type AboutCopy } from './copy';

type Props = {
  /** Override for tests or Hypatia swap without rebuilding the layout. */
  copy?: AboutCopy;
};

/**
 * CUR-11 — about page (render-glass only).
 * Copy lives in `./copy.ts` so Hypatia can replace strings without touching layout.
 */
export function AboutPage({ copy = ABOUT_COPY }: Props) {
  return (
    <div
      style={{
        minHeight: '100vh',
        background: E.bgCss,
        color: E.text,
        fontFamily: E.fontSans,
      }}
    >
      <div
        style={{
          maxWidth: 720,
          margin: '0 auto',
          padding: '2rem 1.25rem 4rem',
        }}
      >
        <header
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 16,
            marginBottom: '2.5rem',
          }}
        >
          <Link
            href="/"
            style={{
              fontFamily: E.fontSans,
              fontSize: 12,
              fontWeight: 600,
              letterSpacing: '0.2em',
              textTransform: 'uppercase',
              color: E.accent,
              textDecoration: 'none',
            }}
          >
            {copy.brand}
          </Link>
          <Link
            href="/"
            style={{
              fontSize: 12,
              color: E.muted,
              textDecoration: 'none',
              letterSpacing: '0.04em',
              border: `1px solid ${E.border}`,
              borderRadius: 8,
              padding: '6px 12px',
            }}
          >
            {copy.backLabel}
          </Link>
        </header>

        {copy.provisionalBanner ? (
          <p
            role="note"
            style={{
              margin: '0 0 1.75rem',
              padding: '10px 14px',
              borderRadius: 10,
              border: `1px dashed ${E.borderLit}`,
              background: 'rgba(249,168,37,0.06)',
              color: E.muted,
              fontSize: 12,
              lineHeight: 1.45,
            }}
          >
            {copy.provisionalBanner}
          </p>
        ) : null}

        <section
          aria-labelledby="about-brand"
          style={{
            marginBottom: '2.75rem',
            animation: 'about-rise 0.7s ease-out both',
          }}
        >
          <p
            id="about-brand"
            style={{
              margin: 0,
              fontSize: 'clamp(2.4rem, 8vw, 3.6rem)',
              fontWeight: 600,
              letterSpacing: '-0.03em',
              lineHeight: 1.05,
              background: `linear-gradient(135deg, ${E.accent}, ${E.accent2})`,
              WebkitBackgroundClip: 'text',
              backgroundClip: 'text',
              color: 'transparent',
            }}
          >
            {copy.brand}
          </p>
          <p
            style={{
              margin: '0.6rem 0 0',
              fontSize: 15,
              color: E.dim,
              letterSpacing: '0.02em',
              animation: 'about-rise 0.8s ease-out 0.08s both',
            }}
          >
            {copy.tagline}
          </p>
          <p
            style={{
              margin: '1.25rem 0 0',
              fontSize: 17,
              lineHeight: 1.55,
              color: E.text,
              maxWidth: '38em',
              animation: 'about-rise 0.85s ease-out 0.14s both',
            }}
          >
            {copy.lede}
          </p>
        </section>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
          {copy.sections.map((section, i) => (
            <section
              key={section.id}
              aria-labelledby={`about-${section.id}`}
              style={{
                ...solarGlass,
                padding: '1.35rem 1.4rem',
                animation: `about-rise 0.7s ease-out ${0.18 + i * 0.06}s both`,
              }}
            >
              <h2
                id={`about-${section.id}`}
                style={{
                  margin: '0 0 0.75rem',
                  fontSize: 13,
                  fontWeight: 600,
                  letterSpacing: '0.14em',
                  textTransform: 'uppercase',
                  color: E.accent,
                }}
              >
                {section.heading}
              </h2>
              {section.body.map((para) => (
                <p
                  key={para.slice(0, 48)}
                  style={{
                    margin: '0 0 0.7rem',
                    fontSize: 15,
                    lineHeight: 1.55,
                    color: E.text,
                  }}
                >
                  {para}
                </p>
              ))}
            </section>
          ))}
        </div>

        <section
          aria-labelledby="about-principles"
          style={{
            marginTop: '2.5rem',
            animation: 'about-rise 0.7s ease-out 0.45s both',
          }}
        >
          <h2
            id="about-principles"
            style={{
              margin: '0 0 1rem',
              fontSize: 13,
              fontWeight: 600,
              letterSpacing: '0.14em',
              textTransform: 'uppercase',
              color: E.accent,
            }}
          >
            {copy.principlesHeading}
          </h2>
          <ul
            style={{
              listStyle: 'none',
              margin: 0,
              padding: 0,
              display: 'flex',
              flexDirection: 'column',
              gap: 12,
            }}
          >
            {copy.principles.map((p) => (
              <li
                key={p.title}
                style={{
                  borderLeft: `2px solid ${E.borderLit}`,
                  paddingLeft: 14,
                }}
              >
                <div
                  style={{
                    fontSize: 14,
                    fontWeight: 600,
                    color: E.text,
                    marginBottom: 2,
                  }}
                >
                  {p.title}
                </div>
                <div style={{ fontSize: 13, color: E.muted, lineHeight: 1.45 }}>
                  {p.line}
                </div>
              </li>
            ))}
          </ul>
        </section>

        <p
          style={{
            marginTop: '3rem',
            textAlign: 'center',
            fontSize: 13,
            color: E.dim,
            letterSpacing: '0.02em',
          }}
        >
          {copy.closing}
        </p>
      </div>

      <style>{`
        @keyframes about-rise {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @media (prefers-reduced-motion: reduce) {
          * { animation: none !important; }
        }
      `}</style>
    </div>
  );
}
