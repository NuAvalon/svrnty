// app/u/page.tsx — Public profile page (PARAM-FREE shell)
// Node Zero G-D coverage: this is a byte-stable prerendered shell. The middleware rewrites both
// the canonical /u/<name> and the bare /<name> alias to this param-free /u route (URL preserved),
// so the slug lives ONLY in window.location — never in a Next dynamic segment. A dynamic segment
// would echo the slug into the RSC flight-data inline script, making /u/alice ≠ /u/bob in prod
// (KB#3220) and breaking content-addressing + hash-CSP. Reading the slug client-side (post-hydration,
// like /c reads its #key) keeps the served shell identical across every profile URL.
'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { hasIdentity, loadIdentity } from '@/lib/identity/client-store';
import { slugUrlShort } from '@/lib/config/domain';

interface ProfileData {
  display_name?: string;
  public_key?: string;
  fingerprint?: string;
  verified?: boolean;
  created_at?: string;
  registered_at?: string;
}

/**
 * The profile slug, read from the current URL CLIENT-SIDE only. Handles the canonical
 * /u/<name> and the bare /<name> alias (both rewritten to /u by middleware, URL preserved).
 * Returns '' during SSR/prerender (window undefined) so the prerendered shell carries no slug.
 */
function readSlugFromLocation(): string {
  if (typeof window === 'undefined') return '';
  const segs = window.location.pathname.split('/').filter(Boolean);
  const raw = segs[0] === 'u' ? segs[1] : segs[0];
  if (!raw) return '';
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

export default function ProfilePage() {
  const [name, setName] = useState('');
  const [profile, setProfile] = useState<ProfileData | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  useEffect(() => {
    const slug = readSlugFromLocation();
    setName(slug);

    if (!slug) {
      setNotFound(true);
      setLoading(false);
      return;
    }

    async function loadProfile() {
      // Try registration API first (server-side identities)
      try {
        const res = await fetch(`/api/auth/slug/${encodeURIComponent(slug)}`);
        if (res.ok) {
          const data = await res.json();
          setProfile(data);
          setLoading(false);
          return;
        }
      } catch {}

      // Try local identity from IndexedDB (if viewer is the owner)
      try {
        if (await hasIdentity()) {
          const identity = await loadIdentity();
          if (identity?.name?.toLowerCase() === slug.toLowerCase()) {
            setProfile({
              display_name: identity.name,
              public_key: identity.publicKey || identity.signingPublicKey,
              fingerprint: identity.fingerprint,
              verified: identity.verification?.status === 'verified',
              created_at: identity.createdAt,
            });
            setLoading(false);
            return;
          }
        }
      } catch {}

      setNotFound(true);
      setLoading(false);
    }

    loadProfile();
  }, []);

  if (loading) {
    return (
      <div style={{
        minHeight: '100vh',
        background: '#0a0a0f',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        fontFamily: "'Space Grotesk', sans-serif",
        color: 'rgba(255,255,255,0.3)',
        fontSize: '14px',
        letterSpacing: '4px',
      }}>
        {/* Fonts self-hosted via next/font in layout.tsx */}
        RESOLVING...
      </div>
    );
  }

  if (notFound) {
    return (
      <div style={{
        minHeight: '100vh',
        background: '#0a0a0f',
        display: 'flex',
        flexDirection: 'column' as const,
        justifyContent: 'center',
        alignItems: 'center',
        padding: '20px',
      }}>
        {/* Fonts self-hosted via next/font in layout.tsx */}
        <h1 style={{
          fontFamily: "'Cormorant Garamond', serif",
          fontSize: '28px',
          fontWeight: 300,
          color: '#e8e4d9',
          letterSpacing: '2px',
          marginBottom: '12px',
        }}>
          {name}
        </h1>
        <p style={{
          fontFamily: "'Space Grotesk', sans-serif",
          fontSize: '13px',
          color: 'rgba(255,255,255,0.25)',
          marginBottom: '32px',
        }}>
          This identity has not been claimed yet.
        </p>
        <Link
          href="/"
          style={{
            background: 'rgba(52, 211, 153, 0.1)',
            border: '1px solid rgba(52, 211, 153, 0.3)',
            borderRadius: '8px',
            padding: '14px 28px',
            color: '#34d399',
            fontSize: '12px',
            fontWeight: 500,
            fontFamily: "'Space Grotesk', sans-serif",
            letterSpacing: '2px',
            textTransform: 'uppercase' as const,
            textDecoration: 'none',
          }}
        >
          Claim This Name
        </Link>
      </div>
    );
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: '#0a0a0f',
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      padding: '20px',
    }}>
      {/* Fonts self-hosted via next/font in layout.tsx */}
      <div style={{
        maxWidth: '440px',
        width: '100%',
        background: 'rgba(10, 14, 12, 0.92)',
        border: '1px solid rgba(52, 211, 153, 0.1)',
        borderRadius: '16px',
        padding: '40px',
        boxShadow: '0 4px 60px rgba(0, 0, 0, 0.5), 0 0 80px rgba(52, 211, 153, 0.03)',
        textAlign: 'center' as const,
      }}>
        {/* Shield icon */}
        <div style={{
          width: '72px',
          height: '72px',
          borderRadius: '50%',
          background: 'rgba(52, 211, 153, 0.08)',
          border: '1px solid rgba(52, 211, 153, 0.15)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          margin: '0 auto 20px',
        }}>
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#34d399" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        </div>

        {/* Name */}
        <h1 style={{
          fontFamily: "'Cormorant Garamond', serif",
          fontSize: '28px',
          fontWeight: 300,
          color: '#e8e4d9',
          letterSpacing: '2px',
          margin: '0 0 4px',
        }}>
          {profile?.display_name || name}
        </h1>

        <p style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '12px',
          color: 'rgba(255,255,255,0.3)',
          letterSpacing: '2px',
          margin: '0 0 24px',
        }}>
          {slugUrlShort(name)}
        </p>

        {/* Verified badge */}
        {profile?.verified && (
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            background: 'rgba(52, 211, 153, 0.08)',
            border: '1px solid rgba(52, 211, 153, 0.2)',
            borderRadius: '20px',
            padding: '6px 14px',
            marginBottom: '24px',
            fontSize: '11px',
            fontFamily: "'Space Grotesk', sans-serif",
            color: '#34d399',
            letterSpacing: '1px',
          }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" />
            </svg>
            VERIFIED
          </div>
        )}

        {/* Public key */}
        {(profile?.public_key || profile?.fingerprint) && (
          <div style={{ marginBottom: '24px' }}>
            <label style={{
              display: 'block',
              fontFamily: "'Space Grotesk', sans-serif",
              fontSize: '9px',
              color: 'rgba(255,255,255,0.25)',
              letterSpacing: '3px',
              marginBottom: '8px',
            }}>
              {profile?.fingerprint ? 'FINGERPRINT' : 'PUBLIC KEY'}
            </label>
            <div style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '10px',
              color: '#a09880',
              background: 'rgba(6, 10, 8, 0.8)',
              border: '1px solid rgba(52, 211, 153, 0.08)',
              borderRadius: '8px',
              padding: '12px',
              wordBreak: 'break-all' as const,
              lineHeight: '1.6',
            }}>
              {profile?.fingerprint || profile?.public_key}
            </div>
          </div>
        )}

        {/* Created date */}
        {(profile?.created_at || profile?.registered_at) && (
          <p style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '10px',
            color: 'rgba(255,255,255,0.15)',
            marginBottom: '24px',
          }}>
            Sovereign since {new Date(profile?.created_at || profile?.registered_at || '').toLocaleDateString('en-US', {
              year: 'numeric',
              month: 'long',
              day: 'numeric',
            })}
          </p>
        )}

        {/* CTA */}
        <Link
          href="/"
          style={{
            display: 'block',
            background: 'rgba(52, 211, 153, 0.1)',
            border: '1px solid rgba(52, 211, 153, 0.3)',
            borderRadius: '8px',
            padding: '14px 20px',
            color: '#34d399',
            fontSize: '12px',
            fontWeight: 500,
            fontFamily: "'Space Grotesk', sans-serif",
            letterSpacing: '2px',
            textTransform: 'uppercase' as const,
            textDecoration: 'none',
            boxShadow: '0 0 20px rgba(52, 211, 153, 0.06)',
          }}
        >
          Claim Your Sovereignty
        </Link>

        <p style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '9px',
          color: 'rgba(255,255,255,0.12)',
          marginTop: '20px',
        }}>
          Ed25519 · ML-DSA-87 ready · Local-first
        </p>
      </div>
    </div>
  );
}
