// app/u/[name]/page.tsx — Public profile page
// Client component that checks both registration API and local identity
'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { hasIdentity, loadIdentity } from '@/lib/identity/client-store';

interface ProfileData {
  display_name?: string;
  public_key?: string;
  fingerprint?: string;
  verified?: boolean;
  created_at?: string;
  registered_at?: string;
}

export default function ProfilePage() {
  const params = useParams();
  const name = params?.name as string;
  const [profile, setProfile] = useState<ProfileData | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  useEffect(() => {
    if (!name) return;

    async function loadProfile() {
      // Try registration API first (server-side identities)
      try {
        const res = await fetch(`/api/auth/slug/${encodeURIComponent(name)}`);
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
          if (identity?.name?.toLowerCase() === name.toLowerCase()) {
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
  }, [name]);

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
          svrnty.is/{name}
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
          ED25519 + ML-DSA-87 · Post-quantum · Local-first
        </p>
      </div>
    </div>
  );
}
