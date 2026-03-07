"use client";

import React, { useState, useEffect } from 'react';

interface SoverentityFrontendProps {
  existingIdentity?: any;
  onIdentityUpdate?: (identity: any) => void;
}

export function SoverentityFrontend({
  existingIdentity,
  onIdentityUpdate
}: SoverentityFrontendProps) {
  const [identity, setIdentity] = useState(existingIdentity || null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [formData, setFormData] = useState({ name: '', email: '' });
  const [verificationState, setVerificationState] = useState({
    loading: false,
    error: null as string | null,
    status: existingIdentity?.verification?.status || 'unverified',
  });
  const [verificationCode, setVerificationCode] = useState('');

  useEffect(() => {
    if (existingIdentity) {
      setIdentity(existingIdentity);
      setVerificationState(prev => ({
        ...prev,
        status: existingIdentity.verification?.status || 'unverified',
      }));
    }
  }, [existingIdentity]);

  const handleCreateIdentity = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('/api/identity', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Failed to create identity');
      setIdentity(data.identity);
      onIdentityUpdate?.(data.identity);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleVerification = async () => {
    try {
      setVerificationState(prev => ({ ...prev, loading: true, error: null }));
      const response = await fetch('/api/identity/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fingerprint: identity.identity.fingerprint,
          type: 'email',
          value: identity.identity.email,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Verification failed');
      setVerificationState(prev => ({ ...prev, status: 'verification_sent', loading: false }));
    } catch (err) {
      setVerificationState(prev => ({
        ...prev,
        error: err instanceof Error ? err.message : 'Verification failed',
        loading: false,
      }));
    }
  };

  const handleVerifyCode = async () => {
    try {
      setVerificationState(prev => ({ ...prev, loading: true, error: null }));
      const response = await fetch('/api/identity/verify', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fingerprint: identity.identity.fingerprint,
          code: verificationCode,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Code verification failed');
      setVerificationState(prev => ({ ...prev, status: 'verified', loading: false }));
      setIdentity(data.identity);
      onIdentityUpdate?.(data.identity);
    } catch (err) {
      setVerificationState(prev => ({
        ...prev,
        error: err instanceof Error ? err.message : 'Code verification failed',
        loading: false,
      }));
    }
  };

  const formatFingerprint = (fp: string) => fp?.match(/.{1,4}/g)?.join(' ') || fp;

  // --- Creation Screen ---
  if (!identity) {
    return (
      <div style={s.outerWrap}>
        <div style={s.createPanel}>
          {/* Hero */}
          <div style={s.hero}>
            <div style={s.keyIcon}>
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#c8a84e" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
              </svg>
            </div>
            <h2 style={s.heroTitle}>Forge Your Identity</h2>
            <p style={s.heroSub}>
              Generate a sovereign keypair. Your keys never leave your device.
              Post-quantum encryption. No servers. No tracking.
            </p>
          </div>

          {error && <div style={s.error}>{error}</div>}

          {/* Form */}
          <div style={s.field}>
            <label style={s.label}>NAME</label>
            <input
              type="text"
              placeholder="Your name"
              value={formData.name}
              onChange={e => setFormData(prev => ({ ...prev, name: e.target.value }))}
              style={s.input}
            />
          </div>

          <div style={s.field}>
            <label style={s.label}>EMAIL</label>
            <input
              type="email"
              placeholder="your@email.com"
              value={formData.email}
              onChange={e => setFormData(prev => ({ ...prev, email: e.target.value }))}
              style={s.input}
            />
            <p style={s.hint}>Used for verification. Never shared.</p>
          </div>

          <button
            onClick={handleCreateIdentity}
            disabled={loading || !formData.name || !formData.email}
            style={{
              ...s.primaryBtn,
              opacity: loading || !formData.name || !formData.email ? 0.5 : 1,
            }}
          >
            {loading ? (
              <span style={s.btnInner}>
                <Spinner /> Generating keys...
              </span>
            ) : (
              <span style={s.btnInner}>Forge Identity</span>
            )}
          </button>

          <p style={s.footer}>
            ED25519 + ML-DSA-65 signing. Curve25519 + ML-KEM-768 encryption.
            <br />Your keys. Your data. Your sovereignty.
          </p>
        </div>
      </div>
    );
  }

  // --- Identity View ---
  const isVerified = verificationState.status === 'verified' || identity.verification?.status === 'verified';

  return (
    <div style={s.outerWrap}>
      <div style={s.identityPanel}>
        {/* Identity Card */}
        <div style={s.idCard}>
          <div style={s.idHeader}>
            <div style={{
              ...s.statusDot,
              background: isVerified ? '#6a9a6a' : '#c8a84e',
              boxShadow: `0 0 8px ${isVerified ? 'rgba(106,154,106,0.4)' : 'rgba(200,168,78,0.4)'}`,
            }} />
            <div>
              <h3 style={s.idName}>{identity.identity.name}</h3>
              <p style={s.idEmail}>{identity.identity.email}</p>
            </div>
            <span style={{
              ...s.statusBadge,
              color: isVerified ? '#6a9a6a' : '#c8a84e',
              borderColor: isVerified ? 'rgba(106,154,106,0.3)' : 'rgba(200,168,78,0.3)',
              background: isVerified ? 'rgba(106,154,106,0.1)' : 'rgba(200,168,78,0.1)',
            }}>
              {isVerified ? 'VERIFIED' : 'UNVERIFIED'}
            </span>
          </div>

          <div style={s.fpSection}>
            <label style={s.label}>FINGERPRINT</label>
            <div style={s.fpValue}>{formatFingerprint(identity.identity.fingerprint)}</div>
          </div>

          <div style={s.cryptoTags}>
            <span style={s.tag}>ED25519</span>
            <span style={s.tag}>ML-DSA-65</span>
            <span style={s.tag}>Curve25519</span>
            <span style={s.tag}>ML-KEM-768</span>
          </div>
        </div>

        {/* Verification Section */}
        {!isVerified && (
          <div style={s.verifySection}>
            <h3 style={s.sectionTitle}>VERIFY IDENTITY</h3>

            {verificationState.error && (
              <div style={s.error}>{verificationState.error}</div>
            )}

            {verificationState.status === 'verification_sent' ? (
              <>
                <p style={s.verifyText}>
                  Verification code sent to your email. Enter it below.
                </p>
                <input
                  type="text"
                  placeholder="Enter code"
                  value={verificationCode}
                  onChange={e => setVerificationCode(e.target.value)}
                  maxLength={6}
                  style={{ ...s.input, textAlign: 'center' as const, letterSpacing: '6px', fontSize: '18px' }}
                />
                <button
                  onClick={handleVerifyCode}
                  disabled={verificationState.loading || !verificationCode}
                  style={{
                    ...s.primaryBtn,
                    opacity: verificationState.loading || !verificationCode ? 0.5 : 1,
                  }}
                >
                  {verificationState.loading ? (
                    <span style={s.btnInner}><Spinner /> Verifying...</span>
                  ) : (
                    <span style={s.btnInner}>Verify</span>
                  )}
                </button>
              </>
            ) : (
              <>
                <p style={s.verifyText}>
                  Verify your email to prove ownership of this identity.
                </p>
                <button
                  onClick={handleVerification}
                  disabled={verificationState.loading}
                  style={{
                    ...s.outlineBtn,
                    opacity: verificationState.loading ? 0.5 : 1,
                  }}
                >
                  {verificationState.loading ? (
                    <span style={s.btnInner}><Spinner /> Sending...</span>
                  ) : (
                    <span style={s.btnInner}>Send Verification Email</span>
                  )}
                </button>
              </>
            )}
          </div>
        )}

        {isVerified && (
          <div style={s.verifiedBanner}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#6a9a6a" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" />
            </svg>
            <span>Identity verified. You are sovereign.</span>
          </div>
        )}
      </div>
    </div>
  );
}

function Spinner() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ animation: 'spin 1s linear infinite' }}>
      <path d="M21 12a9 9 0 1 1-6.219-8.56" />
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </svg>
  );
}

// --- Inline styles (constellation aesthetic) ---

const s: Record<string, React.CSSProperties> = {
  outerWrap: {
    display: 'flex',
    justifyContent: 'center',
    padding: '20px 0',
  },
  createPanel: {
    background: 'rgba(15, 15, 25, 0.85)',
    backdropFilter: 'blur(16px)',
    border: '1px solid rgba(180, 160, 100, 0.12)',
    borderRadius: '16px',
    padding: '40px',
    maxWidth: '460px',
    width: '100%',
    boxShadow: '0 4px 60px rgba(0, 0, 0, 0.4), 0 0 40px rgba(200, 168, 78, 0.03)',
  },
  hero: {
    textAlign: 'center' as const,
    marginBottom: '32px',
  },
  keyIcon: {
    width: '72px',
    height: '72px',
    borderRadius: '50%',
    background: 'rgba(200, 168, 78, 0.08)',
    border: '1px solid rgba(200, 168, 78, 0.2)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    margin: '0 auto 20px',
    boxShadow: '0 0 30px rgba(200, 168, 78, 0.06)',
  },
  heroTitle: {
    fontSize: '22px',
    fontWeight: 600,
    color: '#e0dcd0',
    letterSpacing: '1px',
    marginBottom: '10px',
  },
  heroSub: {
    fontSize: '13px',
    color: '#8a8070',
    lineHeight: '1.6',
    maxWidth: '340px',
    margin: '0 auto',
  },
  field: {
    marginBottom: '20px',
  },
  label: {
    display: 'block',
    fontSize: '10px',
    color: '#8a8070',
    letterSpacing: '2px',
    textTransform: 'uppercase' as const,
    marginBottom: '8px',
    fontWeight: 500,
  },
  input: {
    width: '100%',
    background: 'rgba(10, 10, 15, 0.7)',
    border: '1px solid rgba(180, 160, 100, 0.15)',
    borderRadius: '8px',
    padding: '12px 16px',
    color: '#e0dcd0',
    fontSize: '14px',
    fontFamily: "'JetBrains Mono', monospace",
    outline: 'none',
    transition: 'border-color 0.2s',
  },
  hint: {
    fontSize: '11px',
    color: '#5a5548',
    marginTop: '6px',
  },
  primaryBtn: {
    width: '100%',
    background: 'rgba(200, 168, 78, 0.15)',
    border: '1px solid rgba(200, 168, 78, 0.35)',
    borderRadius: '8px',
    padding: '14px 20px',
    color: '#c8a84e',
    fontSize: '13px',
    fontWeight: 600,
    fontFamily: "'JetBrains Mono', monospace",
    letterSpacing: '1px',
    cursor: 'pointer',
    transition: 'all 0.2s',
    marginTop: '8px',
  },
  outlineBtn: {
    width: '100%',
    background: 'transparent',
    border: '1px solid rgba(180, 160, 100, 0.25)',
    borderRadius: '8px',
    padding: '14px 20px',
    color: '#8a8070',
    fontSize: '13px',
    fontWeight: 500,
    fontFamily: "'JetBrains Mono', monospace",
    letterSpacing: '0.5px',
    cursor: 'pointer',
    transition: 'all 0.2s',
    marginTop: '8px',
  },
  btnInner: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
  },
  footer: {
    fontSize: '10px',
    color: '#3a3530',
    textAlign: 'center' as const,
    marginTop: '24px',
    lineHeight: '1.6',
    letterSpacing: '0.3px',
  },
  error: {
    background: 'rgba(154, 90, 90, 0.1)',
    border: '1px solid rgba(154, 90, 90, 0.25)',
    borderRadius: '8px',
    padding: '12px 16px',
    color: '#d47a7a',
    fontSize: '13px',
    marginBottom: '16px',
  },
  // --- Identity view ---
  identityPanel: {
    maxWidth: '520px',
    width: '100%',
    margin: '0 auto',
  },
  idCard: {
    background: 'rgba(15, 15, 25, 0.85)',
    backdropFilter: 'blur(16px)',
    border: '1px solid rgba(180, 160, 100, 0.15)',
    borderRadius: '16px',
    padding: '28px',
    boxShadow: '0 4px 60px rgba(0, 0, 0, 0.4)',
  },
  idHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '14px',
    marginBottom: '24px',
  },
  statusDot: {
    width: '10px',
    height: '10px',
    borderRadius: '50%',
    flexShrink: 0,
  },
  idName: {
    fontSize: '18px',
    fontWeight: 600,
    color: '#e0dcd0',
    margin: 0,
  },
  idEmail: {
    fontSize: '12px',
    color: '#8a8070',
    margin: 0,
  },
  statusBadge: {
    marginLeft: 'auto',
    fontSize: '10px',
    fontWeight: 600,
    letterSpacing: '1.5px',
    padding: '4px 10px',
    borderRadius: '4px',
    border: '1px solid',
  },
  fpSection: {
    marginBottom: '20px',
  },
  fpValue: {
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: '11px',
    letterSpacing: '1.5px',
    color: '#a09880',
    background: 'rgba(10, 10, 15, 0.5)',
    border: '1px solid rgba(180, 160, 100, 0.1)',
    borderRadius: '6px',
    padding: '10px 14px',
    wordBreak: 'break-all' as const,
  },
  cryptoTags: {
    display: 'flex',
    flexWrap: 'wrap' as const,
    gap: '6px',
  },
  tag: {
    fontSize: '9px',
    fontWeight: 600,
    letterSpacing: '1px',
    color: '#4ecdc4',
    background: 'rgba(78, 205, 196, 0.08)',
    border: '1px solid rgba(78, 205, 196, 0.15)',
    borderRadius: '4px',
    padding: '3px 8px',
  },
  verifySection: {
    background: 'rgba(15, 15, 25, 0.6)',
    border: '1px solid rgba(180, 160, 100, 0.1)',
    borderRadius: '12px',
    padding: '24px',
    marginTop: '16px',
  },
  sectionTitle: {
    fontSize: '11px',
    color: '#c8a84e',
    letterSpacing: '2px',
    fontWeight: 600,
    marginBottom: '16px',
  },
  verifyText: {
    fontSize: '13px',
    color: '#8a8070',
    marginBottom: '16px',
    lineHeight: '1.5',
  },
  verifiedBanner: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    background: 'rgba(106, 154, 106, 0.08)',
    border: '1px solid rgba(106, 154, 106, 0.2)',
    borderRadius: '10px',
    padding: '14px 20px',
    marginTop: '16px',
    fontSize: '13px',
    color: '#6a9a6a',
  },
};
