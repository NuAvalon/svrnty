// app/c/[code]/page.tsx
// Landing page for shortcode relay links.
// Reads the code from the URL path and the AES key from the fragment.
// Decrypts locally — the server never sees the key.
"use client";

import { useState, useEffect, useCallback } from 'react';
import { resolveRelay } from '@/lib/sync/relay';

type Status = 'loading' | 'decrypted' | 'importing' | 'imported' | 'error' | 'already_exists';

interface ImportResult {
  contact?: { peer_name?: string; name?: string };
  message?: string;
}

export default function RelayPage({ params }: { params: Promise<{ code: string }> }) {
  const [status, setStatus] = useState<Status>('loading');
  const [exchangeData, setExchangeData] = useState<string>('');
  const [error, setError] = useState<string>('');
  const [importResult, setImportResult] = useState<ImportResult | null>(null);
  const [code, setCode] = useState<string>('');

  useEffect(() => {
    let cancelled = false;

    async function resolve() {
      try {
        const { code: resolvedCode } = await params;
        if (cancelled) return;
        setCode(resolvedCode);

        // Read the key from the URL fragment (never sent to server)
        const hash = window.location.hash;
        if (!hash || hash.length < 2) {
          setError('Missing decryption key. The link may be incomplete.');
          setStatus('error');
          return;
        }
        const keyFragment = hash.slice(1); // remove the '#'

        // Fetch + decrypt
        const decrypted = await resolveRelay(resolvedCode, keyFragment);
        if (cancelled) return;
        setExchangeData(decrypted);
        setStatus('decrypted');
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'Failed to decrypt relay.');
        setStatus('error');
      }
    }

    resolve();
    return () => { cancelled = true; };
  }, [params]);

  const handleImport = useCallback(async () => {
    if (!exchangeData) return;

    setStatus('importing');
    try {
      // The user needs an active identity to import. Try to get fingerprint from localStorage.
      const fingerprint = localStorage.getItem('svrnty_active_fingerprint');
      if (!fingerprint) {
        setError('No active identity found. Please set up your identity on the main page first, then revisit this link.');
        setStatus('error');
        return;
      }

      const res = await fetch('/api/contacts/process', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fingerprint, exchangeData }),
      });

      const data = await res.json();

      if (!res.ok || !data.success) {
        setError(data.error || 'Import failed.');
        setStatus('error');
        return;
      }

      setImportResult(data);
      setStatus(data.alreadyExists ? 'already_exists' : 'imported');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Import failed.');
      setStatus('error');
    }
  }, [exchangeData]);

  return (
    <div
      className="min-h-screen flex items-center justify-center p-6"
      style={{ background: '#0a0a0f', color: '#e0dcd0' }}
    >
      <div className="stars" />

      <div
        className="w-full max-w-md rounded-xl p-8"
        style={{
          background: 'rgba(15, 15, 25, 0.85)',
          backdropFilter: 'blur(12px)',
          border: '1px solid rgba(180, 160, 100, 0.12)',
          boxShadow: '0 4px 40px rgba(0, 0, 0, 0.4), 0 0 60px rgba(200, 168, 78, 0.04)',
        }}
      >
        {/* Header */}
        <div className="text-center mb-8">
          <h1
            className="text-xl font-bold tracking-widest mb-1"
            style={{ color: '#c8a84e' }}
          >
            SVRNTY
          </h1>
          <p className="text-xs" style={{ color: '#5a5548' }}>
            Secure Identity Exchange
          </p>
        </div>

        {/* Loading */}
        {status === 'loading' && (
          <div className="text-center">
            <div
              className="inline-block w-6 h-6 rounded-full border-2 animate-spin mb-4"
              style={{
                borderColor: 'rgba(200, 168, 78, 0.2)',
                borderTopColor: '#c8a84e',
              }}
            />
            <p className="text-sm" style={{ color: '#8a8070' }}>
              Retrieving and decrypting...
            </p>
            <p className="text-xs mt-2" style={{ color: '#5a5548' }}>
              Code: {code || '...'}
            </p>
          </div>
        )}

        {/* Decrypted — ready to import */}
        {status === 'decrypted' && (
          <div>
            <div
              className="rounded-lg p-4 mb-6"
              style={{
                background: 'rgba(78, 205, 196, 0.06)',
                border: '1px solid rgba(78, 205, 196, 0.15)',
              }}
            >
              <div className="flex items-center gap-2 mb-2">
                <div
                  className="w-2 h-2 rounded-full"
                  style={{ background: '#4ecdc4' }}
                />
                <span className="text-xs font-medium" style={{ color: '#4ecdc4' }}>
                  Package decrypted
                </span>
              </div>
              <p className="text-xs" style={{ color: '#8a8070' }}>
                A signed identity exchange package is ready to import.
              </p>
            </div>

            <button
              onClick={handleImport}
              className="w-full py-3 px-4 rounded-lg text-sm font-medium transition-all"
              style={{
                background: 'rgba(200, 168, 78, 0.15)',
                border: '1px solid rgba(200, 168, 78, 0.3)',
                color: '#c8a84e',
                letterSpacing: '1px',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = 'rgba(200, 168, 78, 0.25)';
                e.currentTarget.style.boxShadow = '0 0 16px rgba(200, 168, 78, 0.12)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = 'rgba(200, 168, 78, 0.15)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              IMPORT CONTACT
            </button>

            <div className="mt-6 pt-4" style={{ borderTop: '1px solid rgba(180, 160, 100, 0.08)' }}>
              <p className="text-xs text-center" style={{ color: '#5a5548' }}>
                This data was decrypted locally. The server never saw your identity.
              </p>
            </div>
          </div>
        )}

        {/* Importing */}
        {status === 'importing' && (
          <div className="text-center">
            <div
              className="inline-block w-6 h-6 rounded-full border-2 animate-spin mb-4"
              style={{
                borderColor: 'rgba(200, 168, 78, 0.2)',
                borderTopColor: '#c8a84e',
              }}
            />
            <p className="text-sm" style={{ color: '#8a8070' }}>
              Verifying signatures and importing...
            </p>
          </div>
        )}

        {/* Imported successfully */}
        {status === 'imported' && importResult && (
          <div>
            <div
              className="rounded-lg p-4 mb-6"
              style={{
                background: 'rgba(78, 205, 196, 0.06)',
                border: '1px solid rgba(78, 205, 196, 0.15)',
              }}
            >
              <div className="flex items-center gap-2 mb-2">
                <div
                  className="w-2 h-2 rounded-full"
                  style={{ background: '#4ecdc4' }}
                />
                <span className="text-xs font-medium" style={{ color: '#4ecdc4' }}>
                  Contact imported
                </span>
              </div>
              <p className="text-sm" style={{ color: '#e0dcd0' }}>
                {importResult.message || 'Contact added to your network.'}
              </p>
            </div>

            <a
              href="/"
              className="block w-full py-3 px-4 rounded-lg text-sm font-medium text-center transition-all"
              style={{
                background: 'rgba(180, 160, 100, 0.08)',
                border: '1px solid rgba(180, 160, 100, 0.15)',
                color: '#8a8070',
                textDecoration: 'none',
                letterSpacing: '1px',
              }}
            >
              OPEN SVRNTY
            </a>

            <div className="mt-6 pt-4" style={{ borderTop: '1px solid rgba(180, 160, 100, 0.08)' }}>
              <p className="text-xs text-center" style={{ color: '#5a5548' }}>
                This data was decrypted locally. The server never saw your identity.
              </p>
            </div>
          </div>
        )}

        {/* Already exists */}
        {status === 'already_exists' && importResult && (
          <div>
            <div
              className="rounded-lg p-4 mb-6"
              style={{
                background: 'rgba(200, 168, 78, 0.06)',
                border: '1px solid rgba(200, 168, 78, 0.15)',
              }}
            >
              <div className="flex items-center gap-2 mb-2">
                <div
                  className="w-2 h-2 rounded-full"
                  style={{ background: '#c8a84e' }}
                />
                <span className="text-xs font-medium" style={{ color: '#c8a84e' }}>
                  Already known
                </span>
              </div>
              <p className="text-sm" style={{ color: '#e0dcd0' }}>
                {importResult.message || 'This contact already exists in your network.'}
              </p>
            </div>

            <a
              href="/"
              className="block w-full py-3 px-4 rounded-lg text-sm font-medium text-center transition-all"
              style={{
                background: 'rgba(180, 160, 100, 0.08)',
                border: '1px solid rgba(180, 160, 100, 0.15)',
                color: '#8a8070',
                textDecoration: 'none',
                letterSpacing: '1px',
              }}
            >
              OPEN SVRNTY
            </a>
          </div>
        )}

        {/* Error */}
        {status === 'error' && (
          <div>
            <div
              className="rounded-lg p-4 mb-6"
              style={{
                background: 'rgba(212, 120, 90, 0.06)',
                border: '1px solid rgba(212, 120, 90, 0.15)',
              }}
            >
              <div className="flex items-center gap-2 mb-2">
                <div
                  className="w-2 h-2 rounded-full"
                  style={{ background: '#d4785a' }}
                />
                <span className="text-xs font-medium" style={{ color: '#d4785a' }}>
                  Link unavailable
                </span>
              </div>
              <p className="text-sm" style={{ color: '#e0dcd0' }}>
                {error || 'This link has expired or already been used.'}
              </p>
            </div>

            <a
              href="/"
              className="block w-full py-3 px-4 rounded-lg text-sm font-medium text-center transition-all"
              style={{
                background: 'rgba(180, 160, 100, 0.08)',
                border: '1px solid rgba(180, 160, 100, 0.15)',
                color: '#8a8070',
                textDecoration: 'none',
                letterSpacing: '1px',
              }}
            >
              GO TO SVRNTY
            </a>
          </div>
        )}
      </div>
    </div>
  );
}
