// app/page.tsx
"use client";

import { useState, useEffect, useCallback } from 'react';
import { SoverentityFrontend } from '@/components/SoverentityFrontend';
import { ContactManagement } from '@/components/ContactManagement';
import { TrustMap } from '@/components/TrustMap';
import { HelpGuide } from '@/components/HelpGuide';
import { Ceremony } from '@/components/Ceremony';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import type { TrustEdge } from '@/lib/trust/types';
import { contactRecordToEdge } from '@/lib/trust/contact-edge';
import {
  hasIdentity,
  getActiveFingerprint,
  loadIdentity,
  getAllContacts,
  hasEncryptedKeys,
  initSessionKey,
  isSessionUnlocked,
  loadKey,
  lockSession,
  listIdentities,
  setActiveFingerprint,
} from '@/lib/identity/client-store';

type AppState = 'checking' | 'locked' | 'gate' | 'unlocked';

export default function Home() {
  const [appState, setAppState] = useState<AppState>('checking');
  const [identity, setIdentity] = useState<any>(null);
  const [contacts, setContacts] = useState<TrustEdge[]>([]);
  const [lockedIdentity, setLockedIdentity] = useState<{ name: string; fingerprint: string } | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [unlockError, setUnlockError] = useState('');
  const [unlocking, setUnlocking] = useState(false);
  // Phase-1 identity switcher (UI-only): other on-device vaults, loaded EPHEMERALLY into component
  // state — never persisted as a new cross-identity link (Flint's correlation-surface line). Empty in
  // the single-identity case, so the demo shows only "New Identity" (no fingerprints co-located).
  const [otherIdentities, setOtherIdentities] = useState<{ name: string; fingerprint: string }[]>([]);

  // Check for existing identity on page load.
  // Encrypted-at-rest keys require initSessionKey before unlocking.
  useEffect(() => {
    async function checkIdentity() {
      try {
        const exists = await hasIdentity();
        if (exists) {
          const fp = await getActiveFingerprint();
          if (fp) {
            const id = await loadIdentity(fp);
            if (id) {
              const encrypted = await hasEncryptedKeys(fp);
              if (encrypted && !isSessionUnlocked()) {
                setLockedIdentity({
                  name: id.identity?.name || 'Identity',
                  fingerprint: fp,
                });
                setIdentity(null);
                setAppState('locked');
                return;
              }
              setIdentity(id);
              setAppState('unlocked');
              return;
            }
          }
        }
        setAppState('gate');
      } catch {
        setAppState('gate');
      }
    }
    checkIdentity();
  }, []);

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!lockedIdentity || !passphrase) return;

    setUnlocking(true);
    setUnlockError('');

    try {
      // User unlock passphrase derives the session key — it is NOT the PGP key passphrase.
      await initSessionKey(passphrase);
      const key = await loadKey(lockedIdentity.fingerprint);
      if (!key) {
        lockSession();
        setUnlockError('Could not decrypt keys — wrong passphrase?');
        return;
      }
      const id = await loadIdentity(lockedIdentity.fingerprint);
      if (id) {
        setIdentity(id);
        setAppState('unlocked');
        setPassphrase('');
        setLockedIdentity(null);
      } else {
        lockSession();
        setUnlockError('Identity data not found');
      }
    } catch {
      lockSession();
      setUnlockError('Incorrect passphrase');
    } finally {
      setUnlocking(false);
    }
  };

  // Phase-1: when locked, load the OTHER on-device vaults so the switcher can offer them. Ephemeral —
  // reads the existing identities store into component state only; adds NO new persisted cross-identity
  // link. Cleared whenever we leave the locked screen.
  useEffect(() => {
    if (appState !== 'locked') { setOtherIdentities([]); return; }
    let cancelled = false;
    (async () => {
      try {
        const all = await listIdentities();
        const active = lockedIdentity?.fingerprint;
        const others = all
          .filter((r) => r.fingerprint && r.fingerprint !== active)
          .map((r) => ({ name: r.data?.identity?.name || 'Identity', fingerprint: r.fingerprint }));
        if (!cancelled) setOtherIdentities(others);
      } catch { if (!cancelled) setOtherIdentities([]); }
    })();
    return () => { cancelled = true; };
  }, [appState, lockedIdentity?.fingerprint]);

  // Phase-1 swap: choose another EXISTING vault to unlock instead of the current one. We are already
  // locked (no keys in memory); lockSession() first is defensive so no key material bleeds across the
  // swap (Flint #4). Then repoint the active pointer + unlock form at the chosen vault. Existing
  // primitives only — no new vault schema, no derivation (that is Phase 2).
  const handleSwitchIdentity = async (fingerprint: string, name: string) => {
    lockSession();
    await setActiveFingerprint(fingerprint);
    setLockedIdentity({ name, fingerprint });
    setPassphrase('');
    setUnlockError('');
  };

  const handleIdentityUpdate = (newIdentity: any) => {
    setIdentity(newIdentity);
    setAppState('unlocked');
    setLockedIdentity(null);
  };

  // Load contacts — extracted as callback so ContactManagement can trigger refresh
  const refreshContacts = useCallback(async () => {
    if (!identity?.identity?.fingerprint) return;
    try {
      const rawContacts = await getAllContacts(identity.identity.fingerprint);
      // Single shared projection (carries pq — see contact-edge.ts). Same helper the joiner
      // ceremony uses, so no field (incl. peer_pq_*) is dropped on one path but not the other.
      const edges: TrustEdge[] = rawContacts.map(contactRecordToEdge);
      setContacts(edges);
    } catch (err: any) {
      console.error('Failed to load contacts:', err);
    }
  }, [identity]);

  // Load contacts when identity is available
  useEffect(() => {
    refreshContacts();
  }, [refreshContacts]);

  // Loading state
  if (appState === 'checking') {
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

  // Passphrase gate
  if (appState === 'locked' && lockedIdentity) {
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
          maxWidth: '400px',
          width: '100%',
          background: 'rgba(10, 14, 12, 0.92)',
          border: '1px solid rgba(52, 211, 153, 0.1)',
          borderRadius: '16px',
          padding: '40px',
          boxShadow: '0 4px 60px rgba(0, 0, 0, 0.5), 0 0 80px rgba(52, 211, 153, 0.03)',
          textAlign: 'center' as const,
        }}>
          {/* Lock icon */}
          <div style={{
            width: '64px',
            height: '64px',
            borderRadius: '50%',
            background: 'rgba(52, 211, 153, 0.06)',
            border: '1px solid rgba(52, 211, 153, 0.12)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 20px',
          }}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#34d399" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
          </div>

          <h1 style={{
            fontFamily: "'Cormorant Garamond', serif",
            fontSize: '24px',
            fontWeight: 300,
            color: '#e8e4d9',
            letterSpacing: '2px',
            margin: '0 0 4px',
          }}>
            Welcome back
          </h1>

          <p style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '12px',
            color: 'rgba(255,255,255,0.3)',
            marginBottom: '28px',
          }}>
            {lockedIdentity.name}
          </p>

          <form onSubmit={handleUnlock}>
            <input
              type="password"
              placeholder="Enter passphrase"
              value={passphrase}
              onChange={e => { setPassphrase(e.target.value); setUnlockError(''); }}
              autoFocus
              style={{
                width: '100%',
                background: 'rgba(6, 10, 8, 0.8)',
                border: `1px solid ${unlockError ? 'rgba(239, 68, 68, 0.4)' : 'rgba(52, 211, 153, 0.15)'}`,
                borderRadius: '8px',
                padding: '14px 16px',
                color: '#e8e4d9',
                fontSize: '14px',
                fontFamily: "'Space Grotesk', sans-serif",
                outline: 'none',
                marginBottom: '8px',
                boxSizing: 'border-box' as const,
              }}
            />

            {unlockError && (
              <p style={{
                fontFamily: "'Space Grotesk', sans-serif",
                fontSize: '12px',
                color: '#ef4444',
                marginBottom: '8px',
              }}>
                {unlockError}
              </p>
            )}

            <button
              type="submit"
              disabled={unlocking || !passphrase}
              style={{
                width: '100%',
                background: passphrase ? 'rgba(52, 211, 153, 0.12)' : 'rgba(52, 211, 153, 0.04)',
                border: `1px solid ${passphrase ? 'rgba(52, 211, 153, 0.3)' : 'rgba(52, 211, 153, 0.1)'}`,
                borderRadius: '8px',
                padding: '14px 20px',
                color: passphrase ? '#34d399' : 'rgba(52, 211, 153, 0.3)',
                fontSize: '12px',
                fontWeight: 500,
                fontFamily: "'Space Grotesk', sans-serif",
                letterSpacing: '2px',
                textTransform: 'uppercase' as const,
                cursor: passphrase ? 'pointer' : 'default',
                marginTop: '8px',
              }}
            >
              {unlocking ? 'UNLOCKING...' : 'UNLOCK'}
            </button>
          </form>

          {/* Phase-1 identity switcher (home screen) — UI only, no vault changes. Single-identity case
              shows only "New Identity"; the switch list appears solely when 2+ vaults exist on-device. */}
          <div style={{ marginTop: '24px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {otherIdentities.length > 0 && (
              <div data-testid="switch-identity" style={{ marginBottom: '4px' }}>
                <p style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '10px',
                  letterSpacing: '1px',
                  textTransform: 'uppercase' as const,
                  color: 'rgba(255,255,255,0.25)',
                  marginBottom: '6px',
                }}>
                  Switch identity
                </p>
                {otherIdentities.map(o => (
                  <button
                    key={o.fingerprint}
                    data-testid="switch-identity-option"
                    onClick={() => handleSwitchIdentity(o.fingerprint, o.name)}
                    style={{
                      width: '100%',
                      background: 'rgba(255,255,255,0.03)',
                      border: '1px solid rgba(255,255,255,0.08)',
                      borderRadius: '8px',
                      padding: '10px 14px',
                      color: 'rgba(232,228,217,0.8)',
                      fontSize: '13px',
                      fontFamily: "'Space Grotesk', sans-serif",
                      textAlign: 'left' as const,
                      cursor: 'pointer',
                      marginBottom: '6px',
                    }}
                  >
                    {o.name}
                  </button>
                ))}
              </div>
            )}
            <button
              data-testid="new-identity-btn"
              onClick={() => setAppState('gate')}
              style={{
                width: '100%',
                background: 'none',
                border: '1px dashed rgba(52, 211, 153, 0.25)',
                borderRadius: '8px',
                padding: '12px 16px',
                color: 'rgba(52, 211, 153, 0.7)',
                fontSize: '12px',
                fontFamily: "'Space Grotesk', sans-serif",
                letterSpacing: '1px',
                cursor: 'pointer',
              }}
            >
              + New Identity
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Gate (no identity) or main app
  return (
    <div className="min-h-screen p-8" style={{ background: '#0a0a0f', color: '#e0dcd0' }}>
      <header className="mb-12 text-center relative">
        <h1 className="text-3xl font-bold mb-2" style={{ color: '#c8a84e', letterSpacing: '3px' }}>SVRNTY</h1>
        <p style={{ color: '#8a8070', fontSize: '14px' }}>Self-Sovereign Trust Network</p>
        <p style={{ color: '#5a5548', fontSize: '11px', marginTop: '4px' }}>from NuAvalon</p>
        {identity && (
          <p style={{ marginTop: '12px' }}>
            <a
              href="/msg"
              style={{
                color: 'rgba(200, 168, 78, 0.85)',
                fontSize: '12px',
                fontFamily: "'Space Grotesk', sans-serif",
                letterSpacing: '1px',
                textDecoration: 'none',
                borderBottom: '1px solid rgba(200, 168, 78, 0.3)',
              }}
            >
              Notes between contacts
            </a>
          </p>
        )}
        <HelpGuide />
      </header>

      <main className="max-w-6xl mx-auto">
        {!identity ? (
          <SoverentityFrontend onIdentityUpdate={handleIdentityUpdate} />
        ) : (
          <Tabs defaultValue="trust-map" className="w-full">
            <TabsList className="w-full max-w-2xl mx-auto mb-8">
              <TabsTrigger value="trust-map" className="flex-1">Trust Map</TabsTrigger>
              <TabsTrigger value="ceremony" className="flex-1">Ceremony</TabsTrigger>
              <TabsTrigger value="contacts" className="flex-1">Contacts</TabsTrigger>
              <TabsTrigger value="identity" className="flex-1">Identity</TabsTrigger>
            </TabsList>

            <TabsContent value="trust-map">
              <TrustMap
                ownerFingerprint={identity.identity.fingerprint}
                ownerName={identity.identity.name}
                contacts={contacts}
              />
            </TabsContent>

            <TabsContent value="ceremony">
              <Ceremony identity={identity} contacts={contacts} />
            </TabsContent>

            <TabsContent value="contacts">
              <ContactManagement identity={identity} onContactsChange={refreshContacts} />
            </TabsContent>

            <TabsContent value="identity">
              <SoverentityFrontend
                existingIdentity={identity}
                onIdentityUpdate={handleIdentityUpdate}
              />
            </TabsContent>
          </Tabs>
        )}
      </main>

      <footer className="mt-16 text-center text-sm" style={{ color: '#5a5548' }}>
        <p>SVRNTY — Self-Sovereign Trust Network</p>
        <p className="mt-1">All data is encrypted and stored locally. No server can read it. No tracking.</p>
      </footer>
    </div>
  );
}
