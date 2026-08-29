// app/page.tsx
"use client";

import { useState, useEffect, useCallback, type CSSProperties } from 'react';
import { SoverentityFrontend } from '@/components/SoverentityFrontend';
import { ContactManagement } from '@/components/ContactManagement';
import { TrustMap } from '@/components/TrustMap';
import { HelpGuide } from '@/components/HelpGuide';
import { Ceremony } from '@/components/Ceremony';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import type { TrustEdge } from '@/lib/trust/types';
import { contactRecordToEdge } from '@/lib/trust/contact-edge';
import { solarEmber as E } from '@/components/recovery/solar-ember';
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

const shellBg: CSSProperties = {
  minHeight: '100vh',
  background: E.bgCss,
  color: E.text,
  fontFamily: E.fontSans,
};

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
  // Archie home: identity card is the first surface; Trust Map via "Your circle".
  const [mainTab, setMainTab] = useState('identity');

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
        setMainTab('identity');
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
    setMainTab('identity');
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
        ...shellBg,
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        fontSize: '14px',
        letterSpacing: '4px',
        color: E.dim,
      }}>
        RESOLVING...
      </div>
    );
  }

  // Passphrase gate
  if (appState === 'locked' && lockedIdentity) {
    return (
      <div style={{
        ...shellBg,
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        padding: '20px',
      }}>
        <div style={{
          maxWidth: '400px',
          width: '100%',
          background: E.surfaceSolid,
          border: `1px solid ${E.borderLit}`,
          borderRadius: '16px',
          padding: '40px',
          boxShadow: '0 4px 60px rgba(0, 0, 0, 0.45), 0 0 80px rgba(249, 168, 37, 0.06)',
          textAlign: 'center' as const,
          backdropFilter: 'blur(20px)',
        }}>
          <div style={{
            width: '64px',
            height: '64px',
            borderRadius: '50%',
            background: 'rgba(249, 168, 37, 0.06)',
            border: `1px solid ${E.borderLit}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 20px',
          }}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke={E.accent} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
          </div>

          <h1 style={{
            fontFamily: E.fontSerif,
            fontSize: '24px',
            fontWeight: 300,
            color: E.text,
            letterSpacing: '2px',
            margin: '0 0 4px',
          }}>
            Welcome back
          </h1>

          <p style={{
            fontFamily: E.fontMono,
            fontSize: '12px',
            color: E.muted,
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
                background: 'rgba(12, 8, 5, 0.85)',
                border: `1px solid ${unlockError ? 'rgba(255, 143, 122, 0.45)' : E.border}`,
                borderRadius: '8px',
                padding: '14px 16px',
                color: E.text,
                fontSize: '14px',
                fontFamily: E.fontSans,
                outline: 'none',
                marginBottom: '8px',
                boxSizing: 'border-box' as const,
              }}
            />

            {unlockError && (
              <p style={{
                fontFamily: E.fontSans,
                fontSize: '12px',
                color: E.danger,
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
                background: passphrase ? 'rgba(249, 168, 37, 0.14)' : 'rgba(249, 168, 37, 0.04)',
                border: `1px solid ${passphrase ? E.borderLit : E.border}`,
                borderRadius: '8px',
                padding: '14px 20px',
                color: passphrase ? E.accent : E.dim,
                fontSize: '12px',
                fontWeight: 500,
                fontFamily: E.fontSans,
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
                  fontFamily: E.fontMono,
                  fontSize: '10px',
                  letterSpacing: '1px',
                  textTransform: 'uppercase' as const,
                  color: E.dim,
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
                      background: 'rgba(255,190,120,0.03)',
                      border: `1px solid ${E.border}`,
                      borderRadius: '8px',
                      padding: '10px 14px',
                      color: E.text,
                      fontSize: '13px',
                      fontFamily: E.fontSans,
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
                border: `1px dashed ${E.borderLit}`,
                borderRadius: '8px',
                padding: '12px 16px',
                color: E.muted,
                fontSize: '12px',
                fontFamily: E.fontSans,
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
    <div className="min-h-screen px-5 py-6 sm:px-8 sm:py-8" style={shellBg}>
      <header
        style={{
          maxWidth: 1100,
          margin: '0 auto 1.75rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 16,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, minWidth: 0 }}>
          <span
            style={{
              fontFamily: E.fontSans,
              fontSize: 12,
              fontWeight: 600,
              letterSpacing: '0.2em',
              textTransform: 'uppercase',
              color: E.accent,
            }}
          >
            svrnty
          </span>
          <span
            style={{
              fontFamily: E.fontSans,
              fontSize: 13,
              color: E.dim,
              letterSpacing: '0.01em',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
          >
            local-first
          </span>
        </div>
        <HelpGuide />
      </header>

      <main className="max-w-6xl mx-auto">
        {!identity ? (
          <SoverentityFrontend onIdentityUpdate={handleIdentityUpdate} />
        ) : (
          <Tabs value={mainTab} onValueChange={setMainTab} className="w-full">
            <TabsList
              className="w-full max-w-xl mx-auto mb-8"
              style={{
                background: 'rgba(30,20,10,.55)',
                border: `1px solid ${E.border}`,
                height: 'auto',
                padding: 4,
                fontFamily: E.fontSans,
              }}
            >
              <TabsTrigger
                value="identity"
                className="flex-1 data-[state=active]:bg-[rgba(249,168,37,0.14)] data-[state=active]:text-[#fbead2]"
                style={{ color: E.muted, fontFamily: E.fontSans }}
              >
                Identity
              </TabsTrigger>
              <TabsTrigger
                value="trust-map"
                className="flex-1 data-[state=active]:bg-[rgba(249,168,37,0.14)] data-[state=active]:text-[#fbead2]"
                style={{ color: E.muted, fontFamily: E.fontSans }}
              >
                Trust Map
              </TabsTrigger>
              <TabsTrigger
                value="ceremony"
                className="flex-1 data-[state=active]:bg-[rgba(249,168,37,0.14)] data-[state=active]:text-[#fbead2]"
                style={{ color: E.muted, fontFamily: E.fontSans }}
              >
                Ceremony
              </TabsTrigger>
              <TabsTrigger
                value="contacts"
                className="flex-1 data-[state=active]:bg-[rgba(249,168,37,0.14)] data-[state=active]:text-[#fbead2]"
                style={{ color: E.muted, fontFamily: E.fontSans }}
              >
                Contacts
              </TabsTrigger>
            </TabsList>

            <TabsContent value="identity">
              <SoverentityFrontend
                existingIdentity={identity}
                onIdentityUpdate={handleIdentityUpdate}
                onOpenCircle={() => setMainTab('trust-map')}
              />
            </TabsContent>

            <TabsContent value="trust-map">
              <TrustMap
                ownerFingerprint={identity.identity.fingerprint}
                ownerName={identity.identity.name}
                contacts={contacts}
                onLoadSample={async () => {
                  const { seedSampleCircle } = await import('@/lib/trust/sample-circle');
                  await seedSampleCircle(identity.identity.fingerprint);
                  await refreshContacts();
                }}
              />
            </TabsContent>

            <TabsContent value="ceremony">
              <Ceremony identity={identity} contacts={contacts} />
            </TabsContent>

            <TabsContent value="contacts">
              <ContactManagement identity={identity} onContactsChange={refreshContacts} />
            </TabsContent>
          </Tabs>
        )}
      </main>

      <footer
        className="mt-16 text-center text-sm"
        style={{ color: E.dim, fontFamily: E.fontSans, letterSpacing: '0.02em' }}
      >
        <p>The card is yours. No account. No server that can read you.</p>
      </footer>
    </div>
  );
}
