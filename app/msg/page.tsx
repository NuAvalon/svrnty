'use client';

// Notes inbox at /msg — same glass as the app-shell Notes tab.
// Unlock uses the existing vault passphrase (notes store salt is separate).

import { useCallback, useEffect, useState, type CSSProperties, type FormEvent } from 'react';
import Link from 'next/link';
import {
  getActiveFingerprint,
  hasEncryptedKeys,
  initSessionKey,
  isSessionUnlocked,
  listIdentities,
  loadIdentity,
  loadKey,
  lockSession,
} from '@/lib/identity/client-store';
import { initNotesStore, isNotesStoreUnlocked, lockNotesStore } from '@/lib/messaging';
import { NotesInbox } from '@/components/notes/NotesInbox';
import { NOTES_COPY } from '@/components/notes/notes-copy';
import { solarEmber as E, solarGlass } from '@/components/recovery/solar-ember';

type Gate = 'loading' | 'locked' | 'ready' | 'empty';

const shell: CSSProperties = {
  minHeight: '100vh',
  background: E.bgCss,
  color: E.text,
  fontFamily: E.fontSans,
  padding: '24px 16px 40px',
};

export default function NotesPage() {
  const [gate, setGate] = useState<Gate>('loading');
  const [passphrase, setPassphrase] = useState('');
  const [unlockError, setUnlockError] = useState('');
  const [identity, setIdentity] = useState<{
    identity?: { fingerprint?: string; name?: string; public_key?: string };
    post_quantum?: { kem_public_key?: string; sig_public_key?: string };
  } | null>(null);
  const [fingerprint, setFingerprint] = useState('');

  const boot = useCallback(async () => {
    try {
      const ids = await listIdentities();
      if (!ids.length) {
        setGate('empty');
        return;
      }
      const fp = (await getActiveFingerprint()) || ids[0].fingerprint;
      const id = await loadIdentity(fp);
      setFingerprint(fp);
      setIdentity(id);
      if (isSessionUnlocked() && isNotesStoreUnlocked()) {
        setGate('ready');
      } else {
        setGate('locked');
      }
    } catch {
      setGate('empty');
    }
  }, []);

  useEffect(() => {
    void boot();
  }, [boot]);

  const handleUnlock = async (e: FormEvent) => {
    e.preventDefault();
    setUnlockError('');
    try {
      if (!(await hasEncryptedKeys(fingerprint))) {
        setUnlockError(NOTES_COPY.identityKeysMissing);
        return;
      }
      await initSessionKey(passphrase);
      await loadKey(fingerprint);
      await initNotesStore(passphrase);
      setPassphrase('');
      setGate('ready');
    } catch {
      lockSession();
      lockNotesStore();
      setUnlockError('Unlock failed — check passphrase.');
    }
  };

  return (
    <div style={shell}>
      {gate === 'loading' && (
        <p style={{ textAlign: 'center', color: E.muted }}>…</p>
      )}

      {gate === 'empty' && (
        <div style={{ ...solarGlass, maxWidth: 480, margin: '40px auto', padding: 24, textAlign: 'center' }}>
          <h1 style={{ fontSize: 22, color: E.accent, margin: '0 0 12px' }}>{NOTES_COPY.tabLabel}</h1>
          <p style={{ color: E.muted, margin: '0 0 16px' }}>No identity on this device yet.</p>
          <Link href="/" style={{ color: E.accent }}>
            Create identity
          </Link>
        </div>
      )}

      {gate === 'locked' && (
        <div style={{ ...solarGlass, maxWidth: 480, margin: '40px auto', padding: 24 }}>
          <h1 style={{ fontSize: 22, color: E.accent, margin: '0 0 12px' }}>{NOTES_COPY.tabLabel}</h1>
          <p style={{ color: E.muted, fontSize: 14, lineHeight: 1.5, margin: '0 0 16px' }}>
            {NOTES_COPY.identityLocked}
          </p>
          <form onSubmit={(e) => void handleUnlock(e)} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <input
              type="password"
              placeholder="Unlock passphrase"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              autoComplete="current-password"
              style={{
                fontFamily: E.fontSans,
                fontSize: 14,
                color: E.text,
                background: E.inputBg,
                border: `1px solid ${E.border}`,
                borderRadius: 10,
                padding: '10px 12px',
              }}
            />
            {unlockError ? (
              <p role="alert" style={{ color: E.danger, fontSize: 13, margin: 0 }}>
                {unlockError}
              </p>
            ) : null}
            <button
              type="submit"
              style={{
                fontFamily: E.fontSans,
                fontSize: 13,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                color: E.bg,
                background: E.accent,
                border: 'none',
                borderRadius: 999,
                padding: '10px 18px',
                cursor: 'pointer',
              }}
            >
              Unlock
            </button>
          </form>
          <p style={{ margin: '16px 0 0' }}>
            <Link href="/" style={{ color: E.accent, fontSize: 13 }}>
              Trust book
            </Link>
          </p>
        </div>
      )}

      {gate === 'ready' && <NotesInbox identity={identity} />}
    </div>
  );
}
