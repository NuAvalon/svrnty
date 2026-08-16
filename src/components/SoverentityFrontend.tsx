"use client";

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { SecureExportDialog, PrivateKeyExportDialog } from '@/components/SecureImportExportDialogs';
import { getBrowserIdentity } from '@/lib/identity/browser-identity';
import { loadKey, storeKey, loadPQKeys, initSessionKey, isSessionUnlocked } from '@/lib/identity/client-store';

interface SoverentityFrontendProps {
  existingIdentity?: any;
  onIdentityUpdate?: (identity: any) => void;
  onVaultRestore?: (contents: any) => void;
}

type GateMode = 'choose' | 'forge' | 'restore' | 'restore-verify' | 'pq-migrate' | 'recovery-reveal';

// --- Constellation Background ---
// Generates fixed node positions once (via useMemo) and animates with CSS.
// Nodes drift slowly, lines pulse between nearby nodes — a living trust map.

interface ConstellationNode {
  id: number;
  x: number;
  y: number;
  size: number;
  delay: number;
  duration: number;
  drift: number;
}

function generateNodes(count: number): ConstellationNode[] {
  const nodes: ConstellationNode[] = [];
  for (let i = 0; i < count; i++) {
    nodes.push({
      id: i,
      x: Math.random() * 100,
      y: Math.random() * 100,
      size: 1.5 + Math.random() * 2.5,
      delay: Math.random() * 8,
      duration: 12 + Math.random() * 16,
      drift: 8 + Math.random() * 20,
    });
  }
  return nodes;
}

function SacredGeometryBg() {
  // Flower of Life + constellation hybrid — sacred geometry that breathes
  const nodes = useMemo(() => generateNodes(18), []);

  const lines = useMemo(() => {
    const result: { x1: number; y1: number; x2: number; y2: number; delay: number }[] = [];
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 30) {
          result.push({
            x1: nodes[i].x, y1: nodes[i].y,
            x2: nodes[j].x, y2: nodes[j].y,
            delay: Math.random() * 6,
          });
        }
      }
    }
    return result;
  }, [nodes]);

  // Flower of Life circle positions (7 circles)
  const flowerCircles = useMemo(() => {
    const r = 60; // radius of each circle
    const cx = 270, cy = 240; // center
    const circles = [{ cx, cy }]; // center circle
    for (let i = 0; i < 6; i++) {
      const angle = (i * Math.PI) / 3;
      circles.push({
        cx: cx + r * Math.cos(angle),
        cy: cy + r * Math.sin(angle),
      });
    }
    return circles;
  }, []);

  return (
    <div style={{
      position: 'absolute',
      inset: 0,
      overflow: 'hidden',
      pointerEvents: 'none',
      zIndex: 0,
    }}>
      <style>{`
        /* Fonts self-hosted via next/font in layout.tsx */
        @keyframes drift {
          0%, 100% { transform: translate(0, 0); }
          25% { transform: translate(var(--dx), var(--dy)); }
          50% { transform: translate(calc(var(--dx) * -0.5), calc(var(--dy) * 0.7)); }
          75% { transform: translate(calc(var(--dx) * 0.3), calc(var(--dy) * -0.6)); }
        }
        @keyframes pulse-node {
          0%, 100% { opacity: 0.2; transform: scale(1); }
          50% { opacity: 0.6; transform: scale(1.3); }
        }
        @keyframes pulse-line {
          0%, 100% { opacity: 0.04; }
          50% { opacity: 0.12; }
        }
        @keyframes sacred-breathe {
          0%, 100% { opacity: 0.04; transform: scale(1) rotate(0deg); }
          50% { opacity: 0.08; transform: scale(1.02) rotate(0.5deg); }
        }
        @keyframes spin-dome {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        @keyframes pulse-key {
          0%, 100% { opacity: 0.7; }
          50% { opacity: 1; }
        }
        @keyframes amber-pulse {
          0%, 100% { box-shadow: 0 0 30px rgba(200, 168, 78, 0.08); }
          50% { box-shadow: 0 0 50px rgba(200, 168, 78, 0.2), 0 0 80px rgba(200, 168, 78, 0.06); }
        }
        @keyframes emerald-pulse {
          0%, 100% { box-shadow: 0 0 20px rgba(52, 211, 153, 0.06); }
          50% { box-shadow: 0 0 40px rgba(52, 211, 153, 0.15), 0 0 60px rgba(52, 211, 153, 0.04); }
        }
      `}</style>

      {/* Sacred geometry — Flower of Life */}
      <svg width="100%" height="100%" style={{
        position: 'absolute', inset: 0,
        animation: 'sacred-breathe 12s ease-in-out infinite',
      }}>
        <defs>
          <radialGradient id="sacredGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#34d399" stopOpacity="0.06" />
            <stop offset="100%" stopColor="#34d399" stopOpacity="0" />
          </radialGradient>
        </defs>
        {/* Flower of Life circles */}
        {flowerCircles.map((c, i) => (
          <circle
            key={`flower-${i}`}
            cx={c.cx} cy={c.cy} r={60}
            fill="none"
            stroke="#34d399"
            strokeWidth="0.5"
            opacity={0.06}
          />
        ))}
        {/* Outer ring */}
        <circle cx={270} cy={240} r={120} fill="none" stroke="#c8a84e" strokeWidth="0.3" opacity={0.05} />
        <circle cx={270} cy={240} r={180} fill="none" stroke="#c8a84e" strokeWidth="0.3" opacity={0.03} />
        {/* Center glow */}
        <circle cx={270} cy={240} r={90} fill="url(#sacredGlow)" />
        {/* Constellation lines */}
        {lines.map((line, i) => (
          <line
            key={`l${i}`}
            x1={`${line.x1}%`} y1={`${line.y1}%`}
            x2={`${line.x2}%`} y2={`${line.y2}%`}
            stroke="#c8a84e"
            strokeWidth="0.4"
            style={{
              animation: `pulse-line ${10 + line.delay * 2}s ease-in-out ${line.delay}s infinite`,
            }}
          />
        ))}
      </svg>

      {/* Constellation nodes */}
      {nodes.map(node => (
        <div
          key={node.id}
          style={{
            position: 'absolute',
            left: `${node.x}%`,
            top: `${node.y}%`,
            width: `${node.size}px`,
            height: `${node.size}px`,
            borderRadius: '50%',
            background: node.id % 3 === 0 ? '#34d399' : '#c8a84e',
            boxShadow: `0 0 6px ${node.id % 3 === 0 ? 'rgba(52,211,153,0.3)' : 'rgba(200,168,78,0.3)'}`,
            '--dx': `${node.drift}px`,
            '--dy': `${node.drift * 0.7}px`,
            animation: `drift ${node.duration}s ease-in-out ${node.delay}s infinite, pulse-node ${6 + node.delay}s ease-in-out ${node.delay}s infinite`,
          } as React.CSSProperties}
        />
      ))}
    </div>
  );
}


async function safeJson(response: Response): Promise<any> {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    if (response.status >= 500) throw new Error('Server error — please try again');
    throw new Error(text.slice(0, 200) || 'Unexpected response');
  }
}

export function SoverentityFrontend({
  existingIdentity,
  onIdentityUpdate,
  onVaultRestore,
}: SoverentityFrontendProps) {
  const [identity, setIdentity] = useState(existingIdentity || null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [formData, setFormData] = useState({ name: '', email: '' });
  const [unlockPassphrase, setUnlockPassphrase] = useState('');
  const [unlockConfirm, setUnlockConfirm] = useState('');
  const [unlockError, setUnlockError] = useState('');
  const [gateMode, setGateMode] = useState<GateMode>('choose');
  const [pendingRecovery, setPendingRecovery] = useState<{
    seedPhrase: string;
    identity: any;
    shardCount: number;
    threshold: number;
  } | null>(null);
  const [recoveryAcked, setRecoveryAcked] = useState(false);
  const [verificationState, setVerificationState] = useState({
    loading: false,
    error: null as string | null,
    status: existingIdentity?.verification?.status || 'unverified',
  });
  const [verificationCode, setVerificationCode] = useState('');

  // Vault restore state
  const [vaultFile, setVaultFile] = useState<File | null>(null);
  const [vaultHeader, setVaultHeader] = useState<any>(null);
  const [vaultPassphrase, setVaultPassphrase] = useState('');

  // PQ migration state (shown after v1 import)
  const [pendingPqMigration, setPendingPqMigration] = useState<{ fingerprint: string; identity: any } | null>(null);
  const [pqMigrating, setPqMigrating] = useState(false);
  const [hasPqKeys, setHasPqKeys] = useState(false);

  // Export dialog state
  const [showExportDialog, setShowExportDialog] = useState(false);
  const [showKeyExportDialog, setShowKeyExportDialog] = useState(false);
  const [showFullBackupDialog, setShowFullBackupDialog] = useState(false);
  const [fullBackupPassword, setFullBackupPassword] = useState('');
  const [fullBackupConfirm, setFullBackupConfirm] = useState('');
  const [fullBackupLoading, setFullBackupLoading] = useState(false);
  const [fullBackupError, setFullBackupError] = useState<string | null>(null);
  const [showPassphraseDialog, setShowPassphraseDialog] = useState(false);
  const [showClaimUrlDialog, setShowClaimUrlDialog] = useState(false);
  const [claimSlug, setClaimSlug] = useState('');
  const [claimStatus, setClaimStatus] = useState<'idle' | 'checking' | 'claiming' | 'success' | 'taken' | 'error'>('idle');
  const [claimedUrl, setClaimedUrl] = useState('');
  const [newPassphrase, setNewPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [passphraseError, setPassphraseError] = useState('');
  const [passphraseSuccess, setPassphraseSuccess] = useState(false);
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [restoreLoading, setRestoreLoading] = useState(false);
  const [restoreError, setRestoreError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (existingIdentity) {
      setIdentity(existingIdentity);
      setVerificationState(prev => ({
        ...prev,
        status: existingIdentity.verification?.status || 'unverified',
      }));
    }
  }, [existingIdentity]);

  // Check for PQ keys when identity loads
  useEffect(() => {
    const fp = identity?.identity?.fingerprint;
    if (fp) {
      loadPQKeys(fp).then(pq => setHasPqKeys(!!pq));
    } else {
      setHasPqKeys(false);
    }
  }, [identity]);

  // Restore claimed URL from registration service on identity load
  useEffect(() => {
    const fp = identity?.identity?.fingerprint;
    if (fp && !claimedUrl) {
      fetch(`/identity/${fp}`).then(r => r.ok ? r.json() : null).then(data => {
        if (data?.slug) setClaimedUrl(`svrnty.is/${data.slug}`);
      }).catch(() => {});
    }
  }, [identity]);

  const handleSetPassphrase = async () => {
    if (newPassphrase !== confirmPassphrase) {
      setPassphraseError('Passphrases do not match');
      return;
    }
    if (newPassphrase.length < 12) {
      setPassphraseError('Passphrase must be at least 12 characters');
      return;
    }
    try {
      const fp = identity?.identity?.fingerprint;
      if (!fp) { setPassphraseError('No identity found'); return; }
      // Unlock passphrase wraps IndexedDB at rest — NEVER overwrite the PGP key passphrase.
      // Load material first (works for legacy plaintext records), then init session + re-store encrypted.
      const existing = await loadKey(fp);
      if (!existing) { setPassphraseError('No keys found for this identity'); return; }
      const pq = await loadPQKeys(fp);
      await initSessionKey(newPassphrase);
      await storeKey(fp, existing.privateKey, existing.passphrase);
      if (pq) {
        const { storePQKeys } = await import('@/lib/identity/client-store');
        await storePQKeys(fp, pq);
      }
      setPassphraseSuccess(true);
      setPassphraseError('');
      setTimeout(() => { setShowPassphraseDialog(false); setPassphraseSuccess(false); setNewPassphrase(''); setConfirmPassphrase(''); }, 1500);
    } catch { setPassphraseError('Failed to set unlock passphrase'); }
  };

  const handleClaimUrl = async () => {
    const slug = claimSlug.toLowerCase().replace(/[^a-z0-9_-]/g, '');
    if (slug.length < 3) { setClaimStatus('error'); return; }
    setClaimStatus('checking');
    try {
      // Check availability
      const checkRes = await fetch(`/slug/${slug}`); const checkData = await checkRes.json();
      if (checkRes.ok && !checkData.available) {
        // Check if this slug is already ours
        const fp = identity?.identity?.fingerprint;
        if (checkData.fingerprint && checkData.fingerprint === fp) {
          setClaimStatus('success');
          setClaimedUrl(`svrnty.is/${slug}`);
          return;
        }
        setClaimStatus('taken');
        return;
      }
      // Register with satellite
      const fp = identity?.identity?.fingerprint;
      const pk = identity?.identity?.public_key || identity?.identity?.publicKey || '';
      const email = identity?.identity?.email || '';
      const regRes = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, display_name: slug, public_key: pk, fingerprint: fp || '', slug }),
      });
      if (regRes.ok || regRes.status === 409) {
        // Claim the slug
        const claimRes = await fetch(`/slug/${slug}/claim`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ fingerprint: fp }),
        });
        if (claimRes.ok) {
          setClaimStatus('success');
          setClaimedUrl(`svrnty.is/${slug}`);
        } else { setClaimStatus('taken'); }
      } else { setClaimStatus('error'); }
    } catch { setClaimStatus('error'); }
  };

  const handleCreateIdentity = async () => {
    // Unlock passphrase is required — keys must be encrypted at rest.
    if (!unlockPassphrase || unlockPassphrase.length < 12) {
      setUnlockError('Unlock passphrase required (min 12 characters)');
      return;
    }
    if (unlockPassphrase !== unlockConfirm) {
      setUnlockError('Passphrases do not match');
      return;
    }
    setUnlockError('');
    try {
      setLoading(true);
      setError(null);
      const bi = getBrowserIdentity();
      const result = await bi.generateIdentity(formData, { unlockPassphrase });
      // One-time recovery material — must be shown before entering the app.
      setPendingRecovery({
        seedPhrase: result.seedPhrase,
        identity: result.identity,
        shardCount: result.shards?.length ?? 0,
        threshold: result.shards?.[0]?.threshold ?? 3,
      });
      setGateMode('recovery-reveal');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const confirmRecoveryReveal = () => {
    if (!pendingRecovery || !recoveryAcked) return;
    setIdentity(pendingRecovery.identity);
    onIdentityUpdate?.(pendingRecovery.identity);
    setPendingRecovery(null);
    setRecoveryAcked(false);
  };

  const handleVerification = async () => {
    try {
      setVerificationState(prev => ({ ...prev, loading: true, error: null }));
      const response = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: identity.identity.email,
        }),
      });
      const data = await safeJson(response);
      if (!response.ok) throw new Error(data.detail || data.error || 'Failed to send verification email');
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
      const response = await fetch('/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: identity.identity.email,
          otp: verificationCode,
          fingerprint: identity.identity.fingerprint,
          public_key: identity.identity.public_key,
        }),
      });
      const data = await safeJson(response);
      if (!response.ok) throw new Error(data.detail || data.error || 'Code verification failed');
      // Update local identity verification status
      const updatedIdentity = { ...identity };
      updatedIdentity.verification = {
        status: 'verified',
        method: 'email',
        verified_at: new Date().toISOString(),
      };
      setIdentity(updatedIdentity);
      onIdentityUpdate?.(updatedIdentity);
      // Store updated identity in IndexedDB
      try {
        const { storeIdentity } = await import('@/lib/identity/client-store');
        await storeIdentity(identity.identity.fingerprint, updatedIdentity);
      } catch (e) { console.warn('Failed to update IndexedDB:', e); }
      setVerificationState(prev => ({ ...prev, status: 'verified', loading: false }));
    } catch (err) {
      setVerificationState(prev => ({
        ...prev,
        error: err instanceof Error ? err.message : 'Code verification failed',
        loading: false,
      }));
    }
  };


  // --- Vault Restore ---

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setVaultFile(file);
    setRestoreError(null);

    try {
      // JSON-based backups (.json or .svrnty that are JSON inside)
      if (file.name.endsWith('.json') || file.name.endsWith('.svrnty')) {
        const text = await file.text();
        let data: any;
        try { data = JSON.parse(text); } catch { data = null; }

        if (data) {
          const isFullBackupEncrypted = data.type === 'svrnty-full-backup';
          const isKeysOnly = data.type === 'svrnty-keys';
          const isContactsOnly = !!(data.owner_fingerprint && data.contacts && !data.identity);
          const fp = data.identity?.identity?.fingerprint || data.owner_fingerprint || data.fingerprint || data.fingerprint_hint || '';

          let format = 'json-backup';
          if (isFullBackupEncrypted) format = 'json-full-encrypted';
          else if (isKeysOnly) format = 'json-keys-encrypted';

          const displayName = isFullBackupEncrypted
            ? 'Full backup (encrypted — password required)'
            : data.identity?.identity?.name
              || data.identity?.identity?.display_name
              || (isContactsOnly ? `Contacts backup (${data.contacts?.length || 0} contacts)` : '')
              || (isKeysOnly ? 'Key backup (encrypted — password required)' : '')
              || 'Backup';

          setVaultHeader({
            format,
            displayName,
            fingerprintHint: (typeof fp === 'string' ? fp.slice(-8) : '') || '??',
            _jsonData: data,
          });
          setGateMode('restore-verify');
          return;
        }
        // If not valid JSON but .svrnty, fall through to vault binary reader
        if (file.name.endsWith('.json')) {
          setRestoreError('Could not parse JSON file.');
          return;
        }
      }

      // .svrnty vault — read unencrypted header
      const arrayBuffer = await file.arrayBuffer();
      const { readVaultHeader } = await import('@/lib/sync/vault');
      const header = readVaultHeader(arrayBuffer);
      setVaultHeader(header);
      setGateMode('restore-verify');
    } catch (err) {
      setRestoreError(
        err instanceof Error ? err.message : 'Could not read file. Accepts .svrnty or .json backups.'
      );
    }
  };

  const handleVaultRestore = async () => {
    if (!vaultFile) return;

    try {
      setRestoreLoading(true);
      setRestoreError(null);

      // JSON backup path (plain, encrypted keys, or encrypted full backup)
      if (vaultHeader?.format === 'json-backup' || vaultHeader?.format === 'json-keys-encrypted' || vaultHeader?.format === 'json-full-encrypted') {
        const data = vaultHeader._jsonData;
        const { importAll, storeIdentity, storeKey, addContact, setActiveFingerprint, loadIdentity } = await import('@/lib/identity/client-store');

        // Detect format and normalize
        if (data.type === 'svrnty-full-backup') {
          // Encrypted full backup — decrypt first, then import
          if (!vaultPassphrase) {
            setRestoreError('Enter your backup password to decrypt.');
            return;
          }
          const fromBase64 = (b64: string) => {
            const bin = atob(b64);
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            return bytes;
          };
          const enc = new TextEncoder();
          const salt = fromBase64(data.salt);
          const iv = fromBase64(data.iv);
          const encrypted = fromBase64(data.data);
          const keyMaterial = await crypto.subtle.importKey(
            'raw', enc.encode(vaultPassphrase), 'PBKDF2', false, ['deriveKey']
          );
          const derivedKey = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
          );
          const decrypted = new Uint8Array(
            await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, derivedKey, encrypted)
          );
          const backup = JSON.parse(new TextDecoder().decode(decrypted));
          await importAll(backup);

          // PQ migration: check for missing PRIVATE PQ keys (identity may have public PQ keys but backup lacks private)
          if (!backup.pq_keys) {
            const fp = backup.identity?.identity?.fingerprint;
            if (fp) {
              setPendingPqMigration({ fingerprint: fp, identity: backup.identity });
              setGateMode('pq-migrate');
              return;
            }
          }

          setIdentity(backup.identity);
          onIdentityUpdate?.(backup.identity);
        } else if (data.identity?.identity?.fingerprint) {
          // SovereignBackup format (from exportAll) — pass directly
          await importAll(data);

          // PQ migration: check for missing PRIVATE PQ keys
          if (!data.pq_keys) {
            const fp = data.identity?.identity?.fingerprint;
            if (fp) {
              setPendingPqMigration({ fingerprint: fp, identity: data.identity });
              setGateMode('pq-migrate');
              return;
            }
          }

          setIdentity(data.identity);
          onIdentityUpdate?.(data.identity);
        } else if (data.owner_fingerprint && data.contacts) {
          // SecureExportDialog format — contacts only, no identity
          // Import contacts into existing identity or create stub
          const fp = data.owner_fingerprint;
          for (const contact of data.contacts) {
            await addContact(fp, {
              fingerprint: contact.fingerprint || '',
              name: contact.name || '',
              email: contact.email || '',
              public_key: contact.public_key || '',
              trust_level: contact.trust_level || 'unknown',
            });
          }
          await setActiveFingerprint(fp);
          const existingIdentity = await loadIdentity(fp);
          if (existingIdentity) {
            setIdentity(existingIdentity);
            onIdentityUpdate?.(existingIdentity);
          }
        } else if (data.type === 'svrnty-keys' && data.fingerprint) {
          // PrivateKeyExportDialog format — encrypted keys, need passphrase to decrypt
          if (!vaultPassphrase) {
            setRestoreError('This is an encrypted key backup. Enter your password above to decrypt it.');
            return;
          }
          // Decrypt the key data
          const fromBase64 = (b64: string) => {
            const bin = atob(b64);
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            return bytes;
          };
          const enc = new TextEncoder();
          const salt = fromBase64(data.salt);
          const iv = fromBase64(data.iv);
          const encrypted = fromBase64(data.data);
          const keyMaterial = await crypto.subtle.importKey(
            'raw', enc.encode(vaultPassphrase), 'PBKDF2', false, ['deriveKey']
          );
          const derivedKey = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
          );
          const decrypted = new Uint8Array(
            await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, derivedKey, encrypted)
          );
          const keyData = JSON.parse(new TextDecoder().decode(decrypted));
          // Store key in IndexedDB
          const fp = keyData.fingerprint || data.fingerprint;
          if (keyData.privateKey) {
            await storeKey(fp, keyData.privateKey, keyData.passphrase || '');
          }
          await setActiveFingerprint(fp);
          const existingIdentity = await loadIdentity(fp);
          if (existingIdentity) {
            setIdentity(existingIdentity);
            onIdentityUpdate?.(existingIdentity);
          }
        } else if (data.fingerprint && (data.public_key || data.identity)) {
          // Raw identity object — wrap and import
          const fp = data.fingerprint;
          const wrappedIdentity = data.identity ? { identity: data } : { identity: { fingerprint: fp, ...data } };
          await storeIdentity(fp, wrappedIdentity);
          await setActiveFingerprint(fp);
          setIdentity(wrappedIdentity);
          onIdentityUpdate?.(wrappedIdentity);
        } else {
          throw new Error('Unrecognized backup format. Expected a sovereign backup, contacts export, or identity file.');
        }
      } else {
        // .svrnty vault path — needs passphrase
        if (!vaultPassphrase) return;
        const arrayBuffer = await vaultFile.arrayBuffer();
        const { unpackVault } = await import('@/lib/sync/vault');
        const { contents } = await unpackVault(arrayBuffer, vaultPassphrase);
        // Decryption succeeded → everything in `contents` is now AUTHENTICATED
        // by the passphrase (AES-GCM). The safe word (contents.settings.safeWord)
        // may be shown here as a post-decrypt confirmation — the honest place for
        // the recognition ritual, unforgeable because it required the key. (Pre-
        // passphrase display was removed in v3; a cleartext safe word is fakeable.)
        setIdentity(contents.identity);
        onIdentityUpdate?.(contents.identity);
        onVaultRestore?.(contents);
      }
    } catch (err) {
      setRestoreError(
        err instanceof Error
          ? err.message.includes('decrypt')
            ? 'Wrong passphrase. Check your spelling and try again.'
            : err.message
          : 'Failed to restore'
      );
    } finally {
      setRestoreLoading(false);
    }
  };

  const formatFingerprint = (fp: string) => fp?.match(/.{1,4}/g)?.join(' ') || fp;

  // --- Gate: Choose Mode ---
  if (!identity && gateMode === 'choose') {
    return (
      <div style={s.outerWrap}>
        <div style={s.gateOuter}>
          <SacredGeometryBg />
          <div style={s.gatePanel}>
            {/* Hero */}
            <div style={s.hero}>
              <div style={s.shieldIcon}>
                {/* Geodesic dome wireframe with key inside */}
                <svg width="100" height="100" viewBox="-55 -55 110 110" style={{ overflow: 'visible' }}>
                  <defs>
                    <linearGradient id="domeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                      <stop offset="0%" stopColor="#34d399" stopOpacity="0.6" />
                      <stop offset="100%" stopColor="#c8a84e" stopOpacity="0.4" />
                    </linearGradient>
                  </defs>
                  {/* Outer geodesic wireframe — icosahedron projection */}
                  <g style={{ animation: 'spin-dome 20s linear infinite' }}>
                    {/* Pentagon ring top */}
                    <polygon points="0,-48 45.6,-14.8 28.2,38.8 -28.2,38.8 -45.6,-14.8" fill="none" stroke="url(#domeGrad)" strokeWidth="0.6" opacity="0.5" />
                    {/* Pentagon ring bottom (rotated) */}
                    <polygon points="0,48 -45.6,14.8 -28.2,-38.8 28.2,-38.8 45.6,14.8" fill="none" stroke="url(#domeGrad)" strokeWidth="0.6" opacity="0.3" />
                    {/* Connecting triangles */}
                    <line x1="0" y1="-48" x2="45.6" y2="14.8" stroke="#34d399" strokeWidth="0.4" opacity="0.3" />
                    <line x1="0" y1="-48" x2="-45.6" y2="14.8" stroke="#34d399" strokeWidth="0.4" opacity="0.3" />
                    <line x1="45.6" y1="-14.8" x2="0" y2="48" stroke="#34d399" strokeWidth="0.4" opacity="0.25" />
                    <line x1="-45.6" y1="-14.8" x2="0" y2="48" stroke="#34d399" strokeWidth="0.4" opacity="0.25" />
                    <line x1="28.2" y1="38.8" x2="-28.2" y2="-38.8" stroke="#c8a84e" strokeWidth="0.4" opacity="0.2" />
                    <line x1="-28.2" y1="38.8" x2="28.2" y2="-38.8" stroke="#c8a84e" strokeWidth="0.4" opacity="0.2" />
                    {/* Inner triangulation */}
                    <line x1="45.6" y1="-14.8" x2="-28.2" y2="38.8" stroke="#34d399" strokeWidth="0.3" opacity="0.15" />
                    <line x1="-45.6" y1="-14.8" x2="28.2" y2="38.8" stroke="#34d399" strokeWidth="0.3" opacity="0.15" />
                    <line x1="28.2" y1="38.8" x2="45.6" y2="14.8" stroke="#c8a84e" strokeWidth="0.3" opacity="0.15" />
                    <line x1="-28.2" y1="38.8" x2="-45.6" y2="14.8" stroke="#c8a84e" strokeWidth="0.3" opacity="0.15" />
                  </g>
                  {/* Key at center — doesn't rotate */}
                  <g opacity="0.9" style={{ animation: 'pulse-key 4s ease-in-out infinite' }}>
                    <svg x="-12" y="-16" width="24" height="32" viewBox="0 0 24 32" fill="none" stroke="#c8a84e" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="9" r="6" />
                      <line x1="12" y1="15" x2="12" y2="28" />
                      <line x1="12" y1="22" x2="16" y2="22" />
                      <line x1="12" y1="26" x2="15" y2="26" />
                    </svg>
                  </g>
                  {/* Glow */}
                  <circle cx="0" cy="0" r="50" fill="none" stroke="#34d399" strokeWidth="0.3" opacity="0.08" style={{ animation: 'pulse-node 6s ease-in-out infinite' }} />
                </svg>
              </div>
              <h1 style={s.gateTitle}>svrnty</h1>
              <p style={s.gateSub}>
                Your identity. Your trust. Your sovereignty.
              </p>
            </div>

            {/* Two Doors */}
            <div style={s.doorContainer}>
              <button
                onClick={() => setGateMode('forge')}
                style={s.doorBtn}
                onMouseEnter={e => {
                  const el = e.currentTarget;
                  el.style.borderColor = 'rgba(200, 168, 78, 0.4)';
                  el.style.background = 'rgba(200, 168, 78, 0.08)';
                }}
                onMouseLeave={e => {
                  const el = e.currentTarget;
                  el.style.borderColor = 'rgba(180, 160, 100, 0.15)';
                  el.style.background = 'rgba(15, 15, 25, 0.6)';
                }}
              >
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#c8a84e" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ marginBottom: '12px' }}>
                  <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
                </svg>
                <span style={s.doorTitle}>Begin anew.</span>
                <span style={s.doorDesc}>
                  Generate a new cryptographic identity.
                  Your keys never leave your device.
                </span>
              </button>

              <button
                onClick={() => setGateMode('restore')}
                style={s.doorBtn}
                onMouseEnter={e => {
                  const el = e.currentTarget;
                  el.style.borderColor = 'rgba(78, 205, 196, 0.4)';
                  el.style.background = 'rgba(78, 205, 196, 0.06)';
                }}
                onMouseLeave={e => {
                  const el = e.currentTarget;
                  el.style.borderColor = 'rgba(180, 160, 100, 0.15)';
                  el.style.background = 'rgba(15, 15, 25, 0.6)';
                }}
              >
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#4ecdc4" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ marginBottom: '12px' }}>
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
                <span style={{ ...s.doorTitle, color: '#4ecdc4' }}>Open your vault.</span>
                <span style={s.doorDesc}>
                  Restore your identity from a vault file.
                  Pick up where you left off.
                </span>
              </button>
            </div>

            <p style={s.footer}>
              ED25519 + ML-DSA-87 signing. Curve25519 + ML-KEM-1024 encryption.
              <br />Post-quantum. Zero-knowledge. Sovereign.
            </p>
          </div>
        </div>
      </div>
    );
  }

  // --- Gate: Forge Identity ---
  if (!identity && gateMode === 'forge') {
    return (
      <div style={s.outerWrap}>
        <div style={s.createPanel}>
          {/* Back button */}
          <button onClick={() => setGateMode('choose')} style={s.backBtn}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M19 12H5M12 19l-7-7 7-7" />
            </svg>
            Back
          </button>

          {/* Hero */}
          <div style={s.hero}>
            <div style={s.keyIcon}>
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#c8a84e" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
              </svg>
            </div>
            <h2 style={s.heroTitle}>Begin anew.</h2>
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

          <div style={s.field}>
            <label style={s.label}>UNLOCK PASSPHRASE (required)</label>
            <input
              type="password"
              placeholder="Encrypts your keys at rest"
              value={unlockPassphrase}
              onChange={e => { setUnlockPassphrase(e.target.value); setUnlockError(''); }}
              style={s.input}
            />
            <input
              type="password"
              placeholder="Confirm passphrase"
              value={unlockConfirm}
              onChange={e => { setUnlockConfirm(e.target.value); setUnlockError(''); }}
              style={{ ...s.input, marginTop: '8px' }}
            />
            {unlockError && <p style={{ ...s.hint, color: '#ff6b6b' }}>{unlockError}</p>}
            <p style={s.hint}>Required. Protects private keys in this browser. Min 12 chars. This is NOT emailed — write it down.</p>
          </div>

          <button
            onClick={handleCreateIdentity}
            disabled={loading || !formData.name || !formData.email || unlockPassphrase.length < 12 || unlockPassphrase !== unlockConfirm}
            style={{
              ...s.primaryBtn,
              opacity: loading || !formData.name || !formData.email || unlockPassphrase.length < 12 || unlockPassphrase !== unlockConfirm ? 0.5 : 1,
            }}
          >
            {loading ? (
              <span style={s.btnInner}>
                <Spinner /> Generating keys...
              </span>
            ) : (
              <span style={s.btnInner}>Begin anew.</span>
            )}
          </button>

          <p style={s.footer}>
            ED25519 + ML-DSA-87 signing. Curve25519 + ML-KEM-1024 encryption.
            <br />Your keys. Your data. Your sovereignty.
          </p>
        </div>
      </div>
    );
  }

  // --- Gate: one-time recovery reveal (seed phrase) ---
  if (!identity && gateMode === 'recovery-reveal' && pendingRecovery) {
    return (
      <div style={s.outerWrap}>
        <div style={s.createCard}>
          <div style={s.keyIcon}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#c8a84e" strokeWidth="1.5">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <h1 style={s.createTitle}>Write this down.</h1>
          <p style={s.createSub}>
            This recovery phrase reconstructs your master secret. It is shown once.
            It is NOT your vault passphrase — the passphrase unlocks this device,
            the recovery phrase rebuilds your identity if you lose the device.
            Social-recovery shards ({pendingRecovery.threshold}-of-{pendingRecovery.shardCount}) are stored locally for the tear ceremony.
          </p>
          <div style={{
            background: 'rgba(6, 10, 8, 0.9)',
            border: '1px solid rgba(200, 168, 78, 0.25)',
            borderRadius: '10px',
            padding: '16px',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '13px',
            color: '#e8e4d9',
            wordBreak: 'break-all' as const,
            lineHeight: 1.7,
            marginBottom: '16px',
            userSelect: 'all' as const,
          }}>
            {pendingRecovery.seedPhrase}
          </div>
          <label style={{
            display: 'flex',
            gap: '10px',
            alignItems: 'flex-start',
            fontFamily: "'Space Grotesk', sans-serif",
            fontSize: '12px',
            color: 'rgba(255,255,255,0.55)',
            marginBottom: '16px',
            cursor: 'pointer',
          }}>
            <input
              type="checkbox"
              checked={recoveryAcked}
              onChange={e => setRecoveryAcked(e.target.checked)}
              style={{ marginTop: '2px' }}
            />
            <span>I have written this down offline. I understand there is no email recovery.</span>
          </label>
          <button
            onClick={confirmRecoveryReveal}
            disabled={!recoveryAcked}
            style={{
              ...s.primaryBtn,
              opacity: recoveryAcked ? 1 : 0.45,
            }}
          >
            <span style={s.btnInner}>I have it. Continue.</span>
          </button>
        </div>
      </div>
    );
  }

  // --- Gate: Restore Vault (file selection) ---
  if (!identity && gateMode === 'restore') {
    return (
      <div style={s.outerWrap}>
        <div style={s.createPanel}>
          {/* Back button */}
          <button onClick={() => setGateMode('choose')} style={s.backBtn}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M19 12H5M12 19l-7-7 7-7" />
            </svg>
            Back
          </button>

          {/* Hero */}
          <div style={s.hero}>
            <div style={{ ...s.keyIcon, borderColor: 'rgba(78, 205, 196, 0.2)', background: 'rgba(78, 205, 196, 0.08)' }}>
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#4ecdc4" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
            </div>
            <h2 style={s.heroTitle}>Open Your Vault</h2>
            <p style={s.heroSub}>
              Upload your .svrnty vault or .json backup to restore your identity,
              contacts, and trust network on this device.
            </p>
          </div>

          {restoreError && <div style={s.error}>{restoreError}</div>}

          {/* File Upload */}
          <input
            ref={fileInputRef}
            type="file"
            accept=".svrnty,.json"
            onChange={handleFileSelect}
            style={{ display: 'none' }}
          />

          <button
            onClick={() => fileInputRef.current?.click()}
            style={s.uploadBtn}
          >
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="17 8 12 3 7 8" />
              <line x1="12" y1="3" x2="12" y2="15" />
            </svg>
            <span>Choose file (.svrnty or .json)</span>
          </button>

          {vaultFile && (
            <div style={s.fileInfo}>
              <span style={s.fileName}>{vaultFile.name}</span>
              <span style={s.fileSize}>{(vaultFile.size / 1024).toFixed(1)} KB</span>
            </div>
          )}

          <p style={s.footer}>
            Your vault is encrypted with AES-256-GCM.
            <br />The file never leaves this device unencrypted.
          </p>
        </div>
      </div>
    );
  }

  // --- Gate: Restore Vault (verify safe word + enter passphrase) ---
  if (!identity && gateMode === 'restore-verify' && vaultHeader) {
    return (
      <div style={s.outerWrap}>
        <div style={s.createPanel}>
          {/* Back button */}
          <button onClick={() => { setGateMode('restore'); setVaultHeader(null); }} style={s.backBtn}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M19 12H5M12 19l-7-7 7-7" />
            </svg>
            Back
          </button>

          {/* Vault Identity */}
          <div style={s.hero}>
            <div style={{ ...s.keyIcon, borderColor: 'rgba(78, 205, 196, 0.2)', background: 'rgba(78, 205, 196, 0.08)' }}>
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#4ecdc4" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <h2 style={s.heroTitle}>Open Your Vault</h2>
          </div>

          {/* Vault Info Card */}
          {/* A v3 vault reveals nothing before decryption. Its owner, contacts,
              and safe word live in the ENCRYPTED body and are authenticated by
              the passphrase (GCM). A cleartext pre-passphrase preview would be
              forgeable — an attacker could show a plausible name/safe word to
              phish "yes, that's mine" — so we show none. Recognition of TYPE,
              not IDENTITY. (Legacy v2 vaults are refused at file-select.) */}
          {vaultHeader?.format === 'svrnty-vault' && (
            <div style={s.vaultInfoCard}>
              <div style={s.vaultInfoRow}>
                <span style={s.vaultInfoLabel}>FILE</span>
                <span style={s.vaultInfoValue}>Encrypted svrnty vault · v{vaultHeader.version}</span>
              </div>
              <p style={s.safeWordHint}>
                This vault is sealed. Your name, contacts, and safe word appear
                only after you enter the correct passphrase — so nothing shown
                here can be forged. Enter your passphrase to open it.
              </p>
            </div>
          )}

          {restoreError && <div style={s.error}>{restoreError}</div>}

          {/* JSON backup — show passphrase for encrypted keys, skip for plaintext */}
          {vaultHeader?.format === 'json-backup' ? (
            <div style={s.trustWarning}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#c8a84e" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0, marginTop: '1px' }}>
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                <line x1="12" y1="9" x2="12" y2="13" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>
              <div>
                <strong style={{ color: '#c8a84e', fontSize: '12px' }}>JSON backup detected — not encrypted.</strong>
                <p style={{ margin: '4px 0 0', fontSize: '11px', color: '#8a8070', lineHeight: '1.5' }}>
                  This file contains your identity data in plaintext. It will be imported directly into your browser's local storage.
                </p>
              </div>
            </div>
          ) : (vaultHeader?.format === 'json-keys-encrypted' || vaultHeader?.format === 'json-full-encrypted') ? (
            <>
            <div style={s.trustWarning}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#c8a84e" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0, marginTop: '1px' }}>
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                <line x1="12" y1="9" x2="12" y2="13" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>
              <div>
                <strong style={{ color: '#c8a84e', fontSize: '12px' }}>Encrypted key backup detected.</strong>
                <p style={{ margin: '4px 0 0', fontSize: '11px', color: '#8a8070', lineHeight: '1.5' }}>
                  Enter the password you used when exporting to decrypt your private keys.
                </p>
              </div>
            </div>
            <div style={s.field}>
              <label style={s.label}>DECRYPTION PASSWORD</label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showPassphrase ? 'text' : 'password'}
                  placeholder="Enter your export password"
                  value={vaultPassphrase}
                  onChange={e => setVaultPassphrase(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && vaultPassphrase) handleVaultRestore(); }}
                  style={s.input}
                  autoFocus
                />
                <button
                  onClick={() => setShowPassphrase(!showPassphrase)}
                  style={s.eyeBtn}
                >
                  {showPassphrase ? '🙈' : '👁'}
                </button>
              </div>
            </div>
            </>
          ) : (
          <>
          {/* Trust Warning */}
          <div style={s.trustWarning}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#c8a84e" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0, marginTop: '1px' }}>
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
            <div>
              <strong style={{ color: '#c8a84e', fontSize: '12px' }}>Only enter your passphrase on a device you trust.</strong>
              <p style={{ margin: '4px 0 0', fontSize: '11px', color: '#8a8070', lineHeight: '1.5' }}>
                Your passphrase decrypts your private keys, trust network, and contacts.
                Never enter it on a shared, public, or untrusted device.
              </p>
            </div>
          </div>

          {/* Passphrase Input */}
          <div style={s.field}>
            <label style={s.label}>VAULT PASSPHRASE</label>
            <div style={{ position: 'relative' }}>
              <input
                type={showPassphrase ? 'text' : 'password'}
                placeholder="Enter your vault passphrase"
                value={vaultPassphrase}
                onChange={e => setVaultPassphrase(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && vaultPassphrase) handleVaultRestore(); }}
                style={s.input}
                autoFocus
              />
              <button
                onClick={() => setShowPassphrase(!showPassphrase)}
                style={s.eyeBtn}
                tabIndex={-1}
              >
                {showPassphrase ? (
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#8a8070" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                    <line x1="1" y1="1" x2="23" y2="23" />
                  </svg>
                ) : (
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#8a8070" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                    <circle cx="12" cy="12" r="3" />
                  </svg>
                )}
              </button>
            </div>
          </div>

          <button
            onClick={handleVaultRestore}
            disabled={restoreLoading || !vaultPassphrase}
            style={{
              ...s.restoreBtn,
              opacity: restoreLoading || !vaultPassphrase ? 0.5 : 1,
            }}
          >
            {restoreLoading ? (
              <span style={s.btnInner}>
                <Spinner /> Decrypting vault...
              </span>
            ) : (
              <span style={s.btnInner}>Unlock Vault</span>
            )}
          </button>

          <p style={s.footer}>
            Decryption happens locally in your browser.
            <br />Your passphrase never leaves this device.
          </p>
          </>
          )}

          {/* JSON restore button (no passphrase needed) */}
          {vaultHeader?.format === 'json-backup' && (
            <>
            <button
              onClick={handleVaultRestore}
              disabled={restoreLoading}
              style={{
                ...s.restoreBtn,
                opacity: restoreLoading ? 0.5 : 1,
              }}
            >
              {restoreLoading ? (
                <span style={s.btnInner}>
                  <Spinner /> Restoring...
                </span>
              ) : (
                <span style={s.btnInner}>Restore from Backup</span>
              )}
            </button>

            <p style={s.footer}>
              Your backup will be imported into this browser's local storage.
            </p>
            </>
          )}
        </div>
      </div>
    );
  }

  // --- Gate: PQ Migration (shown after v1 import) ---
  if (gateMode === 'pq-migrate' && pendingPqMigration) {
    const handlePqUpgrade = async () => {
      setPqMigrating(true);
      try {
        const { generatePQKeypairBundle, serializeKeypairBundle } = await import('@/lib/crypto/pq');
        const { storePQKeys } = await import('@/lib/identity/client-store');
        const pqBundle = generatePQKeypairBundle();
        const serialized = serializeKeypairBundle(pqBundle);
        await storePQKeys(pendingPqMigration.fingerprint, serialized);
        console.log('[svrnty] PQ migration: generated ML-DSA-87 + ML-KEM-1024 for', pendingPqMigration.fingerprint.slice(-8));
        setHasPqKeys(true);
        setIdentity(pendingPqMigration.identity);
        onIdentityUpdate?.(pendingPqMigration.identity);
        setPendingPqMigration(null);
        setGateMode('choose');
      } catch (err) {
        console.error('[svrnty] PQ migration failed:', err);
        setError('PQ key generation failed. You can try again later from settings.');
        setIdentity(pendingPqMigration.identity);
        onIdentityUpdate?.(pendingPqMigration.identity);
        setPendingPqMigration(null);
        setGateMode('choose');
      } finally {
        setPqMigrating(false);
      }
    };

    const handlePqSkip = () => {
      setIdentity(pendingPqMigration.identity);
      onIdentityUpdate?.(pendingPqMigration.identity);
      setPendingPqMigration(null);
      setGateMode('choose');
    };

    return (
      <div style={s.outerWrap}>
        <div style={s.createPanel}>
          <h2 style={s.title}>Identity Restored</h2>
          <p style={{ ...s.subtitle, marginBottom: 16 }}>
            Your backup does not include post-quantum private keys.
          </p>

          <div style={{
            background: 'rgba(255, 200, 50, 0.08)',
            border: '1px solid rgba(255, 200, 50, 0.25)',
            borderRadius: 8,
            padding: 16,
            marginBottom: 20,
            fontSize: 14,
            lineHeight: 1.6,
            color: 'rgba(255,255,255,0.85)',
          }}>
            <strong style={{ color: 'rgba(255, 200, 50, 0.9)' }}>What happened?</strong><br />
            Your identity has post-quantum public keys (ML-DSA-87, ML-KEM-1024), but the
            private keys weren't included in this backup. Without them, post-quantum
            signing and encryption won't work.
            <br /><br />
            <strong>Regenerate:</strong> New PQ keypairs are generated locally in your browser.
            Your Ed25519 identity and fingerprint stay the same. The old PQ public keys
            will be replaced — anyone who cached them will need your updated keys.
            <br /><br />
            <strong>Skip:</strong> Your identity works fine with Ed25519 only.
            You can regenerate PQ keys later from settings.
          </div>

          <button
            onClick={handlePqUpgrade}
            disabled={pqMigrating}
            style={{
              ...s.restoreBtn,
              opacity: pqMigrating ? 0.5 : 1,
              marginBottom: 10,
            }}
          >
            {pqMigrating ? (
              <span style={s.btnInner}><Spinner /> Generating keys...</span>
            ) : (
              <span style={s.btnInner}>Upgrade to Post-Quantum</span>
            )}
          </button>

          <button
            onClick={handlePqSkip}
            disabled={pqMigrating}
            style={{
              ...s.restoreBtn,
              background: 'transparent',
              border: '1px solid rgba(255,255,255,0.15)',
              opacity: pqMigrating ? 0.5 : 1,
            }}
          >
            <span style={s.btnInner}>Skip for now</span>
          </button>

          <p style={s.footer}>
            You can upgrade later from your identity settings.
          </p>
        </div>
      </div>
    );
  }

  // --- Identity View ---
  const isVerified = verificationState.status === 'verified' || verificationState.status === 'skipped' || identity?.verification?.status === 'verified';

  if (!identity) return null;

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
            {hasPqKeys && <span style={s.tag}>ML-DSA-87</span>}
            <span style={s.tag}>Curve25519</span>
            {hasPqKeys && <span style={s.tag}>ML-KEM-1024</span>}
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
                  Optional: verify your email for account recovery. Your identity works without this.
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
                <button
                  onClick={() => setVerificationState(prev => ({ ...prev, status: 'skipped' }))}
                  style={{
                    ...s.outlineBtn,
                    marginTop: '8px',
                    opacity: 0.7,
                    fontSize: '12px',
                  }}
                >
                  <span style={s.btnInner}>Skip for now</span>
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

        {/* Export / Backup Section */}
        {identity && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '16px' }}>
            <button
              onClick={() => { setShowFullBackupDialog(true); setFullBackupPassword(''); setFullBackupConfirm(''); setFullBackupError(null); }}
              style={{
                ...s.outlineBtn,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                background: 'rgba(106, 154, 106, 0.1)',
                borderColor: '#6a9a6a',
              }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#6a9a6a" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              Full Backup (Encrypted)
            </button>
            {showFullBackupDialog && (
              <div style={{ background: 'rgba(15,15,25,0.95)', border: '1px solid rgba(180,160,100,0.2)', borderRadius: '8px', padding: '16px', marginTop: '8px' }}>
                <p style={{ color: '#c8a84e', fontSize: '12px', fontWeight: 600, marginBottom: '8px' }}>
                  🔒 Encrypt your backup with a password
                </p>
                <p style={{ color: '#8a8070', fontSize: '11px', marginBottom: '12px', lineHeight: '1.5' }}>
                  Your private keys will be encrypted with AES-256-GCM. Without this password, the backup cannot be restored.
                </p>
                <input
                  type="password"
                  placeholder="Password (min 8 characters)"
                  value={fullBackupPassword}
                  onChange={e => setFullBackupPassword(e.target.value)}
                  style={{ ...s.input, marginBottom: '8px' }}
                  autoFocus
                />
                <input
                  type="password"
                  placeholder="Confirm password"
                  value={fullBackupConfirm}
                  onChange={e => setFullBackupConfirm(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && fullBackupPassword.length >= 8 && fullBackupPassword === fullBackupConfirm) document.getElementById('fullBackupBtn')?.click(); }}
                  style={s.input}
                />
                {fullBackupConfirm && fullBackupPassword !== fullBackupConfirm && (
                  <p style={{ color: '#c85a4e', fontSize: '11px', marginTop: '4px' }}>Passwords do not match</p>
                )}
                {fullBackupError && (
                  <p style={{ color: '#c85a4e', fontSize: '11px', marginTop: '4px' }}>{fullBackupError}</p>
                )}
                <div style={{ display: 'flex', gap: '8px', marginTop: '12px' }}>
                  <button
                    onClick={() => setShowFullBackupDialog(false)}
                    style={{ ...s.outlineBtn, flex: 1, fontSize: '12px' }}
                  >Cancel</button>
                  <button
                    id="fullBackupBtn"
                    disabled={fullBackupLoading || fullBackupPassword.length < 8 || fullBackupPassword !== fullBackupConfirm}
                    onClick={async () => {
                      try {
                        setFullBackupLoading(true);
                        setFullBackupError(null);
                        const { exportAll } = await import('@/lib/identity/client-store');
                        const fp = identity.identity?.fingerprint;
                        if (!fp) return;
                        const backup = await exportAll(fp, true);
                        const json = JSON.stringify(backup);

                        // Encrypt with AES-256-GCM
                        const enc = new TextEncoder();
                        const salt = crypto.getRandomValues(new Uint8Array(16));
                        const iv = crypto.getRandomValues(new Uint8Array(12));
                        const keyMaterial = await crypto.subtle.importKey(
                          'raw', enc.encode(fullBackupPassword), 'PBKDF2', false, ['deriveKey']
                        );
                        const derivedKey = await crypto.subtle.deriveKey(
                          { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
                          keyMaterial,
                          { name: 'AES-GCM', length: 256 },
                          false,
                          ['encrypt']
                        );
                        const encrypted = new Uint8Array(
                          await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, derivedKey, enc.encode(json))
                        );
                        const toB64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
                        const result = JSON.stringify({
                          type: 'svrnty-full-backup',
                          version: '1.0',
                          algorithm: 'AES-256-GCM',
                          kdf: 'PBKDF2-SHA256-100k',
                          salt: toB64(salt),
                          iv: toB64(iv),
                          data: toB64(encrypted),
                          fingerprint_hint: fp.slice(-8),
                          exported_at: new Date().toISOString(),
                        }, null, 2);

                        const blob = new Blob([result], { type: 'application/json' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `svrnty-backup-${new Date().toISOString().split('T')[0]}.svrnty`;
                        document.body.appendChild(a);
                        a.click();
                        a.remove();
                        URL.revokeObjectURL(url);
                        setShowFullBackupDialog(false);
                      } catch (err) {
                        setFullBackupError(err instanceof Error ? err.message : 'Backup failed');
                      } finally {
                        setFullBackupLoading(false);
                      }
                    }}
                    style={{
                      ...s.primaryBtn,
                      flex: 1,
                      fontSize: '12px',
                      opacity: (fullBackupLoading || fullBackupPassword.length < 8 || fullBackupPassword !== fullBackupConfirm) ? 0.5 : 1,
                    }}
                  >
                    {fullBackupLoading ? 'Encrypting...' : '🔒 Download Encrypted Backup'}
                  </button>
                </div>
              </div>
            )}
            <div style={{ display: 'flex', gap: '10px' }}>
              <button
                onClick={() => setShowKeyExportDialog(true)}
                style={{
                  ...s.outlineBtn,
                  flex: 1,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                }}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
                </svg>
                Download Keys
              </button>
              <button
                onClick={() => setShowExportDialog(true)}
                style={{
                  ...s.outlineBtn,
                  flex: 1,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                }}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                  <polyline points="7 10 12 15 17 10" />
                  <line x1="12" y1="15" x2="12" y2="3" />
                </svg>
                Export Contacts
              </button>
            </div>
          </div>
        )}

        {/* Set Passphrase button */}
        {identity && (
          <div style={{ display: 'flex', justifyContent: 'center', marginTop: '12px' }}>
            <button
              onClick={() => setShowPassphraseDialog(true)}
              style={{
                background: 'none',
                border: '1px solid rgba(52, 211, 153, 0.15)',
                borderRadius: '8px',
                padding: '10px 20px',
                color: 'rgba(52, 211, 153, 0.6)',
                fontSize: '11px',
                fontFamily: "'Space Grotesk', sans-serif",
                letterSpacing: '1px',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
              Set Passphrase
            </button>
            {claimedUrl ? (
              <span style={{
                color: 'rgba(200, 168, 78, 0.7)',
                fontSize: '12px',
                fontFamily: "'Space Grotesk', sans-serif",
                padding: '10px 16px',
              }}>
                {claimedUrl}
              </span>
            ) : (
              <button
                onClick={() => { setShowClaimUrlDialog(true); setClaimStatus('idle'); setClaimSlug(''); }}
                style={{
                  background: 'rgba(200, 168, 78, 0.08)',
                  border: '1px solid rgba(200, 168, 78, 0.25)',
                  borderRadius: '10px',
                  padding: '10px 16px',
                  color: '#c8a84e',
                  fontSize: '13px',
                  fontFamily: "'Space Grotesk', sans-serif",
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                }}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
                  <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
                </svg>
                Claim URL
              </button>
            )}
          </div>
        )}

        {/* Passphrase Dialog */}
        {showPassphraseDialog && (
          <div style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.8)',
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            zIndex: 50,
          }} onClick={() => setShowPassphraseDialog(false)}>
            <div style={{
              background: 'rgba(10, 14, 12, 0.98)',
              border: '1px solid rgba(52, 211, 153, 0.15)',
              borderRadius: '16px',
              padding: '32px',
              maxWidth: '380px',
              width: '100%',
              margin: '20px',
            }} onClick={e => e.stopPropagation()}>
              <h3 style={{
                fontFamily: "'Cormorant Garamond', serif",
                fontSize: '20px',
                color: '#e8e4d9',
                marginBottom: '20px',
                textAlign: 'center' as const,
              }}>
                {passphraseSuccess ? 'Passphrase Set' : 'Set Passphrase'}
              </h3>
              {passphraseSuccess ? (
                <p style={{ textAlign: 'center' as const, color: '#34d399', fontFamily: "'Space Grotesk', sans-serif", fontSize: '13px' }}>
                  Your identity is now protected.
                </p>
              ) : (
                <>
                  <input
                    type="password"
                    placeholder="New passphrase"
                    value={newPassphrase}
                    onChange={e => { setNewPassphrase(e.target.value); setPassphraseError(''); }}
                    autoFocus
                    style={{
                      width: '100%',
                      background: 'rgba(6, 10, 8, 0.8)',
                      border: '1px solid rgba(52, 211, 153, 0.15)',
                      borderRadius: '8px',
                      padding: '12px 14px',
                      color: '#e8e4d9',
                      fontSize: '14px',
                      fontFamily: "'Space Grotesk', sans-serif",
                      outline: 'none',
                      marginBottom: '12px',
                      boxSizing: 'border-box' as const,
                    }}
                  />
                  <input
                    type="password"
                    placeholder="Confirm passphrase"
                    value={confirmPassphrase}
                    onChange={e => { setConfirmPassphrase(e.target.value); setPassphraseError(''); }}
                    style={{
                      width: '100%',
                      background: 'rgba(6, 10, 8, 0.8)',
                      border: '1px solid rgba(52, 211, 153, 0.15)',
                      borderRadius: '8px',
                      padding: '12px 14px',
                      color: '#e8e4d9',
                      fontSize: '14px',
                      fontFamily: "'Space Grotesk', sans-serif",
                      outline: 'none',
                      marginBottom: '8px',
                      boxSizing: 'border-box' as const,
                    }}
                  />
                  {passphraseError && (
                    <p style={{ color: '#ef4444', fontSize: '12px', fontFamily: "'Space Grotesk', sans-serif", marginBottom: '8px' }}>{passphraseError}</p>
                  )}
                  <button
                    onClick={handleSetPassphrase}
                    disabled={!newPassphrase || !confirmPassphrase}
                    style={{
                      width: '100%',
                      background: 'rgba(52, 211, 153, 0.12)',
                      border: '1px solid rgba(52, 211, 153, 0.3)',
                      borderRadius: '8px',
                      padding: '12px',
                      color: '#34d399',
                      fontSize: '12px',
                      fontFamily: "'Space Grotesk', sans-serif",
                      letterSpacing: '1px',
                      cursor: 'pointer',
                      marginTop: '8px',
                    }}
                  >
                    SET PASSPHRASE
                  </button>
                </>
              )}
            </div>
          </div>
        )}

        {/* Claim URL Dialog */}
        {showClaimUrlDialog && (
          <div style={{
            position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.8)',
            display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 50,
          }} onClick={() => setShowClaimUrlDialog(false)}>
            <div style={{
              background: 'rgba(10, 14, 12, 0.98)', border: '1px solid rgba(200, 168, 78, 0.15)',
              borderRadius: '16px', padding: '32px', maxWidth: '380px', width: '100%', margin: '20px',
            }} onClick={e => e.stopPropagation()}>
              <h3 style={{
                fontFamily: "'Cormorant Garamond', serif", fontSize: '20px',
                color: '#e8e4d9', marginBottom: '8px', textAlign: 'center' as const,
              }}>
                {claimStatus === 'success' ? 'URL Claimed' : 'Claim Your URL'}
              </h3>
              {claimStatus === 'success' ? (
                <div style={{ textAlign: 'center' as const }}>
                  <p style={{ color: '#34d399', fontFamily: "'Space Grotesk', sans-serif", fontSize: '13px', marginBottom: '12px' }}>
                    Your identity is now at:
                  </p>
                  <p style={{ color: '#c8a84e', fontFamily: "'Space Grotesk', sans-serif", fontSize: '16px', fontWeight: 600 }}>
                    {claimedUrl}
                  </p>
                </div>
              ) : (
                <>
                  <p style={{ color: 'rgba(232,228,217,0.5)', fontFamily: "'Space Grotesk', sans-serif", fontSize: '12px', marginBottom: '16px', textAlign: 'center' as const }}>
                    Choose a URL for your public profile
                  </p>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px', marginBottom: '8px' }}>
                    <span style={{ color: 'rgba(232,228,217,0.4)', fontFamily: "'Space Grotesk', sans-serif", fontSize: '14px', whiteSpace: 'nowrap' as const }}>svrnty.is/</span>
                    <input
                      type="text"
                      placeholder="yourname"
                      value={claimSlug}
                      onChange={e => { setClaimSlug(e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, '')); setClaimStatus('idle'); }}
                      style={{
                        flex: 1, background: 'rgba(6, 10, 8, 0.8)', border: '1px solid rgba(200, 168, 78, 0.15)',
                        borderRadius: '8px', padding: '12px 14px', color: '#e8e4d9', fontSize: '14px',
                        fontFamily: "'Space Grotesk', sans-serif", outline: 'none', boxSizing: 'border-box' as const,
                      }}
                    />
                  </div>
                  {claimStatus === 'taken' && (
                    <p style={{ color: '#ef4444', fontSize: '12px', fontFamily: "'Space Grotesk', sans-serif", marginBottom: '8px' }}>This URL is already claimed</p>
                  )}
                  {claimStatus === 'error' && (
                    <p style={{ color: '#ef4444', fontSize: '12px', fontFamily: "'Space Grotesk', sans-serif", marginBottom: '8px' }}>Must be at least 3 characters (a-z, 0-9, -, _)</p>
                  )}
                  <button
                    onClick={handleClaimUrl}
                    disabled={claimSlug.length < 3 || claimStatus === 'checking' || claimStatus === 'claiming'}
                    style={{
                      width: '100%', background: 'rgba(200, 168, 78, 0.12)', border: '1px solid rgba(200, 168, 78, 0.3)',
                      borderRadius: '8px', padding: '12px', color: '#c8a84e', fontSize: '12px',
                      fontFamily: "'Space Grotesk', sans-serif", letterSpacing: '1px', cursor: 'pointer', marginTop: '8px',
                    }}
                  >
                    {claimStatus === 'checking' ? 'CHECKING...' : claimStatus === 'claiming' ? 'CLAIMING...' : 'CLAIM URL'}
                  </button>
                </>
              )}
            </div>
          </div>
        )}

        {/* Export Dialogs */}
        <SecureExportDialog
          open={showExportDialog}
          onClose={() => setShowExportDialog(false)}
          identityFingerprint={identity?.identity?.fingerprint || ''}
        />
        <PrivateKeyExportDialog
          open={showKeyExportDialog}
          onClose={() => setShowKeyExportDialog(false)}
          identityFingerprint={identity?.identity?.fingerprint || ''}
        />
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
  // --- Gate ---
  gateOuter: {
    position: 'relative' as const,
    maxWidth: '540px',
    width: '100%',
    minHeight: '480px',
  },
  gatePanel: {
    position: 'relative' as const,
    zIndex: 1,
    background: 'rgba(10, 14, 12, 0.9)',
    backdropFilter: 'blur(20px)',
    border: '1px solid rgba(52, 211, 153, 0.08)',
    borderRadius: '16px',
    padding: '48px 40px',
    width: '100%',
    boxShadow: '0 4px 60px rgba(0, 0, 0, 0.5), 0 0 60px rgba(52, 211, 153, 0.02), inset 0 1px 0 rgba(255,255,255,0.03)',
  },
  gateTitle: {
    fontSize: '32px',
    fontWeight: 300,
    fontFamily: "'Cormorant Garamond', serif",
    color: '#e8e4d9',
    letterSpacing: '6px',
    textTransform: 'lowercase' as const,
    marginBottom: '8px',
    textShadow: '0 0 40px rgba(200, 168, 78, 0.2)',
  },
  gateSub: {
    fontSize: '14px',
    fontFamily: "'Cormorant Garamond', serif",
    fontWeight: 300,
    fontStyle: 'italic' as const,
    color: 'rgba(255,255,255,0.4)',
    lineHeight: '1.7',
  },
  doorContainer: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '12px',
    marginBottom: '24px',
  },
  doorBtn: {
    display: 'flex',
    flexDirection: 'column' as const,
    alignItems: 'center',
    padding: '28px 24px',
    background: 'rgba(6, 10, 8, 0.5)',
    border: '1px solid rgba(52, 211, 153, 0.08)',
    borderRadius: '12px',
    cursor: 'pointer',
    transition: 'all 0.3s ease',
    textAlign: 'center' as const,
  },
  doorTitle: {
    fontSize: '16px',
    fontWeight: 300,
    fontFamily: "'Cormorant Garamond', serif",
    color: '#c8a84e',
    letterSpacing: '1px',
    marginBottom: '8px',
  },
  doorDesc: {
    fontSize: '12px',
    fontFamily: "'Space Grotesk', system-ui, sans-serif",
    fontWeight: 300,
    color: 'rgba(255,255,255,0.25)',
    lineHeight: '1.6',
    maxWidth: '280px',
  },
  // --- Shared ---
  createPanel: {
    background: 'rgba(10, 14, 12, 0.9)',
    backdropFilter: 'blur(20px)',
    border: '1px solid rgba(52, 211, 153, 0.08)',
    borderRadius: '16px',
    padding: '40px',
    maxWidth: '460px',
    width: '100%',
    boxShadow: '0 4px 60px rgba(0, 0, 0, 0.5), 0 0 60px rgba(52, 211, 153, 0.02), inset 0 1px 0 rgba(255,255,255,0.03)',
  },
  backBtn: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    background: 'none',
    border: 'none',
    color: '#8a8070',
    fontSize: '12px',
    cursor: 'pointer',
    padding: '0',
    marginBottom: '20px',
    fontFamily: "'JetBrains Mono', monospace",
    letterSpacing: '0.5px',
  },
  hero: {
    textAlign: 'center' as const,
    marginBottom: '32px',
  },
  shieldIcon: {
    width: '120px',
    height: '120px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    margin: '0 auto 16px',
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
    fontSize: '26px',
    fontWeight: 300,
    fontFamily: "'Cormorant Garamond', serif",
    color: '#e8e4d9',
    letterSpacing: '2px',
    marginBottom: '10px',
    textShadow: '0 0 30px rgba(200, 168, 78, 0.15)',
  },
  heroSub: {
    fontSize: '13px',
    fontFamily: "'Space Grotesk', system-ui, sans-serif",
    fontWeight: 300,
    color: 'rgba(255,255,255,0.35)',
    lineHeight: '1.7',
    maxWidth: '340px',
    margin: '0 auto',
  },
  field: {
    marginBottom: '20px',
  },
  label: {
    display: 'block',
    fontSize: '10px',
    fontFamily: "'Space Grotesk', system-ui, sans-serif",
    color: 'rgba(255,255,255,0.3)',
    letterSpacing: '2px',
    textTransform: 'uppercase' as const,
    marginBottom: '8px',
    fontWeight: 400,
  },
  input: {
    width: '100%',
    background: 'rgba(6, 10, 8, 0.8)',
    border: '1px solid rgba(52, 211, 153, 0.1)',
    borderRadius: '8px',
    padding: '12px 16px',
    color: '#e8e4d9',
    fontSize: '14px',
    fontFamily: "'JetBrains Mono', monospace",
    outline: 'none',
    transition: 'border-color 0.3s',
    boxSizing: 'border-box' as const,
  },
  hint: {
    fontSize: '11px',
    color: '#5a5548',
    marginTop: '6px',
  },
  primaryBtn: {
    width: '100%',
    background: 'rgba(52, 211, 153, 0.1)',
    border: '1px solid rgba(52, 211, 153, 0.3)',
    borderRadius: '8px',
    padding: '14px 20px',
    color: '#34d399',
    fontSize: '12px',
    fontWeight: 500,
    fontFamily: "'Space Grotesk', system-ui, sans-serif",
    letterSpacing: '2px',
    textTransform: 'uppercase' as const,
    cursor: 'pointer',
    transition: 'all 0.3s',
    marginTop: '8px',
    boxShadow: '0 0 20px rgba(52, 211, 153, 0.06)',
  },
  restoreBtn: {
    width: '100%',
    background: 'rgba(78, 205, 196, 0.12)',
    border: '1px solid rgba(78, 205, 196, 0.35)',
    borderRadius: '8px',
    padding: '14px 20px',
    color: '#4ecdc4',
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
    border: '1px solid rgba(200, 168, 78, 0.2)',
    borderRadius: '8px',
    padding: '14px 20px',
    color: 'rgba(255,255,255,0.4)',
    fontSize: '12px',
    fontWeight: 400,
    fontFamily: "'Space Grotesk', system-ui, sans-serif",
    letterSpacing: '1px',
    cursor: 'pointer',
    transition: 'all 0.3s',
    marginTop: '8px',
  },
  uploadBtn: {
    width: '100%',
    display: 'flex',
    flexDirection: 'column' as const,
    alignItems: 'center',
    gap: '12px',
    background: 'rgba(10, 10, 15, 0.5)',
    border: '2px dashed rgba(78, 205, 196, 0.2)',
    borderRadius: '12px',
    padding: '32px 20px',
    color: '#4ecdc4',
    fontSize: '13px',
    fontFamily: "'JetBrains Mono', monospace",
    cursor: 'pointer',
    transition: 'all 0.2s',
  },
  fileInfo: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    background: 'rgba(78, 205, 196, 0.06)',
    border: '1px solid rgba(78, 205, 196, 0.15)',
    borderRadius: '8px',
    padding: '12px 16px',
    marginTop: '12px',
  },
  fileName: {
    fontSize: '12px',
    color: '#4ecdc4',
    fontFamily: "'JetBrains Mono', monospace",
  },
  fileSize: {
    fontSize: '11px',
    color: '#6a6558',
  },
  // --- Vault Info Card ---
  vaultInfoCard: {
    background: 'rgba(10, 10, 15, 0.5)',
    border: '1px solid rgba(78, 205, 196, 0.12)',
    borderRadius: '12px',
    padding: '20px',
    marginBottom: '20px',
  },
  vaultInfoRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '8px 0',
    borderBottom: '1px solid rgba(180, 160, 100, 0.06)',
  },
  vaultInfoLabel: {
    fontSize: '9px',
    color: '#6a6558',
    letterSpacing: '1.5px',
    fontWeight: 600,
  },
  vaultInfoValue: {
    fontSize: '13px',
    color: '#e0dcd0',
  },
  safeWordSection: {
    marginTop: '16px',
    padding: '16px',
    background: 'rgba(200, 168, 78, 0.06)',
    border: '1px solid rgba(200, 168, 78, 0.15)',
    borderRadius: '8px',
    textAlign: 'center' as const,
  },
  safeWordValue: {
    fontSize: '20px',
    fontWeight: 600,
    color: '#c8a84e',
    fontFamily: "'JetBrains Mono', monospace",
    letterSpacing: '2px',
    margin: '12px 0 8px',
  },
  safeWordHint: {
    fontSize: '11px',
    color: '#8a8070',
    lineHeight: '1.5',
    margin: 0,
  },
  // --- Trust Warning ---
  trustWarning: {
    display: 'flex',
    gap: '12px',
    background: 'rgba(200, 168, 78, 0.06)',
    border: '1px solid rgba(200, 168, 78, 0.2)',
    borderRadius: '10px',
    padding: '14px 16px',
    marginBottom: '20px',
  },
  // --- Eye toggle ---
  eyeBtn: {
    position: 'absolute' as const,
    right: '12px',
    top: '50%',
    transform: 'translateY(-50%)',
    background: 'none',
    border: 'none',
    cursor: 'pointer',
    padding: '4px',
  },
  btnInner: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
  },
  footer: {
    fontSize: '9px',
    fontFamily: "'JetBrains Mono', monospace",
    fontWeight: 300,
    color: 'rgba(255,255,255,0.15)',
    textAlign: 'center' as const,
    marginTop: '28px',
    lineHeight: '1.7',
    letterSpacing: '0.5px',
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
    background: 'rgba(10, 14, 12, 0.92)',
    backdropFilter: 'blur(20px)',
    border: '1px solid rgba(52, 211, 153, 0.1)',
    borderRadius: '16px',
    padding: '32px',
    boxShadow: '0 4px 60px rgba(0, 0, 0, 0.5), 0 0 80px rgba(52, 211, 153, 0.03), inset 0 1px 0 rgba(255,255,255,0.03)',
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
    fontSize: '20px',
    fontWeight: 300,
    fontFamily: "'Cormorant Garamond', serif",
    color: '#e8e4d9',
    letterSpacing: '1px',
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
    fontSize: '10px',
    fontFamily: "'Space Grotesk', system-ui, sans-serif",
    color: '#34d399',
    letterSpacing: '3px',
    fontWeight: 500,
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
    background: 'rgba(52, 211, 153, 0.06)',
    border: '1px solid rgba(52, 211, 153, 0.15)',
    borderRadius: '10px',
    padding: '14px 20px',
    marginTop: '16px',
    fontSize: '13px',
    fontFamily: "'Space Grotesk', system-ui, sans-serif",
    color: '#34d399',
    boxShadow: '0 0 30px rgba(52, 211, 153, 0.04)',
  },
};
