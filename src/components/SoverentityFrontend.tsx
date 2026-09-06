"use client";

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { SecureExportDialog, PrivateKeyExportDialog } from '@/components/SecureImportExportDialogs';
import { VaultExportDialog } from '@/components/export/VaultExportDialog';
import { ExportAuthGate } from '@/components/export/ExportAuthGate';
import { getBrowserIdentity } from '@/lib/identity/browser-identity';
import { loadKey, storeKey, loadPQKeys, loadIdentity, initSessionKey, isSessionUnlocked, storeIdentity, getAllContacts } from '@/lib/identity/client-store';
import { sendContactUpdate } from '@/lib/sync/send-contact-update';
import { buildMethodDelta } from '@/lib/contacts/method-send-delta';
import { base64ToUint8 } from '@/lib/crypto/pq';
import type { ContactMethodSendFn } from '@/components/identity/contact-method-send';
import { SVRNTY_DOMAIN, slugUrlShort } from '@/lib/config/domain';
import { EntropyMeter } from '@/components/recovery/EntropyMeter';
import { SoulSeedReveal } from '@/components/recovery/SoulSeedReveal';
import { SeedRestoreInterstitial } from '@/components/recovery/SeedRestoreInterstitial';
import { SovereignIdentityCard, type MethodKind } from '@/components/identity/SovereignIdentityCard';
import { OwnerCardStudio } from '@/components/identity/OwnerCardStudio';
import { ContactShareDialog } from '@/components/ContactShareDialog';
import { buildSignedIdentityCard } from '@/lib/identity/identity-card-sign';
import { ContactMethodReviseDialog } from '@/components/identity/ContactMethodReviseDialog';
import { loadLocalMethods, saveLocalMethods } from '@/components/identity/local-methods';
import { solarEmber as SE } from '@/components/recovery/solar-ember';
import { TRUST_RECIPE_COPY } from '@/lib/trust/trust-recipe';
import { BiometricSettingsPanel } from '@/components/biometric/BiometricSettingsPanel';
import { AppLockSettingsPanel } from '@/components/app-lock/AppLockSettingsPanel';
import type { AppLockPrefs } from '@/components/app-lock/app-lock-prefs';

interface SoverentityFrontendProps {
  existingIdentity?: any;
  onIdentityUpdate?: (identity: any) => void;
  onVaultRestore?: (contents: any) => void;
  /** Jump to Trust Map from the card's "Your circle" affordance */
  onOpenCircle?: () => void;
  /** CUR-7 — Signal-model app-lock prefs (shell owns timers + lockSession). */
  appLockPrefs?: AppLockPrefs;
  onAppLockPrefsChange?: (prefs: AppLockPrefs) => void;
  onLockNow?: () => void;
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
          0%, 100% { box-shadow: 0 0 20px rgba(249, 168, 37, 0.06); }
          50% { box-shadow: 0 0 40px rgba(249, 168, 37, 0.15), 0 0 60px rgba(249, 168, 37, 0.04); }
        }
      `}</style>

      {/* Sacred geometry — Flower of Life */}
      <svg width="100%" height="100%" style={{
        position: 'absolute', inset: 0,
        animation: 'sacred-breathe 12s ease-in-out infinite',
      }}>
        <defs>
          <radialGradient id="sacredGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#f9a825" stopOpacity="0.06" />
            <stop offset="100%" stopColor="#f9a825" stopOpacity="0" />
          </radialGradient>
        </defs>
        {/* Flower of Life circles */}
        {flowerCircles.map((c, i) => (
          <circle
            key={`flower-${i}`}
            cx={c.cx} cy={c.cy} r={60}
            fill="none"
            stroke="#f9a825"
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
            background: node.id % 3 === 0 ? '#f9a825' : '#c8a84e',
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
  onOpenCircle,
  appLockPrefs,
  onAppLockPrefsChange,
  onLockNow,
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

  // Vault restore state
  const [vaultFile, setVaultFile] = useState<File | null>(null);
  const [vaultHeader, setVaultHeader] = useState<any>(null);
  const [vaultPassphrase, setVaultPassphrase] = useState('');
  const [soulSeedPhrase, setSoulSeedPhrase] = useState('');
  /** Binary .svrnty only: daily passphrase unlock vs v4 seed-only (lost passphrase). */
  const [restorePath, setRestorePath] = useState<'passphrase' | 'seed'>('passphrase');
  /** Do-No-Harm: after opening a v3 backup, prompt re-export before a loss event. */
  const [showV3MigrationNudge, setShowV3MigrationNudge] = useState(false);
  /** After successful seed-only restore — unmissable contacts-honesty interstitial (no CTA). */
  const [seedRestoreInterstitial, setSeedRestoreInterstitial] = useState<{
    identity: any;
    fingerprint: string;
    pqSecretsRecovered: boolean;
  } | null>(null);

  // PQ migration state (shown after v1 import)
  const [pendingPqMigration, setPendingPqMigration] = useState<{ fingerprint: string; identity: any } | null>(null);
  const [pqMigrating, setPqMigrating] = useState(false);
  const [hasPqKeys, setHasPqKeys] = useState(false);

  // Export dialog state (CUR-4 — auth gate before sensitive export)
  const [showExportDialog, setShowExportDialog] = useState(false);
  const [showKeyExportDialog, setShowKeyExportDialog] = useState(false);
  const [showVaultExportDialog, setShowVaultExportDialog] = useState(false);
  const [pendingExportAuth, setPendingExportAuth] = useState<'contacts' | 'keys' | null>(null);
  const [showFullBackupDialog, setShowFullBackupDialog] = useState(false);
  const [fullBackupPassword, setFullBackupPassword] = useState('');
  const [fullBackupConfirm, setFullBackupConfirm] = useState('');
  const [fullBackupLoading, setFullBackupLoading] = useState(false);

  // CUR-1 — revise contact method + shared-with send (UI)
  const [reviseKind, setReviseKind] = useState<MethodKind | null>(null);
  const [showShareIdentity, setShowShareIdentity] = useState(false);
  const [sharePackage, setSharePackage] = useState('');
  const [shareBusy, setShareBusy] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);
  const [localMethods, setLocalMethods] = useState<{ signal?: string; site?: string }>({});
  const [audience, setAudience] = useState<
    { fingerprint: string; name: string; public_key?: string; trusted?: boolean; tags?: string[] }[]
  >([]);
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

  // CUR-1 — local Signal/Site drafts + audience list for revise dialog
  useEffect(() => {
    const fp = identity?.identity?.fingerprint as string | undefined;
    if (!fp) {
      setLocalMethods({});
      setAudience([]);
      return;
    }
    setLocalMethods(loadLocalMethods(fp));
    void getAllContacts(fp).then((rows) => {
      setAudience(
        rows
          .map((c) => {
            const peerFp = String(c.fingerprint || c.id || '').trim();
            if (!peerFp) return null;
            return {
              fingerprint: peerFp,
              name: c.name || 'Unnamed',
              public_key: c.public_key || undefined,
              trusted:
                String(c.trust_level || '').toLowerCase() === 'trusted' ||
                String(c.trust_level || '').toLowerCase() === 'verified' ||
                c.trusted === true,
              tags: (c as { tags?: string[]; metadata?: { tags?: string[] } }).tags
                || (c as { metadata?: { tags?: string[] } }).metadata?.tags
                || [],
            };
          })
          .filter((c): c is NonNullable<typeof c> => c != null)
      );
    });
  }, [identity]);

  // Restore claimed URL from registration service on identity load
  useEffect(() => {
    const fp = identity?.identity?.fingerprint;
    if (fp && !claimedUrl) {
      fetch(`/identity/${fp}`).then(r => r.ok ? r.json() : null).then(data => {
        if (data?.slug) setClaimedUrl(slugUrlShort(data.slug));
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
          setClaimedUrl(slugUrlShort(slug));
          return;
        }
        setClaimStatus('taken');
        return;
      }
      // Register with satellite
      const fp = identity?.identity?.fingerprint;
      const pk = identity?.identity?.public_key || identity?.identity?.publicKey || '';
      const { buildSatelliteRegisterFields } = await import('@/lib/identity/fingerprint');
      const extra = await buildSatelliteRegisterFields(identity);
      const regRes = await fetch('/api/satellite/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          display_name: slug,
          public_key: pk,
          fingerprint: extra?.fingerprint || fp || '',
          slug,
          ...(extra
            ? {
                sign_pub: extra.sign_pub,
                enc_pub: extra.enc_pub,
                kem_pub: extra.kem_pub,
                sig_pub: extra.sig_pub,
              }
            : {}),
        }),
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
          setClaimedUrl(slugUrlShort(slug));
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

  // Email-verification + OTP handlers removed. There is no server account to
  // verify against, and any email→identity path is a custodian backdoor (email-verify today implies
  // email-recovery tomorrow → whoever controls the inbox controls the identity). Recovery is SOCIAL
  // (Shamir guardians + veto window), never inbox-based; the identity is self-certifying (key possession).

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

      // .svrnty vault — read unencrypted header (crypto params + version only; no identity)
      const arrayBuffer = await file.arrayBuffer();
      const { readVaultHeader } = await import('@/lib/sync/vault');
      const header = readVaultHeader(arrayBuffer);
      setVaultHeader(header);
      setRestorePath('passphrase');
      setSoulSeedPhrase('');
      setVaultPassphrase('');
      setGateMode('restore-verify');
    } catch (err) {
      setRestoreError(
        err instanceof Error ? err.message : 'Could not read file. Accepts .svrnty or .json backups.'
      );
    }
  };

  /** v4 dual-envelope: lost passphrase → extractRecoveryVault + recoverFromSeedPhrase (fleet seam). */
  const handleSeedVaultRestore = async () => {
    if (!vaultFile || vaultHeader?.format !== 'svrnty-vault') return;
    // v3-guard: never offer / run seed-only on pre-v4 (UI + crypto belt).
    if (vaultHeader.version !== 4) {
      setRestoreError(
        'This backup was created before passphrase-free recovery. It can be restored only with your passphrase.',
      );
      setRestorePath('passphrase');
      return;
    }
    try {
      setRestoreLoading(true);
      setRestoreError(null);
      if (!soulSeedPhrase.trim()) {
        setRestoreError('Enter your recovery code.');
        return;
      }
      const arrayBuffer = await vaultFile.arrayBuffer();
      const { restoreIdentityFromSeedVault } = await import('@/components/recovery/seedVaultRestore');
      const result = await restoreIdentityFromSeedVault(arrayBuffer, soulSeedPhrase);
      // Keys are persisted; hold identity out of the main surface until the
      // contacts-honesty interstitial is acknowledged (queue: UNMISSABLE, no CTA).
      setSeedRestoreInterstitial({
        identity: result.identity,
        fingerprint: result.fingerprint,
        pqSecretsRecovered: result.pqSecretsRecovered,
      });
      setSoulSeedPhrase('');
      setVaultPassphrase('');
      setRestorePath('passphrase');
    } catch (err) {
      const msg = err instanceof Error ? err.message : '';
      // Wrong phrase / hash mismatch from decryptVault — no lockout; let them retry.
      // DO-SECOND honest error (seed-only path).
      if (/master secret|seed phrase|Invalid seed|hash|mismatch/i.test(msg)) {
        setRestoreError("That recovery code doesn't match this backup.");
      } else {
        setRestoreError(msg || 'Could not recover from this backup.');
      }
    } finally {
      setRestoreLoading(false);
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
        const { importAll, storeKey, addContact, loadIdentity, setActiveFingerprint, storeIdentity } = await import('@/lib/identity/client-store');

        // Detect format and normalize
        if (data.type === 'svrnty-full-backup') {
          // Encrypted full backup — decrypt first, then import
          if (!vaultPassphrase) {
            setRestoreError('Enter the encryption password you set when exporting this copy.');
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

          // L8: when a KeyVault is present, soul-seed is the second factor.
          if (backup.vault) {
            if (!soulSeedPhrase.trim()) {
              setRestoreError('Enter your soul-seed recovery phrase (second factor).');
              return;
            }
            try {
              const { recoverFromSeedPhrase } = await import('@/lib/crypto/recovery');
              const bundle = await recoverFromSeedPhrase(backup.vault, soulSeedPhrase.trim());
              // Prefer recovering keys from the vault when plaintext keys were omitted (true 2nd factor).
              if (!backup.keys) {
                backup.keys = {
                  privateKey: bundle.classical_private_key,
                  passphrase: bundle.classical_passphrase,
                };
              }
              // PQ private material shape is team-owned (serializeKeypairBundle). If the backup
              // omitted pq_keys, flag in recovery README — do not invent a bundle layout here.
              void bundle.pq_signing_secret_key;
              void bundle.pq_kem_secret_key;
            } catch {
              setRestoreError('Soul-seed does not open the recovery vault. Check the phrase and try again.');
              return;
            }
          }

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
          if (data.vault) {
            if (!soulSeedPhrase.trim()) {
              setRestoreError('Enter your soul-seed recovery phrase (second factor).');
              return;
            }
            try {
              const { recoverFromSeedPhrase } = await import('@/lib/crypto/recovery');
              const bundle = await recoverFromSeedPhrase(data.vault, soulSeedPhrase.trim());
              if (!data.keys) {
                data.keys = {
                  privateKey: bundle.classical_private_key,
                  passphrase: bundle.classical_passphrase,
                };
              }
            } catch {
              setRestoreError('Soul-seed does not open the recovery vault. Check the phrase and try again.');
              return;
            }
          }
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
        // .svrnty vault path — daily passphrase unlock (v3 + v4)
        if (!vaultPassphrase) return;
        const arrayBuffer = await vaultFile.arrayBuffer();
        const { unpackVault } = await import('@/lib/sync/vault');
        const { contents } = await unpackVault(arrayBuffer, vaultPassphrase);
        // Decryption succeeded → everything in `contents` is now AUTHENTICATED
        // by the passphrase (AES-GCM). The safe word (contents.settings.safeWord)
        // may be shown here as a post-decrypt confirmation — the honest place for
        // the recognition ritual, unforgeable because it required the key. (Pre-
        // passphrase display was removed in v3; a cleartext safe word is fakeable.)

        // PERSIST to IndexedDB so the restored identity survives a reload. Before this,
        // "Open Vault" only hydrated the in-memory React state below and the identity was
        // LOST on the next load — a silent data-safety bug contradicting "restore … on
        // THIS DEVICE / pick up where you left off" (fleet-confirmed
        // launch-blocker). The adapter binds the private key to the fingerprint + inits
        // the session key for at-rest equivalence, mirroring genesis + the recovery-code
        // path (restoreIdentityFromSeedVault). Runs BEFORE setIdentity so a vault that
        // fails its integrity check throws here and never reaches the main surface.
        const { restoreIdentityFromVault } = await import('@/components/recovery/vaultPassphraseRestore');
        await restoreIdentityFromVault(contents, vaultPassphrase);

        setIdentity(contents.identity);
        onIdentityUpdate?.(contents.identity);
        onVaultRestore?.(contents);
        // Migration nudge (DO-SECOND): v3 users should re-export before a loss event.
        if (vaultHeader?.version === 3) {
          setShowV3MigrationNudge(true);
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : '';
      const looksLikeDecryptFail =
        /decrypt|OperationError|passphrase|password|could not open vault/i.test(msg) ||
        (err instanceof DOMException && err.name === 'OperationError');
      // Claim-honesty: wrong passphrase on binary vault must NOT auto-offer seed
      // recovery in the error string for v3. v4 can offer the alternate path in UI.
      setRestoreError(
        looksLikeDecryptFail
          ? vaultHeader?.format === 'svrnty-vault' && vaultHeader?.version === 4
            ? 'Incorrect passphrase. Try again, or recover with your recovery code below.'
            : 'Incorrect encryption password. Use the password you set when you exported this copy.'
          : msg || 'Failed to restore'
      );
    } finally {
      setRestoreLoading(false);
    }
  };

  // --- Gate: Seed-restore contacts-honesty interstitial (UNMISSABLE, no CTA) ---
  // Spec DO-SECOND POST-SUCCESS INTERSTITIAL (d892bfa definitive no-CTA).
  if (seedRestoreInterstitial) {
    return (
      <SeedRestoreInterstitial
        fingerprint={seedRestoreInterstitial.fingerprint}
        pqSecretsRecovered={seedRestoreInterstitial.pqSecretsRecovered}
        onContinue={() => {
          const pending = seedRestoreInterstitial;
          setIdentity(pending.identity);
          onIdentityUpdate?.(pending.identity);
          setSeedRestoreInterstitial(null);
          setVaultFile(null);
          setVaultHeader(null);
          setGateMode('choose');
        }}
      />
    );
  }

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
                {/* Pointy-top hexagon + key — quiet pre-identity mark */}
                <svg
                  width="120"
                  height="120"
                  viewBox="0 0 100 100"
                  aria-hidden
                  style={{ overflow: 'visible', animation: 'gate-breathe 6s ease-in-out infinite' }}
                >
                  <defs>
                    <linearGradient id="hexGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                      <stop offset="0%" stopColor={SE.accent} stopOpacity="0.7" />
                      <stop offset="100%" stopColor={SE.accent2} stopOpacity="0.35" />
                    </linearGradient>
                  </defs>
                  <style>{`
                    @keyframes gate-breathe {
                      0%, 100% { filter: drop-shadow(0 0 10px rgba(249,168,37,.2)); }
                      50% { filter: drop-shadow(0 0 18px rgba(249,168,37,.4)); }
                    }
                    @keyframes gate-key-pulse {
                      0%, 100% { opacity: 0.88; }
                      50% { opacity: 1; }
                    }
                  `}</style>
                  {/* Pointy-top regular hexagon */}
                  <polygon
                    points="50,8 86,29 86,71 50,92 14,71 14,29"
                    fill="none"
                    stroke="url(#hexGrad)"
                    strokeWidth="1.4"
                    strokeLinejoin="miter"
                  />
                  <polygon
                    points="50,20 76,35 76,65 50,80 24,65 24,35"
                    fill="none"
                    stroke={SE.accent}
                    strokeOpacity="0.28"
                    strokeWidth="0.9"
                  />
                  {/* Key */}
                  <g
                    transform="translate(50,50)"
                    style={{ animation: 'gate-key-pulse 4s ease-in-out infinite' }}
                    stroke={SE.accent}
                    strokeWidth="1.6"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    fill="none"
                  >
                    <circle cx="0" cy="-8" r="7" />
                    <circle cx="0" cy="-8" r="2.5" fill={SE.bg} stroke={SE.accent} />
                    <line x1="0" y1="-1" x2="0" y2="16" />
                    <line x1="0" y1="8" x2="6" y2="8" />
                    <line x1="0" y1="13" x2="4.5" y2="13" />
                  </g>
                </svg>
              </div>
              <h1 style={s.gateTitle}>svrnty</h1>
              <p style={s.gateSub}>
                A card, not an account. Trust starts in the world.
              </p>
            </div>

            {/* Two Doors */}
            <div style={s.doorContainer}>
              <button
                onClick={() => setGateMode('forge')}
                style={s.doorBtn}
                aria-label={`${TRUST_RECIPE_COPY.gateStart}. Generate a new cryptographic identity.`}
                onMouseEnter={e => {
                  const el = e.currentTarget;
                  el.style.borderColor = 'var(--se-border-lit)';
                  el.style.background = 'color-mix(in srgb, var(--se-accent) 12%, transparent)';
                }}
                onMouseLeave={e => {
                  const el = e.currentTarget;
                  el.style.borderColor = 'var(--se-border)';
                  el.style.background = 'var(--se-surface)';
                }}
              >
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--se-accent)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ marginBottom: '12px' }}>
                  <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
                </svg>
                <span style={s.doorTitle}>{TRUST_RECIPE_COPY.gateStart}</span>
                <span style={s.doorDesc}>
                  A living address book and social web. You own it. We don&apos;t want your data.
                </span>
              </button>

              <button
                onClick={() => setGateMode('restore')}
                style={s.doorBtn}
                aria-label={`${TRUST_RECIPE_COPY.gateContinue}. Restore your identity from a vault file.`}
                onMouseEnter={e => {
                  const el = e.currentTarget;
                  el.style.borderColor = 'rgba(78, 205, 196, 0.45)';
                  el.style.background = 'rgba(78, 205, 196, 0.08)';
                }}
                onMouseLeave={e => {
                  const el = e.currentTarget;
                  el.style.borderColor = 'var(--se-border)';
                  el.style.background = 'var(--se-surface)';
                }}
              >
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#4ecdc4" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ marginBottom: '12px' }}>
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
                <span style={{ ...s.doorTitle, color: '#4ecdc4' }}>Restore from a copy.</span>
                <span style={s.doorDesc}>
                  Open an exported vault or backup file.
                  You&apos;ll need the encryption password you set when you exported it.
                </span>
              </button>
            </div>

            <p style={s.footer}>
              Ed25519 signing · Curve25519 encryption · post-quantum-ready (ML-DSA-87 + ML-KEM-1024).
              <br />Local-first. Sovereign.
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
            <h2 style={s.heroTitle}>{TRUST_RECIPE_COPY.gateStart}</h2>
            <p style={s.heroSub}>
              A card, not an account. Generate a sovereign keypair. Your keys never leave your device.
              Post-quantum-ready encryption. No server can read your data. No tracking.
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
            <EntropyMeter value={unlockPassphrase} label="Unlock strength" />
            {unlockError && <p style={{ ...s.hint, color: '#ff6b6b' }}>{unlockError}</p>}
            <p style={s.hint}>Required. Protects private keys in this browser. Min 12 chars. This is NOT emailed — write it down. (Recovery code is shown next — a separate second factor.)</p>
          </div>

          <button
            onClick={handleCreateIdentity}
            disabled={loading || !formData.name || unlockPassphrase.length < 12 || unlockPassphrase !== unlockConfirm}
            style={{
              ...s.primaryBtn,
              opacity: loading || !formData.name || unlockPassphrase.length < 12 || unlockPassphrase !== unlockConfirm ? 0.5 : 1,
            }}
          >
            {loading ? (
              <span style={s.btnInner}>
                <Spinner /> Generating keys...
              </span>
            ) : (
              <span style={s.btnInner}>{TRUST_RECIPE_COPY.gateStart}</span>
            )}
          </button>

          <p style={s.footer}>
            Ed25519 signing · Curve25519 encryption · post-quantum-ready (ML-DSA-87 + ML-KEM-1024).
            <br />Your keys. Your data. Your sovereignty.
          </p>
        </div>
      </div>
    );
  }

  // --- Gate: one-time recovery reveal (seed phrase) ---
  if (!identity && gateMode === 'recovery-reveal' && pendingRecovery) {
    const fp = pendingRecovery.identity?.identity?.fingerprint || '';
    return (
      <SoulSeedReveal
        seedPhrase={pendingRecovery.seedPhrase}
        fingerprint={fp}
        threshold={pendingRecovery.threshold}
        shardCount={pendingRecovery.shardCount}
        acked={recoveryAcked}
        onAckChange={setRecoveryAcked}
        onContinue={confirmRecoveryReveal}
      />
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
            <h2 style={s.heroTitle}>Restore from a copy</h2>
            <p style={s.heroSub}>
              Upload a .svrnty vault or .json backup you exported earlier.
              Next you&apos;ll enter the encryption password you chose for that file —
              not an account login password.
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

  // --- Gate: Restore Vault (passphrase unlock / v4 seed recovery) ---
  if (!identity && gateMode === 'restore-verify' && vaultHeader) {
    const isBinaryVault = vaultHeader.format === 'svrnty-vault';
    const isV4Vault = isBinaryVault && vaultHeader.version === 4;
    const isV3Vault = isBinaryVault && vaultHeader.version === 3;
    const seedPathActive = isBinaryVault && restorePath === 'seed';

    return (
      <div style={s.outerWrap}>
        <div style={s.createCard}>
          <button
            onClick={() => {
              setGateMode('restore');
              setVaultHeader(null);
              setVaultPassphrase('');
              setSoulSeedPhrase('');
              setRestorePath('passphrase');
              setRestoreError(null);
            }}
            style={s.backBtn}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M19 12H5M12 19l-7-7 7-7" />
            </svg>
            Back
          </button>

          <div style={s.hero}>
            <div style={{ ...s.keyIcon, borderColor: 'rgba(78, 205, 196, 0.2)', background: 'rgba(78, 205, 196, 0.08)' }}>
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#4ecdc4" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <h2 style={s.heroTitle}>
              {seedPathActive ? 'Recover with your recovery code' : 'Unlock your exported copy'}
            </h2>
            {seedPathActive ? (
              <p style={s.heroSub}>
                Enter your recovery code to unlock this backup — it works without your passphrase.
              </p>
            ) : (
              <p style={s.heroSub}>
                Enter the encryption password you set when you exported this file.
                This is not a website or account login password.
              </p>
            )}
            {isV4Vault && !seedPathActive && (
              <p style={s.heroSub}>
                Two ways to restore — both need your backup file:
              </p>
            )}
          </div>

          {/* Type recognition only — nothing identity-revealing pre-decrypt. */}
          {isBinaryVault && (
            <div style={s.vaultInfoCard}>
              <div style={s.vaultInfoRow}>
                <span style={s.vaultInfoLabel}>FILE</span>
                <span style={s.vaultInfoValue}>Encrypted svrnty vault · v{vaultHeader.version}</span>
              </div>
              {isV4Vault && !seedPathActive ? (
                <div style={{ ...s.safeWordHint, display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <p style={{ margin: 0 }}>
                    Password + backup file → everything (identity, contacts, and trust).
                  </p>
                  <p style={{ margin: 0 }}>
                    Recovery code + backup file → your identity only (no contacts; reconnect those).
                  </p>
                  <p style={{ margin: '4px 0 0', opacity: 0.85 }}>
                    Alternatives — never both. Password alone opens a v4 backup fully.
                  </p>
                </div>
              ) : (
                <p style={s.safeWordHint}>
                  {seedPathActive
                    ? 'Your recovery code unlocks the recovery data inside this backup file — but only together with the file itself. The code alone can\'t rebuild you from nothing.'
                    : 'This vault is sealed. Your name, contacts, and safe word appear only after you enter the correct passphrase — so nothing shown here can be forged. Enter your passphrase to open it.'}
                </p>
              )}
            </div>
          )}

          {restoreError && <div style={s.error}>{restoreError}</div>}

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
                  This file contains your identity data in plaintext. It will be imported directly into your browser&apos;s local storage.
                </p>
              </div>
            </div>
          ) : (vaultHeader?.format === 'json-keys-encrypted' || vaultHeader?.format === 'json-full-encrypted') ? (
            <div style={s.trustWarning}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#c8a84e" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0, marginTop: '1px' }}>
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                <line x1="12" y1="9" x2="12" y2="13" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>
              <div>
                <strong style={{ color: '#c8a84e', fontSize: '12px' }}>Encrypted key backup detected.</strong>
                <p style={{ margin: '4px 0 0', fontSize: '11px', color: '#8a8070', lineHeight: '1.5' }}>
                  Enter the encryption password you set when exporting this copy, then your soul-seed if the backup includes a KeyVault. Not your everyday unlock passphrase.
                </p>
              </div>
            </div>
          ) : !seedPathActive ? (
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
          ) : null}

          {/* Passphrase — daily path only */}
          {!seedPathActive &&
            (vaultHeader?.format === 'json-keys-encrypted' ||
              vaultHeader?.format === 'json-full-encrypted' ||
              vaultHeader?.format === 'svrnty-vault') && (
            <div style={s.field}>
              <label style={s.label}>EXPORT ENCRYPTION PASSWORD</label>
              <p style={{ margin: '0 0 8px', fontSize: '11px', color: '#8a8070', lineHeight: '1.5' }}>
                The password you chose when you exported this copy. It is not a website login password.
              </p>
              <div style={{ position: 'relative' }}>
                <input
                  type={showPassphrase ? 'text' : 'password'}
                  name="svrnty-export-encryption-password"
                  autoComplete="off"
                  autoCorrect="off"
                  autoCapitalize="off"
                  spellCheck={false}
                  placeholder="Encryption password from export"
                  value={vaultPassphrase}
                  onChange={e => setVaultPassphrase(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter' && vaultPassphrase) handleVaultRestore();
                  }}
                  style={s.input}
                  autoFocus
                />
                <button
                  type="button"
                  onClick={() => setShowPassphrase(!showPassphrase)}
                  style={s.eyeBtn}
                  tabIndex={-1}
                  aria-label={showPassphrase ? 'Hide passphrase' : 'Show passphrase'}
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
              {isV4Vault && (
                <p style={s.hint}>Unlocks the backup file — identity, contacts, and trust.</p>
              )}
            </div>
          )}

          {/* Recovery phrase — JSON KeyVault 2FA, or v4 binary seed-only path */}
          {(seedPathActive ||
            vaultHeader?.format === 'json-keys-encrypted' ||
            vaultHeader?.format === 'json-full-encrypted' ||
            (vaultHeader?.format === 'json-backup' && vaultHeader?._jsonData?.vault)) && (
            <div style={s.field}>
              <label style={{ ...s.label, color: SE.accent }}>
                {seedPathActive ? 'Recovery code' : 'RECOVERY PHRASE'}
              </label>
              <textarea
                placeholder={
                  seedPathActive
                    ? 'Enter your recovery code — 8 groups of 8 characters (64 characters total) that you saved when you created your identity.'
                    : 'Paste the recovery phrase shown at forge (hex groups)'
                }
                value={soulSeedPhrase}
                onChange={e => setSoulSeedPhrase(e.target.value)}
                rows={3}
                style={{ ...s.input, fontFamily: SE.fontMono, fontSize: 12, resize: 'vertical' as const }}
                autoFocus={seedPathActive}
              />
              <p style={s.hint}>
                {seedPathActive
                  ? 'Wrong code fails closed — no lockout; try again.'
                  : 'Second factor when the backup includes a KeyVault. Required to open sealed recovery material.'}
              </p>
            </div>
          )}

          {vaultHeader?.format === 'json-backup' && !seedPathActive ? (
            <>
              <button
                type="button"
                onClick={handleVaultRestore}
                disabled={
                  restoreLoading ||
                  (!!vaultHeader?._jsonData?.vault && !soulSeedPhrase.trim())
                }
                style={{
                  ...s.restoreBtn,
                  opacity:
                    restoreLoading ||
                    (!!vaultHeader?._jsonData?.vault && !soulSeedPhrase.trim())
                      ? 0.5
                      : 1,
                }}
              >
                {restoreLoading ? (
                  <span style={s.btnInner}>
                    <Spinner /> Restoring...
                  </span>
                ) : (
                  <span style={s.btnInner}>Open Vault</span>
                )}
              </button>
              <p style={s.footer}>
                Your backup will be imported into this browser&apos;s local storage.
              </p>
            </>
          ) : seedPathActive ? (
            <>
              <button
                type="button"
                onClick={handleSeedVaultRestore}
                disabled={restoreLoading || !soulSeedPhrase.trim()}
                style={{
                  ...s.restoreBtn,
                  opacity: restoreLoading || !soulSeedPhrase.trim() ? 0.5 : 1,
                }}
              >
                {restoreLoading ? (
                  <span style={s.btnInner}>
                    <Spinner /> Recovering...
                  </span>
                ) : (
                  <span style={s.btnInner}>Recover my identity</span>
                )}
              </button>
              <button
                type="button"
                onClick={() => {
                  setRestorePath('passphrase');
                  setSoulSeedPhrase('');
                  setRestoreError(null);
                }}
                style={{ ...s.backBtn, marginTop: 12, alignSelf: 'center' }}
              >
                I have my passphrase
              </button>
              <p style={s.footer}>
                Recovery runs locally on this device with the backup file you selected.
                <br />
                Contacts sealed under the passphrase are not restored on this path.
              </p>
            </>
          ) : (
            <>
              <button
                type="button"
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
                  <span style={s.btnInner}>
                    {isBinaryVault ? 'Restore identity' : 'Open Vault'}
                  </span>
                )}
              </button>

              {isV4Vault && (
                <button
                  type="button"
                  onClick={() => {
                    setRestorePath('seed');
                    setVaultPassphrase('');
                    setRestoreError(null);
                  }}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: SE.accent,
                    fontFamily: SE.fontSans,
                    fontSize: 13,
                    cursor: 'pointer',
                    marginTop: 16,
                    textDecoration: 'underline',
                    textUnderlineOffset: 3,
                  }}
                >
                  Lost your passphrase? Recover with your recovery code
                </button>
              )}
              {isV3Vault && (
                <div style={{ ...s.hint, marginTop: 16, textAlign: 'center' }}>
                  <p style={{ margin: '0 0 6px' }}>
                    This backup was created before passphrase-free recovery. It can be restored only with your passphrase.
                  </p>
                  <p style={{ margin: 0 }}>
                    Re-export your identity to enable recovery-code restore if you lose your passphrase.
                  </p>
                </div>
              )}

              <p style={s.footer}>
                Decryption happens locally in your browser.
                <br />Your passphrase never leaves this device.
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
  // A sovereign identity is SELF-CERTIFYING:
  // the vault (device + Argon2id passphrase) and the local keys ARE the identity — the fingerprint
  // binds the key, the key IS the proof, attested by no one. There is no verified/unverified model to
  // be in: the identity is complete by construction. The label claims only what the architecture
  // confers — self-certification (SOVEREIGN), never third-party verification.


  const handleShareIdentityFromCard = async () => {
    if (!identity?.identity?.fingerprint) return;
    setShareBusy(true);
    setShareError(null);
    try {
      const fp = identity.identity.fingerprint as string;
      const key = await loadKey(fp);
      if (!key) throw new Error('Unlock your identity first to share a signed card.');
      const signed = await buildSignedIdentityCard(identity, key.privateKey, key.passphrase);
      setSharePackage(JSON.stringify(signed, null, 2));
      setShowShareIdentity(true);
    } catch (e) {
      setShareError(e instanceof Error ? e.message : 'Could not prepare share package');
    } finally {
      setShareBusy(false);
    }
  };

  // ── Method-grow: real SEND of a revised contact method to selected contacts. ──
  // Wires the dialog to sendContactUpdate (crypto lives in that module; called from here).
  // The owner signs from the unlocked vault; card_version is the monotonic replay floor — bumped +
  // PERSISTED BEFORE the deposit (crash-safety: a crash after deposit but before persist
  // must never re-use a version, or the next edit stale-rejects and is silently lost). epoch=0 until
  // key-rotation. Recipient poll-loop (ContactManagement) applies + repaints live — this closes it.
  const handleContactMethodSend: ContactMethodSendFn = async (req) => {
    const value = req.value.trim();
    const fp = identity?.identity?.fingerprint as string | undefined;
    if (!fp) return { ok: false, reason: 'error', message: 'No active identity.' };
    if (req.recipientFingerprints.length === 0)
      return { ok: false, reason: 'no-recipients', message: 'Pick at least one person who already has your card.' };

    // Owner signing material — requires the vault unlocked (same gate as sharing a signed card).
    const key = await loadKey(fp);
    if (!key)
      return { ok: false, reason: 'locked', message: 'Unlock your identity first to send a signed update.' };
    let pqSigningSecretKey: Uint8Array | undefined;
    try {
      const pq = await loadPQKeys(fp);
      if (pq?.pq_signing_secret_key) pqSigningSecretKey = base64ToUint8(pq.pq_signing_secret_key);
    } catch {
      /* classical-only if the PQ half can't be read — never block the send on it */
    }

    // Monotonic card_version — PERSIST-FIRST (before any deposit). Read the freshly-persisted identity
    // (loadIdentity, not the possibly-stale React closure) so a just-saved email edit is not clobbered
    // and the version reflects durable truth.
    const fresh = (await loadIdentity(fp)) || identity;
    const nextVersion = (typeof fresh?.card_version === 'number' ? fresh.card_version : 0) + 1;
    const bumped = { ...fresh, card_version: nextVersion };
    await storeIdentity(fp, bumped); // persist BEFORE the deposit — crash-safety
    setIdentity(bumped);

    const owner = {
      fingerprint: fp,
      epoch: 0, // no key-rotation yet — recipients hold the card at epoch 0
      privateKeyArmored: key.privateKey,
      passphrase: key.passphrase,
      pqSigningSecretKey,
    };
    // Map chosen recipients → {fingerprint, pubkey}. A missing key is passed as '' so the composer
    // SKIPS it (reason: no-public-key) — never a downgraded/cleartext send.
    const byFp = new Map(audience.map((c) => [c.fingerprint, c]));
    const recipients = req.recipientFingerprints.map((rfp) => ({
      fingerprint: rfp,
      publicKeyArmored: byFp.get(rfp)?.public_key ?? '',
    }));

    try {
      const result = await sendContactUpdate(
        { version: nextVersion, delta: buildMethodDelta(req.kind, value) },
        owner,
        recipients,
      );
      const deposited = result.deposited.length;
      const skipped = result.skipped.length;
      const failed = result.failed.length;
      if (deposited === 0) {
        return {
          ok: false,
          reason: 'not-delivered',
          message: `Couldn't deliver: ${skipped} had no key, ${failed} failed. Saved locally — try Send again later.`,
        };
      }
      return {
        ok: true,
        status: 'sent',
        deposited,
        skipped,
        failed,
        message:
          `Sent to ${deposited} contact${deposited === 1 ? '' : 's'}` +
          (skipped ? `, ${skipped} skipped (no key yet)` : '') +
          (failed ? `, ${failed} failed (retry)` : '') +
          '.',
      };
    } catch (e) {
      return { ok: false, reason: 'error', message: e instanceof Error ? e.message : 'Send failed.' };
    }
  };

  if (!identity) return null;

  return (
    <div style={s.outerWrap}>
      <div style={s.identityPanel}>
        <SovereignIdentityCard
          name={identity.identity.name}
          fingerprint={identity.identity.fingerprint}
          handle={claimedUrl || undefined}
          email={identity.identity.email}
          signal={localMethods.signal}
          site={
            localMethods.site ||
            (claimedUrl ? claimedUrl.replace(/^https?:\/\//, '') : undefined)
          }
          hasPqKeys={!!hasPqKeys}
          onRevise={(kind) => setReviseKind(kind)}
          onOpenCircle={onOpenCircle}
          onShareIdentity={() => { void handleShareIdentityFromCard(); }}
        />
        <OwnerCardStudio
          fingerprint={identity.identity.fingerprint}
          email={identity.identity.email}
          onEmailChange={async (value) => {
            const fp = identity.identity.fingerprint as string;
            const next = {
              ...identity,
              identity: { ...identity.identity, email: value },
            };
            await storeIdentity(fp, next);
            setIdentity(next);
            onIdentityUpdate?.(next);
          }}
        />
        {shareError ? (
          <p style={{ color: 'var(--se-danger)', fontSize: 12, textAlign: 'center' }}>{shareError}</p>
        ) : null}
        {shareBusy ? (
          <p style={{ color: 'var(--se-muted)', fontSize: 12, textAlign: 'center' }}>Preparing share…</p>
        ) : null}
        <ContactShareDialog
          open={showShareIdentity}
          onClose={() => setShowShareIdentity(false)}
          exchangePackage={sharePackage}
          fingerprint={identity.identity.fingerprint}
        />

        <ContactMethodReviseDialog
          open={reviseKind !== null}
          kind={reviseKind ?? 'email'}
          initialValue={
            reviseKind === 'signal'
              ? localMethods.signal || ''
              : reviseKind === 'site'
                ? localMethods.site ||
                  (claimedUrl ? claimedUrl.replace(/^https?:\/\//, '') : '') ||
                  ''
                : identity.identity.email || ''
          }
          ownerFingerprint={identity.identity.fingerprint}
          contacts={audience}
          onClose={() => setReviseKind(null)}
          onLocalSave={async (kind, value) => {
            const fp = identity.identity.fingerprint as string;
            if (kind === 'email') {
              const next = {
                ...identity,
                identity: { ...identity.identity, email: value },
              };
              await storeIdentity(fp, next);
              setIdentity(next);
              onIdentityUpdate?.(next);
              return;
            }
            const nextMethods = saveLocalMethods(fp, {
              [kind]: value,
            });
            setLocalMethods(nextMethods);
          }}
          sendFn={handleContactMethodSend}
        />

        {/* Export / Backup Section — CUR-4: vault via fleet packVault + export-behind-auth */}
        {identity && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '28px', maxWidth: 440, width: '100%' }}>
            {showV3MigrationNudge && (
              <div
                role="status"
                style={{
                  background: 'rgba(249, 168, 37, 0.08)',
                  border: '1px solid rgba(249, 168, 37, 0.28)',
                  borderRadius: 12,
                  padding: '14px 16px',
                  marginBottom: 4,
                }}
              >
                <p style={{ margin: '0 0 8px', color: SE.accent, fontSize: 13, fontWeight: 600, lineHeight: 1.4 }}>
                  Update your backup to enable passphrase-free recovery
                </p>
                <p style={{ margin: '0 0 12px', color: SE.muted, fontSize: 12, lineHeight: 1.5 }}>
                  This identity was opened from a v3 backup. Re-export a new .svrnty file so recovery-code restore works if you lose your passphrase.
                </p>
                <button
                  type="button"
                  onClick={() => setShowV3MigrationNudge(false)}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: SE.dim,
                    fontFamily: SE.fontSans,
                    fontSize: 12,
                    cursor: 'pointer',
                    textDecoration: 'underline',
                    textUnderlineOffset: 2,
                    padding: 0,
                  }}
                >
                  Dismiss
                </button>
              </div>
            )}
            <button
              onClick={() => setShowVaultExportDialog(true)}
              data-testid="full-backup-open"
              style={{
                ...s.outlineBtn,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                background: 'rgba(249, 168, 37, 0.08)',
                borderColor: 'rgba(249, 168, 37, 0.35)',
                color: SE.accent,
              }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={SE.accent} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              Full Backup (Encrypted)
            </button>
            <div style={{ display: 'flex', gap: '10px' }}>
              <button
                onClick={() => setPendingExportAuth('keys')}
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
                onClick={() => setPendingExportAuth('contacts')}
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

        {/* CUR-7 — app-lock settings (shell owns lockSession + idle timers) */}
        {identity && appLockPrefs && onAppLockPrefsChange && (
          <AppLockSettingsPanel
            prefs={appLockPrefs}
            onChange={onAppLockPrefsChange}
            onLockNow={onLockNow}
          />
        )}

        {/* Set Passphrase button */}
        {identity && (
          <div style={{ display: 'flex', justifyContent: 'center', marginTop: '12px' }}>
            <button
              onClick={() => setShowPassphraseDialog(true)}
              style={{
                background: 'none',
                border: '1px solid rgba(249, 168, 37, 0.15)',
                borderRadius: '8px',
                padding: '10px 20px',
                color: 'rgba(249, 168, 37, 0.6)',
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

        {/* CUR-6 — device unlock (WebAuthn/PRF seam = Flint; stub is claim-honest) */}
        {identity?.identity?.fingerprint && (
          <BiometricSettingsPanel
            fingerprint={identity.identity.fingerprint}
            compact
          />
        )}

        {/* Passphrase Dialog */}
        {showPassphraseDialog && (
          <div style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.55)',
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            zIndex: 50,
          }} onClick={() => setShowPassphraseDialog(false)}>
            <div
              role="dialog"
              aria-label="Set passphrase"
              style={{
              background: SE.surfaceSolid,
              border: `1px solid ${SE.border}`,
              borderRadius: '16px',
              padding: '32px',
              maxWidth: '380px',
              width: '100%',
              margin: '20px',
              boxShadow: 'var(--se-glass-shadow)',
              color: SE.text,
            }} onClick={e => e.stopPropagation()}>
              <h3 style={{
                fontFamily: SE.fontSans,
                fontSize: '1.15rem',
                fontWeight: 500,
                letterSpacing: '-0.02em',
                color: SE.text,
                marginBottom: '20px',
                textAlign: 'center' as const,
              }}>
                {passphraseSuccess ? 'Passphrase Set' : 'Set Passphrase'}
              </h3>
              {passphraseSuccess ? (
                <p style={{ textAlign: 'center' as const, color: SE.accent, fontFamily: SE.fontSans, fontSize: '13px' }}>
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
                      background: SE.inputBg,
                      border: `1px solid ${SE.border}`,
                      borderRadius: '8px',
                      padding: '12px 14px',
                      color: SE.text,
                      fontSize: '14px',
                      fontFamily: SE.fontSans,
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
                      background: SE.inputBg,
                      border: `1px solid ${SE.border}`,
                      borderRadius: '8px',
                      padding: '12px 14px',
                      color: SE.text,
                      fontSize: '14px',
                      fontFamily: SE.fontSans,
                      outline: 'none',
                      marginBottom: '8px',
                      boxSizing: 'border-box' as const,
                    }}
                  />
                  {passphraseError && (
                    <p style={{ color: SE.danger, fontSize: '12px', fontFamily: SE.fontSans, marginBottom: '8px' }}>{passphraseError}</p>
                  )}
                  <button
                    onClick={handleSetPassphrase}
                    disabled={!newPassphrase || !confirmPassphrase}
                    style={{
                      width: '100%',
                      background: 'color-mix(in srgb, var(--se-accent) 12%, transparent)',
                      border: `1px solid ${SE.borderLit}`,
                      borderRadius: '8px',
                      padding: '12px',
                      color: SE.accent,
                      fontSize: '12px',
                      fontFamily: SE.fontSans,
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
            position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)',
            display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 50,
          }} onClick={() => setShowClaimUrlDialog(false)}>
            <div
              role="dialog"
              aria-label="Claim URL"
              style={{
                background: SE.surfaceSolid,
                border: `1px solid ${SE.border}`,
                borderRadius: '16px',
                padding: '32px',
                maxWidth: '380px',
                width: '100%',
                margin: '20px',
                boxShadow: 'var(--se-glass-shadow)',
                color: SE.text,
              }}
              onClick={e => e.stopPropagation()}
            >
              <h3 style={{
                fontFamily: SE.fontSans, fontSize: '1.15rem', fontWeight: 500,
                letterSpacing: '-0.02em',
                color: SE.text, marginBottom: '8px', textAlign: 'center' as const,
              }}>
                {claimStatus === 'success' ? 'URL Claimed' : 'Claim Your URL'}
              </h3>
              {claimStatus === 'success' ? (
                <div style={{ textAlign: 'center' as const }}>
                  <p style={{ color: SE.accent, fontFamily: SE.fontSans, fontSize: '13px', marginBottom: '12px' }}>
                    Your identity is now at:
                  </p>
                  <p style={{ color: SE.accent, fontFamily: SE.fontSans, fontSize: '16px', fontWeight: 600 }}>
                    {claimedUrl}
                  </p>
                </div>
              ) : (
                <>
                  <p style={{ color: SE.muted, fontFamily: SE.fontSans, fontSize: '12px', marginBottom: '16px', textAlign: 'center' as const }}>
                    Choose a URL for your public profile
                  </p>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px', marginBottom: '8px' }}>
                    <span style={{ color: SE.dim, fontFamily: SE.fontSans, fontSize: '14px', whiteSpace: 'nowrap' as const }}>{SVRNTY_DOMAIN}/</span>
                    <input
                      type="text"
                      placeholder="yourname"
                      value={claimSlug}
                      onChange={e => { setClaimSlug(e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, '')); setClaimStatus('idle'); }}
                      style={{
                        flex: 1, background: SE.inputBg, border: `1px solid ${SE.border}`,
                        borderRadius: '8px', padding: '12px 14px', color: SE.text, fontSize: '14px',
                        fontFamily: SE.fontSans, outline: 'none', boxSizing: 'border-box' as const,
                      }}
                    />
                  </div>
                  {claimStatus === 'taken' && (
                    <p style={{ color: SE.danger, fontSize: '12px', fontFamily: SE.fontSans, marginBottom: '8px' }}>This URL is already claimed</p>
                  )}
                  {claimStatus === 'error' && (
                    <p style={{ color: SE.danger, fontSize: '12px', fontFamily: SE.fontSans, marginBottom: '8px' }}>Must be at least 3 characters (a-z, 0-9, -, _)</p>
                  )}
                  <button
                    onClick={handleClaimUrl}
                    disabled={claimSlug.length < 3 || claimStatus === 'checking' || claimStatus === 'claiming'}
                    style={{
                      width: '100%', background: 'color-mix(in srgb, var(--se-accent) 12%, transparent)',
                      border: `1px solid ${SE.borderLit}`,
                      borderRadius: '8px', padding: '12px', color: SE.accent, fontSize: '12px',
                      fontFamily: SE.fontSans, letterSpacing: '1px', cursor: 'pointer', marginTop: '8px',
                    }}
                  >
                    {claimStatus === 'checking' ? 'CHECKING...' : claimStatus === 'claiming' ? 'CLAIMING...' : 'CLAIM URL'}
                  </button>
                </>
              )}
            </div>
          </div>
        )}

        {/* Export Dialogs — CUR-4 auth gate + vault packer */}
        <ExportAuthGate
          open={pendingExportAuth !== null}
          fingerprint={identity?.identity?.fingerprint || ''}
          exportLabel={
            pendingExportAuth === 'keys'
              ? 'your private keys'
              : 'your contacts backup'
          }
          onClose={() => setPendingExportAuth(null)}
          onAuthenticated={() => {
            const kind = pendingExportAuth;
            setPendingExportAuth(null);
            if (kind === 'keys') setShowKeyExportDialog(true);
            if (kind === 'contacts') setShowExportDialog(true);
          }}
          onSessionLocked={() => {
            window.location.reload();
          }}
        />
        <VaultExportDialog
          open={showVaultExportDialog}
          onClose={() => setShowVaultExportDialog(false)}
          fingerprint={identity?.identity?.fingerprint || ''}
          onSessionLocked={() => {
            window.location.reload();
          }}
        />
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
    background: SE.surfaceSolid,
    backdropFilter: 'blur(20px)',
    border: `1px solid ${SE.borderLit}`,
    borderRadius: '16px',
    padding: '48px 40px',
    width: '100%',
    boxShadow: 'var(--se-glass-shadow)',
  },
  gateTitle: {
    fontSize: '1.75rem',
    fontWeight: 500,
    fontFamily: SE.fontSans,
    color: SE.text,
    letterSpacing: '-0.04em',
    textTransform: 'lowercase' as const,
    marginBottom: '10px',
    textShadow: '0 0 40px rgba(249, 168, 37, 0.18)',
  },
  gateSub: {
    fontSize: '0.95rem',
    fontFamily: SE.fontSans,
    fontWeight: 400,
    fontStyle: 'normal' as const,
    color: SE.muted,
    lineHeight: '1.5',
    marginBottom: '0',
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
    background: SE.surface,
    border: `1px solid ${SE.border}`,
    borderRadius: '12px',
    cursor: 'pointer',
    transition: 'all 0.3s ease',
    textAlign: 'center' as const,
  },
  doorTitle: {
    fontSize: '15px',
    fontWeight: 500,
    fontFamily: SE.fontSans,
    color: SE.accent,
    letterSpacing: '-0.02em',
    marginBottom: '8px',
  },
  doorDesc: {
    fontSize: '12px',
    fontFamily: SE.fontSans,
    fontWeight: 400,
    color: 'rgba(201, 162, 113, 0.7)',
    lineHeight: '1.6',
    maxWidth: '280px',
  },
  // --- Shared ---
  createPanel: {
    background: SE.surfaceSolid,
    backdropFilter: 'blur(20px)',
    border: `1px solid ${SE.borderLit}`,
    borderRadius: '16px',
    padding: '40px',
    maxWidth: '460px',
    width: '100%',
    boxShadow: 'var(--se-glass-shadow)',
  },
  backBtn: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    background: 'none',
    border: 'none',
    color: SE.dim,
    fontSize: '12px',
    cursor: 'pointer',
    padding: '0',
    marginBottom: '20px',
    fontFamily: SE.fontMono,
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
    margin: '0 auto 18px',
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
    fontSize: '1.35rem',
    fontWeight: 500,
    fontFamily: SE.fontSans,
    color: SE.text,
    letterSpacing: '-0.03em',
    marginBottom: '10px',
    textShadow: '0 0 30px rgba(249, 168, 37, 0.12)',
  },
  heroSub: {
    fontSize: '13px',
    fontFamily: SE.fontSans,
    fontWeight: 400,
    color: 'rgba(201, 162, 113, 0.75)',
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
    fontFamily: SE.fontSans,
    color: 'rgba(201, 162, 113, 0.55)',
    letterSpacing: '2px',
    textTransform: 'uppercase' as const,
    marginBottom: '8px',
    fontWeight: 400,
  },
  input: {
    width: '100%',
    background: SE.inputBg,
    border: `1px solid ${SE.border}`,
    borderRadius: '8px',
    padding: '12px 16px',
    color: SE.text,
    fontSize: '14px',
    fontFamily: SE.fontMono,
    outline: 'none',
    transition: 'border-color 0.3s',
    boxSizing: 'border-box' as const,
  },
  hint: {
    fontSize: '11px',
    color: SE.dim,
    marginTop: '6px',
  },
  primaryBtn: {
    width: '100%',
    background: 'rgba(249, 168, 37, 0.12)',
    border: '1px solid rgba(249, 168, 37, 0.35)',
    borderRadius: '8px',
    padding: '14px 20px',
    color: '#f9a825',
    fontSize: '12px',
    fontWeight: 500,
    fontFamily: "'Space Grotesk', system-ui, sans-serif",
    letterSpacing: '2px',
    textTransform: 'uppercase' as const,
    cursor: 'pointer',
    transition: 'all 0.3s',
    marginTop: '8px',
    boxShadow: '0 0 20px rgba(249, 168, 37, 0.06)',
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
    border: '1px solid rgba(249, 168, 37, 0.1)',
    borderRadius: '16px',
    padding: '32px',
    boxShadow: '0 4px 60px rgba(0, 0, 0, 0.5), 0 0 80px rgba(249, 168, 37, 0.03), inset 0 1px 0 rgba(255,255,255,0.03)',
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
    fontSize: '1.15rem',
    fontWeight: 500,
    fontFamily: SE.fontSans,
    color: SE.text,
    letterSpacing: '-0.02em',
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
    color: '#f9a825',
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
    background: 'rgba(249, 168, 37, 0.06)',
    border: '1px solid rgba(249, 168, 37, 0.15)',
    borderRadius: '10px',
    padding: '14px 20px',
    marginTop: '16px',
    fontSize: '13px',
    fontFamily: "'Space Grotesk', system-ui, sans-serif",
    color: '#f9a825',
    boxShadow: '0 0 30px rgba(249, 168, 37, 0.04)',
  },
};
