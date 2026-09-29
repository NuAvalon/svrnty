"use client";

// CUR-4 · L4 vault export UI — Solar Ember.
// Fleet crypto only: createVaultContents + packVault + downloadVault.
// ⛔ Does NOT invent KDF/encrypt — packVault is team-owned (v4 dual-envelope).

import React, { useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Download, Eye, EyeOff, RefreshCw, ShieldCheck } from 'lucide-react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { ExportAuthGate } from './ExportAuthGate';
import { MIN_PASSPHRASE_LENGTH } from '@/lib/crypto/kdf';

export interface VaultExportDialogProps {
  open: boolean;
  onClose: () => void;
  fingerprint: string;
  /** Bounce to lock screen if auth gate locks the session. */
  onSessionLocked?: () => void;
}

type Step = 'auth' | 'passphrase' | 'done';

export function VaultExportDialog({
  open,
  onClose,
  fingerprint,
  onSessionLocked,
}: VaultExportDialogProps) {
  const [step, setStep] = useState<Step>('auth');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [show, setShow] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const match = password === confirm;
  const strongEnough = password.length >= MIN_PASSPHRASE_LENGTH;

  const reset = () => {
    setStep('auth');
    setPassword('');
    setConfirm('');
    setShow(false);
    setLoading(false);
    setError(null);
  };

  const handleClose = () => {
    reset();
    onClose();
  };

  const handleExport = async () => {
    if (!fingerprint || !strongEnough || !match) return;
    setLoading(true);
    setError(null);
    try {
      const { exportAll, loadPQKeys, loadVault } = await import(
        '@/lib/identity/client-store'
      );
      const backup = await exportAll(fingerprint, true);
      const pqKeys = await loadPQKeys(fingerprint);
      const vaultData = await loadVault(fingerprint);

      const vaultKeys = {
        classical: backup.keys || { privateKey: '', passphrase: '' },
        pq: pqKeys || null,
      };

      // Same loose graph shape ContactManagement already packs — fleet packVault
      // reads identity/keys/recovery; graph edges are carried for restore fidelity.
      const trustGraph = {
        edges: backup.contacts.map((c: any) => ({
          source: fingerprint,
          target: c.fingerprint,
          trust_level: c.trust_level || 'unverified',
          added_at: c.added_at,
          metadata: {
            name: c.name,
            email: c.email,
            public_key: c.public_key,
            ...c.metadata,
          },
        })),
        contacts: backup.contacts,
      };

      const { createVaultContents, packVault, downloadVault } = await import(
        '@/lib/sync/vault'
      );
      const contents = createVaultContents(
        backup.identity,
        vaultKeys,
        trustGraph as any,
        { safeWord: '' },
        vaultData || null,
      );
      const packed = await packVault(contents, password);
      downloadVault(packed);
      setStep('done');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Vault export failed');
    } finally {
      setLoading(false);
    }
  };

  if (!open) return null;

  // Step 1 — export-behind-auth
  if (step === 'auth') {
    return (
      <ExportAuthGate
        open={open}
        fingerprint={fingerprint}
        exportLabel="your full identity vault (.svrnty)"
        onClose={handleClose}
        onAuthenticated={() => setStep('passphrase')}
        onSessionLocked={onSessionLocked}
      />
    );
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) handleClose();
      }}
    >
      <DialogContent
        className="sm:max-w-md"
        style={{
          background: E.surfaceSolid,
          color: E.text,
          border: `1px solid ${E.border}`,
          fontFamily: E.fontSans,
        }}
        data-testid="vault-export-dialog"
      >
        <DialogHeader>
          <DialogTitle style={{ color: E.text, fontFamily: E.fontSans }}>
            {step === 'done' ? 'Vault downloaded' : 'Encrypt your vault'}
          </DialogTitle>
          <DialogDescription style={{ color: E.muted }}>
            {step === 'done'
              ? 'Store the .svrnty file somewhere safe. Restore needs this encryption password (or your recovery code for password-free recovery on v4).'
              : 'Choose an encryption password (12+ characters). This protects keys, contacts, and trust — remember it for restore. It is not your recovery code.'}
          </DialogDescription>
        </DialogHeader>

        {error && (
          <Alert variant="destructive">
            <AlertTitle>Export failed</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {step === 'passphrase' && (
          <div className="space-y-4 py-2">
            <Alert
              style={{
                background: 'color-mix(in srgb, var(--se-accent) 10%, var(--se-surface-solid))',
                borderColor: E.borderLit,
              }}
            >
              <ShieldCheck className="h-4 w-4" style={{ color: E.accent }} />
              <AlertDescription className="text-sm" style={{ color: E.text }}>
                Encryption uses the fleet vault packer (Argon2id · AES-256-GCM · v4).
                Without this encryption password, the daily body of the file cannot open.
              </AlertDescription>
            </Alert>

            <div className="space-y-2">
              <Label htmlFor="vault-export-pass" style={{ color: E.muted }}>
                Encryption password (min {MIN_PASSPHRASE_LENGTH})
              </Label>
              <div className="flex gap-2">
                <Input
                  id="vault-export-pass"
                  type={show ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={`At least ${MIN_PASSPHRASE_LENGTH} characters`}
                  autoFocus
                  data-testid="vault-export-passphrase"
                  style={{
                    background: E.inputBg,
                    borderColor: E.border,
                    color: E.text,
                  }}
                />
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setShow(!show)}
                  aria-label={show ? 'Hide' : 'Show'}
                >
                  {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="vault-export-confirm" style={{ color: E.muted }}>
                Confirm encryption password
              </Label>
              <Input
                id="vault-export-confirm"
                type={show ? 'text' : 'password'}
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                placeholder="Confirm encryption password"
                data-testid="vault-export-confirm"
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && strongEnough && match) void handleExport();
                }}
                style={{
                  background: E.inputBg,
                  borderColor: E.border,
                  color: E.text,
                }}
              />
              {confirm && !match && (
                <p className="text-xs" style={{ color: E.danger }}>
                  Passwords do not match
                </p>
              )}
            </div>
          </div>
        )}

        {step === 'done' && (
          <Alert
            style={{
              background: 'color-mix(in srgb, var(--se-ok) 12%, var(--se-surface-solid))',
              borderColor: E.border,
            }}
          >
            <Download className="h-4 w-4" style={{ color: E.ok }} />
            <AlertDescription style={{ color: E.text }}>
              Your encrypted vault downloaded. Remember this encryption password —
              and keep your recovery code somewhere you&apos;ll still have if you lose it.
            </AlertDescription>
          </Alert>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={handleClose}>
            {step === 'done' ? 'Close' : 'Cancel'}
          </Button>
          {step === 'passphrase' && (
            <Button
              id="fullBackupBtn"
              data-testid="vault-export-download"
              onClick={() => void handleExport()}
              disabled={loading || !strongEnough || !match}
              style={{
                background: 'color-mix(in srgb, var(--se-accent) 18%, transparent)',
                color: E.accent,
                border: `1px solid ${E.borderLit}`,
                opacity: loading || !strongEnough || !match ? 0.5 : 1,
                fontFamily: E.fontSans,
              }}
            >
              {loading ? (
                <>
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                  Encrypting…
                </>
              ) : (
                <>
                  <Download className="h-4 w-4 mr-2" />
                  Download encrypted vault
                </>
              )}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
