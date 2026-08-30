"use client";

// Export-behind-auth prompt (CUR-4 / L4) — Solar Ember glass.
// Re-enter unlock passphrase before private-key / vault / sensitive export.
// Crypto: verifyUnlockPassphrase → fleet initSessionKey + loadKey only.

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
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Eye, EyeOff, Lock, RefreshCw } from 'lucide-react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { verifyUnlockPassphrase } from './verifyUnlock';

export interface ExportAuthGateProps {
  open: boolean;
  fingerprint: string;
  /** What the user is about to export — shown in the body for honesty. */
  exportLabel: string;
  onClose: () => void;
  /** Called only after unlock passphrase verifies (or legacy plaintext skip). */
  onAuthenticated: () => void;
  /** Wrong attempt locked the session — parent should bounce to unlock screen. */
  onSessionLocked?: () => void;
}

export function ExportAuthGate({
  open,
  fingerprint,
  exportLabel,
  onClose,
  onAuthenticated,
  onSessionLocked,
}: ExportAuthGateProps) {
  const [passphrase, setPassphrase] = useState('');
  const [show, setShow] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reset = () => {
    setPassphrase('');
    setShow(false);
    setLoading(false);
    setError(null);
  };

  const handleClose = () => {
    reset();
    onClose();
  };

  const handleConfirm = async () => {
    if (!fingerprint) return;
    setLoading(true);
    setError(null);
    try {
      const result = await verifyUnlockPassphrase(fingerprint, passphrase);
      if (result === 'ok' || result === 'skipped-plaintext') {
        reset();
        onAuthenticated();
        return;
      }
      setError(
        result === 'no-keys'
          ? 'Could not decrypt keys with that passphrase.'
          : 'Incorrect unlock passphrase. Your session was locked for safety — unlock again to continue.',
      );
      onSessionLocked?.();
    } catch {
      setError('Could not verify unlock passphrase.');
      onSessionLocked?.();
    } finally {
      setLoading(false);
    }
  };

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
      >
        <DialogHeader>
          <DialogTitle
            className="flex items-center gap-2"
            style={{ color: E.text, fontFamily: E.fontSans }}
          >
            <Lock className="h-5 w-5" style={{ color: E.accent }} />
            Confirm it&apos;s you
          </DialogTitle>
          <DialogDescription style={{ color: E.muted }}>
            Before exporting <span style={{ color: E.text }}>{exportLabel}</span>,
            re-enter your unlock passphrase. This keeps a stolen unlocked session
            from quietly downloading your keys.
          </DialogDescription>
        </DialogHeader>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <div className="space-y-2 py-2">
          <Label htmlFor="export-auth-pass" style={{ color: E.muted }}>
            Unlock passphrase
          </Label>
          <div className="flex gap-2">
            <Input
              id="export-auth-pass"
              type={show ? 'text' : 'password'}
              value={passphrase}
              onChange={(e) => {
                setPassphrase(e.target.value);
                setError(null);
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && passphrase) void handleConfirm();
              }}
              placeholder="Your everyday unlock passphrase"
              autoFocus
              autoComplete="current-password"
              style={{
                background: E.inputBg,
                borderColor: E.border,
                color: E.text,
                fontFamily: E.fontSans,
              }}
            />
            <Button
              type="button"
              variant="outline"
              onClick={() => setShow(!show)}
              aria-label={show ? 'Hide passphrase' : 'Show passphrase'}
            >
              {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </Button>
          </div>
          <p className="text-xs" style={{ color: E.dim }}>
            Not your recovery phrase — the passphrase you use to unlock this device.
          </p>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={handleClose} disabled={loading}>
            Cancel
          </Button>
          <Button
            onClick={() => void handleConfirm()}
            disabled={loading || !passphrase}
            style={{
              background: 'color-mix(in srgb, var(--se-accent) 18%, transparent)',
              color: E.accent,
              border: `1px solid ${E.borderLit}`,
              fontFamily: E.fontSans,
              opacity: loading || !passphrase ? 0.5 : 1,
            }}
          >
            {loading ? (
              <>
                <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                Checking…
              </>
            ) : (
              'Continue'
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
