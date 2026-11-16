// src/components/SecureImportExportDialogs.tsx
"use client";

import React, { useState } from 'react';
import {
  Dialog, DialogContent, DialogDescription, DialogHeader,
  DialogTitle, DialogFooter
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import {
  Checkbox
} from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { RefreshCw, Lock, Download, Upload, Copy, Eye, EyeOff, Key, ShieldCheck } from 'lucide-react';
import { Textarea } from '@/components/ui/textarea';
import {
  getAllContacts,
  addContact,
  loadKey,
  loadPQKeys,
} from '@/lib/identity/client-store';
import { contactsEncryptedExportFilename } from '@/components/export/contacts-export-name';
import { sealWithPassword, openWithPassword, LEGACY_PASSWORD_METHOD_NOTICE, MIN_EXPORT_PASSWORD_LENGTH } from '@/lib/crypto/password-envelope';
import { ContactIoRefused, errorTag, exportFailureMessage, importFailureView, keyExportFailureMessage } from '@/lib/contacts/contact-io-errors';

// ── Helpers ────────────────────────────────────────────

// ── Secure Export Dialog ────────────────────────────────

interface SecureExportDialogProps {
  open: boolean;
  onClose: () => void;
  identityFingerprint: string;
  onExportComplete?: (exportedData: string, encryptionMethod: string) => void;
}

export function SecureExportDialog({
  open,
  onClose,
  identityFingerprint,
  onExportComplete
}: SecureExportDialogProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [includePublicKeys, setIncludePublicKeys] = useState(true);
  // CUR-4: password protection is REQUIRED — no plaintext contacts export.
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [exportedData, setExportedData] = useState<string | null>(null);
  const [exportComplete, setExportComplete] = useState(false);

  const handleExport = async () => {
    if (!identityFingerprint) return;

    try {
      setLoading(true);
      setError(null);

      // Read contacts from IndexedDB
      const contacts = await getAllContacts(identityFingerprint);

      const exportPayload = contacts.map((c: any) => {
        const base: any = {
          id: c.id,
          fingerprint: c.fingerprint,
          name: c.name,
          email: c.email,
          trust_level: c.trust_level,
          added_at: c.added_at,
        };
        if (includePublicKeys && c.public_key) {
          base.public_key = c.public_key;
          // A contact's fingerprint is bound to ALL its public keys, so a file without the post-quantum keys cannot be imported back (the store refuses every
          // key-bound contact). They are public, and the plain contact-book export writes them too.
          if (c.pq_kem_public_key) base.pq_kem_public_key = c.pq_kem_public_key;
          if (c.pq_sig_public_key) base.pq_sig_public_key = c.pq_sig_public_key;
        }
        return base;
      });

      const jsonStr = JSON.stringify({
        version: '1.0',
        exported_at: new Date().toISOString(),
        owner_fingerprint: identityFingerprint,
        contacts: exportPayload,
      }, null, 2);

      let result: string;
      let method: string;

      if (!password || password.length < MIN_EXPORT_PASSWORD_LENGTH) {
        throw new ContactIoRefused('export-password-short');
      }

      // Encrypt with AES-256-GCM, the key derived from the password with Argon2id (the one derivation path, kdf.ts). Older exports used a weaker password
      // method; those files are still READ (openWithPassword) and never written.
      const sealed = await sealWithPassword(new TextEncoder().encode(jsonStr), password);
      result = JSON.stringify({ encrypted: true, ...sealed });
      method = 'AES-256-GCM';

      setExportedData(result);
      setExportComplete(true);

      if (onExportComplete) {
        onExportComplete(result, method);
      }

    } catch (err) {
      console.error('Error exporting contacts:', errorTag(err));
      setError(exportFailureMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const handleCopyToClipboard = () => {
    if (exportedData) {
      navigator.clipboard.writeText(exportedData);
    }
  };

  const handleDownload = () => {
    if (exportedData) {
      const blob = new Blob([exportedData], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      // Not bare `.svrnty` — that is the identity vault. See contacts-export-name.ts.
      a.download = contactsEncryptedExportFilename();
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    }
  };

  const handleClose = () => {
    setExportedData(null);
    setExportComplete(false);
    setPassword('');
    setIncludePublicKeys(true);
    setError(null);
    onClose();
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-md bg-[var(--se-surface-solid)] text-[var(--se-text)] border-[var(--se-border)]">
        <DialogHeader>
          <DialogTitle className="text-[var(--se-text)]">Export contacts</DialogTitle>
          <DialogDescription className="text-[var(--se-muted)]">
            Password-protected contacts only — not your identity vault. For keys + contacts + trust, use Full Backup (.svrnty).
          </DialogDescription>
        </DialogHeader>

        {error && (
          <Alert variant="destructive" className="mb-4">
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {!exportComplete ? (
          <div className="space-y-4 py-4">
            <div className="flex items-center space-x-2">
              <Checkbox
                id="includePublicKeys"
                checked={includePublicKeys}
                onCheckedChange={(checked) => setIncludePublicKeys(checked === true)}
              />
              <Label htmlFor="includePublicKeys">Include public keys</Label>
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Export password (required)</Label>
              <div className="flex">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={`At least ${MIN_EXPORT_PASSWORD_LENGTH} characters`}
                  className="flex-1"
                />
                <Button
                  variant="outline"
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="ml-2"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
              </div>
              <p className="text-xs text-[var(--se-dim)]">
                You will need this password to import these contacts. This file cannot restore your identity.
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-4 py-4">
            <Alert className="bg-[color-mix(in_srgb,var(--se-ok)_12%,var(--se-surface-solid))] border-[var(--se-border)]">
              <Lock className="h-4 w-4 text-[var(--se-ok)]" />
              <AlertDescription className="text-[var(--se-text)]">
                Your contacts have been exported with password protection.
              </AlertDescription>
            </Alert>

            <div className="space-y-2">
              <Label>Encrypted Data</Label>
              <Textarea
                value={exportedData || ''}
                readOnly
                className="font-mono text-xs h-32"
              />
              <div className="flex space-x-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleCopyToClipboard}
                  className="flex-1"
                >
                  <Copy className="h-4 w-4 mr-2" />
                  Copy to Clipboard
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleDownload}
                  className="flex-1"
                >
                  <Download className="h-4 w-4 mr-2" />
                  Download File
                </Button>
              </div>
            </div>

            <Alert>
              <AlertTitle>Password Protection</AlertTitle>
              <AlertDescription>
                You will need the export password to import these contacts. Save it securely — it is not shown again after you close this dialog.
              </AlertDescription>
            </Alert>
          </div>
        )}

        <DialogFooter>
          <Button
            variant="outline"
            onClick={handleClose}
          >
            {exportComplete ? 'Close' : 'Cancel'}
          </Button>

          {!exportComplete && (
            <Button
              onClick={handleExport}
              disabled={loading || password.length < MIN_EXPORT_PASSWORD_LENGTH}
              className="bg-[color-mix(in_srgb,var(--se-accent)_18%,transparent)] hover:bg-[color-mix(in_srgb,var(--se-accent)_28%,transparent)] text-[var(--se-accent)] border border-[var(--se-border-lit)]"
            >
              {loading ?
                <><RefreshCw className="h-4 w-4 mr-2 animate-spin" />Exporting...</> :
                <><Lock className="h-4 w-4 mr-2" />Export contacts</>
              }
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Private Key Export Dialog ────────────────────────────

interface PrivateKeyExportDialogProps {
  open: boolean;
  onClose: () => void;
  identityFingerprint: string;
}

export function PrivateKeyExportDialog({
  open,
  onClose,
  identityFingerprint,
}: PrivateKeyExportDialogProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [exportComplete, setExportComplete] = useState(false);

  const passwordsMatch = password === confirmPassword;
  const passwordValid = password.length >= MIN_EXPORT_PASSWORD_LENGTH;

  const handleExport = async () => {
    if (!identityFingerprint || !passwordValid || !passwordsMatch) return;

    try {
      setLoading(true);
      setError(null);

      // Read key from IndexedDB
      const keyData = await loadKey(identityFingerprint);
      if (!keyData) throw new ContactIoRefused('private-key-missing');

      const pqKeys = await loadPQKeys(identityFingerprint);

      // Encrypt with the password (AES-256-GCM, Argon2id-derived key)
      const payload = JSON.stringify({
        fingerprint: identityFingerprint,
        privateKey: keyData.privateKey,
        passphrase: keyData.passphrase,
        pq_keys: pqKeys || undefined,
        exported_at: new Date().toISOString(),
      });
      const sealed = await sealWithPassword(new TextEncoder().encode(payload), password);

      const exportFile = JSON.stringify({
        version: '1.0',
        type: 'svrnty-keys',
        ...sealed,
        fingerprint: identityFingerprint,
      }, null, 2);

      // Download as .svrnty-keys file
      const blob = new Blob([exportFile], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `svrnty-keys-${new Date().toISOString().split('T')[0]}.svrnty-keys`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);

      setExportComplete(true);
    } catch (err) {
      console.error('Key export error:', errorTag(err));
      setError(keyExportFailureMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setPassword('');
    setConfirmPassword('');
    setExportComplete(false);
    setError(null);
    onClose();
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-md bg-[var(--se-surface-solid)] text-[var(--se-text)] border-[var(--se-border)]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-[var(--se-text)]">
            <Key className="h-5 w-5 text-[var(--se-accent)]" />
            Download Private Key
          </DialogTitle>
          <DialogDescription className="text-[var(--se-muted)]">
            Export your private key as a password-protected file. Store it securely — this file can access your identity.
          </DialogDescription>
        </DialogHeader>

        {error && (
          <Alert variant="destructive" className="mb-4">
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {!exportComplete ? (
          <div className="space-y-4 py-4">
            <Alert className="bg-[color-mix(in_srgb,var(--se-accent)_10%,var(--se-surface-solid))] border-[var(--se-border-lit)]">
              <ShieldCheck className="h-4 w-4 text-[var(--se-accent)]" />
              <AlertDescription className="text-[var(--se-text)] text-sm">
                Your private key will be encrypted with AES-256-GCM using your password. Without this password, the file cannot be decrypted.
              </AlertDescription>
            </Alert>

            <div className="space-y-2">
              <Label htmlFor="keyPassword" className="text-[var(--se-muted)]">{`Password (minimum ${MIN_EXPORT_PASSWORD_LENGTH} characters)`}</Label>
              <div className="flex">
                <Input
                  id="keyPassword"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter a strong password"
                  className="flex-1"
                />
                <Button
                  variant="outline"
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="ml-2"
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </Button>
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirmKeyPassword" className="text-[var(--se-muted)]">Confirm Password</Label>
              <Input
                id="confirmKeyPassword"
                type={showPassword ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm your password"
              />
              {confirmPassword && !passwordsMatch && (
                <p className="text-xs text-[var(--se-danger)]">Passwords do not match</p>
              )}
            </div>
          </div>
        ) : (
          <div className="space-y-4 py-4">
            <Alert className="bg-[color-mix(in_srgb,var(--se-ok)_12%,var(--se-surface-solid))] border-[var(--se-border)]">
              <Lock className="h-4 w-4 text-[var(--se-ok)]" />
              <AlertDescription className="text-[var(--se-text)]">
                Your private key has been downloaded as a password-protected file. Store it in a secure location and remember your password.
              </AlertDescription>
            </Alert>
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={handleClose}>
            {exportComplete ? 'Close' : 'Cancel'}
          </Button>

          {!exportComplete && (
            <Button
              onClick={handleExport}
              disabled={loading || !passwordValid || !passwordsMatch}
              className="bg-[color-mix(in_srgb,var(--se-accent)_18%,transparent)] hover:bg-[color-mix(in_srgb,var(--se-accent)_28%,transparent)] text-[var(--se-accent)] border border-[var(--se-border-lit)]"
            >
              {loading ? (
                <>
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                  Encrypting...
                </>
              ) : (
                <>
                  <Download className="h-4 w-4 mr-2" />
                  Download Encrypted Key
                </>
              )}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Secure Import Dialog ────────────────────────────────

interface SecureImportDialogProps {
  open: boolean;
  onClose: () => void;
  identityFingerprint: string;
  onImportComplete?: (importCount: number) => void;
}

export function SecureImportDialog({
  open,
  onClose,
  identityFingerprint,
  onImportComplete
}: SecureImportDialogProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [importData, setImportData] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [overwrite, setOverwrite] = useState(false);
  const [needsPassword, setNeedsPassword] = useState(false);
  const [importComplete, setImportComplete] = useState(false);
  const [importCount, setImportCount] = useState(0);
  const [legacyNotice, setLegacyNotice] = useState(false);

  const checkIfNeedsPassword = (data: string) => {
    try {
      const parsed = JSON.parse(data);
      setNeedsPassword(!!parsed.encrypted);
    } catch {
      setNeedsPassword(false);
    }
  };

  const handleImport = async () => {
    if (!identityFingerprint || !importData) return;

    try {
      setLoading(true);
      setError(null);

      let contactsJson: string;
      let legacyOpened = false;

      // Check if data is encrypted
      const parsed = JSON.parse(importData);
      if (parsed.encrypted) {
        if (!password) {
          setNeedsPassword(true);
          throw new ContactIoRefused('import-password-required');
        }
        // Decrypt: the file's own tag picks the derivation (Argon2id, or the older method for files already held)
        const opened = await openWithPassword(parsed, password);
        contactsJson = new TextDecoder().decode(opened.plaintext);
        legacyOpened = opened.legacy;
      } else {
        contactsJson = importData;
      }

      const exportData = JSON.parse(contactsJson);
      const contacts = exportData.contacts || [];

      // Import contacts into IndexedDB
      let count = 0;
      for (const contact of contacts) {
        await addContact(identityFingerprint, {
          fingerprint: contact.fingerprint || contact.peer_fingerprint || '',
          name: contact.name || contact.peer_name || '',
          email: contact.email || contact.peer_email || '',
          public_key: contact.public_key || contact.peer_public_key || '',
          trust_level: contact.trust_level || 'unknown',
        });
        count++;
      }

      setImportCount(count);
      setLegacyNotice(legacyOpened);
      setImportComplete(true);

      if (onImportComplete) {
        onImportComplete(count);
      }

    } catch (err) {
      console.error('Error importing contacts:', errorTag(err));
      const view = importFailureView(err);                              // the sentence and the password prompt both come from the error's type/code
      if (view.needsPassword) setNeedsPassword(true);
      setError(view.message);
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setImportData('');
    setPassword('');
    setOverwrite(false);
    setNeedsPassword(false);
    setImportComplete(false);
    setImportCount(0);
    setLegacyNotice(false);
    setError(null);
    onClose();
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-md bg-[var(--se-surface-solid)] text-[var(--se-text)] border-[var(--se-border)]">
        <DialogHeader>
          <DialogTitle className="text-[var(--se-text)]">Import contacts</DialogTitle>
          <DialogDescription className="text-[var(--se-muted)]">
            Import contacts from a password-protected contacts export (not an identity vault).
          </DialogDescription>
        </DialogHeader>

        {error && (
          <Alert variant="destructive" className="mb-4">
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {!importComplete ? (
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="importData">Encrypted Contact Data</Label>
              <Textarea
                id="importData"
                value={importData}
                onChange={(e) => {
                  setImportData(e.target.value);
                  checkIfNeedsPassword(e.target.value);
                }}
                placeholder="Paste the encrypted contact data here..."
                className="font-mono text-xs"
                rows={8}
              />
            </div>

            {needsPassword && (
              <div className="space-y-2">
                <Label htmlFor="importPassword">Decryption Password</Label>
                <div className="flex">
                  <Input
                    id="importPassword"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter the export password"
                    className="flex-1"
                  />
                  <Button
                    variant="outline"
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="ml-2"
                  >
                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </Button>
                </div>
                <p className="text-xs text-slate-500">
                  This export was password-protected. Enter the password used during export.
                </p>
              </div>
            )}

            <div className="flex items-center space-x-2">
              <Checkbox
                id="overwrite"
                checked={overwrite}
                onCheckedChange={(checked) => setOverwrite(checked === true)}
              />
              <Label htmlFor="overwrite">Overwrite existing contacts</Label>
            </div>
          </div>
        ) : (
          <div className="space-y-4 py-4">
            <Alert className="bg-green-50 dark:bg-green-900/20 border-green-100 dark:border-green-900">
              <Upload className="h-4 w-4 text-green-600 dark:text-green-500" />
              <AlertDescription className="text-green-800 dark:text-green-300">
                Successfully imported {importCount} contacts.
              </AlertDescription>
            </Alert>
            {legacyNotice && (
              <Alert data-testid="legacy-password-method-notice">
                <AlertDescription>{LEGACY_PASSWORD_METHOD_NOTICE}</AlertDescription>
              </Alert>
            )}
          </div>
        )}

        <DialogFooter>
          <Button
            variant="outline"
            onClick={handleClose}
          >
            {importComplete ? 'Close' : 'Cancel'}
          </Button>

          {!importComplete && (
            <Button
              onClick={handleImport}
              disabled={loading || !importData || (needsPassword && !password)}
              className="bg-[color-mix(in_srgb,var(--se-accent)_18%,transparent)] hover:bg-[color-mix(in_srgb,var(--se-accent)_28%,transparent)] text-[var(--se-accent)] border border-[var(--se-border-lit)]"
            >
              {loading ?
                <><RefreshCw className="h-4 w-4 mr-2 animate-spin" />Importing...</> :
                <><Upload className="h-4 w-4 mr-2" />Import contacts</>
              }
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
