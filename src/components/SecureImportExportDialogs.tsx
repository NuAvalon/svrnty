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
  const [usePassword, setUsePassword] = useState(false);
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [exportedData, setExportedData] = useState<string | null>(null);
  const [exportComplete, setExportComplete] = useState(false);
  
  const handleExport = async () => {
    if (!identityFingerprint) return;
    
    try {
      setLoading(true);
      setError(null);
      
      // Build the query parameters
      const params = new URLSearchParams();
      params.append('fingerprint', identityFingerprint);
      params.append('includePublicKeys', includePublicKeys.toString());
      params.append('usePassword', usePassword.toString());
      
      if (usePassword && password) {
        params.append('password', password);
      }
      
      // Call the secure export API
      const response = await fetch(`/api/contacts/secure-export?${params.toString()}`, {
        method: 'GET'
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to export contacts');
      }
      
      // Store the exported data
      setExportedData(data.encryptedContacts);
      setExportComplete(true);
      
      // Call the completion callback if provided
      if (onExportComplete) {
        onExportComplete(data.encryptedContacts, data.encryptionMethod);
      }
      
    } catch (err) {
      console.error('Error exporting contacts:', err);
      setError(err instanceof Error ? err.message : 'An error occurred');
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
      // Create a blob and download link
      const blob = new Blob([exportedData], { type: 'application/pgp-encrypted' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `soverentity-contacts-${new Date().toISOString().split('T')[0]}.pgp`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    }
  };
  
  const handleClose = () => {
    // Reset the state
    setExportedData(null);
    setExportComplete(false);
    setUsePassword(false);
    setPassword('');
    setIncludePublicKeys(true);
    setError(null);
    
    // Call the close callback
    onClose();
  };
  
  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Secure Contact Export</DialogTitle>
          <DialogDescription>
            Export your contacts with encryption for secure backup or transfer.
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
            
            <div className="flex items-center space-x-2">
              <Checkbox 
                id="usePassword"
                checked={usePassword}
                onCheckedChange={(checked) => setUsePassword(checked === true)}
              />
              <Label htmlFor="usePassword">Password-protect export</Label>
            </div>
            
            {usePassword && (
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <div className="flex">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter secure password"
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
                  Choose a strong password you can remember. This password will be needed to import these contacts.
                </p>
              </div>
            )}
          </div>
        ) : (
          <div className="space-y-4 py-4">
            <Alert className="bg-green-50 dark:bg-green-900/20 border-green-100 dark:border-green-900">
              <Lock className="h-4 w-4 text-green-600 dark:text-green-500" />
              <AlertDescription className="text-green-800 dark:text-green-300">
                Your contacts have been successfully exported with encryption.
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
            
            {usePassword && (
              <Alert>
                <AlertTitle>Password Protection</AlertTitle>
                <AlertDescription>
                  You will need the password <span className="font-medium">{password}</span> to import these contacts.
                  Please save it securely.
                </AlertDescription>
              </Alert>
            )}
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
              disabled={loading || (usePassword && !password)}
              className="bg-blue-600 hover:bg-blue-700"
            >
              {loading ? 
                <><RefreshCw className="h-4 w-4 mr-2 animate-spin" />Exporting...</> : 
                <><Lock className="h-4 w-4 mr-2" />Secure Export</>
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
  const passwordValid = password.length >= 8;

  const handleExport = async () => {
    if (!identityFingerprint || !passwordValid || !passwordsMatch) return;

    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/keys/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fingerprint: identityFingerprint, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to export keys');
      }

      // Download as .svrnty-keys file
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `soverentity-keys-${new Date().toISOString().split('T')[0]}.svrnty-keys`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);

      setExportComplete(true);
    } catch (err) {
      console.error('Key export error:', err);
      setError(err instanceof Error ? err.message : 'An error occurred');
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
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Key className="h-5 w-5" />
            Download Private Key
          </DialogTitle>
          <DialogDescription>
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
            <Alert className="bg-amber-50 dark:bg-amber-900/20 border-amber-200 dark:border-amber-800">
              <ShieldCheck className="h-4 w-4 text-amber-600 dark:text-amber-400" />
              <AlertDescription className="text-amber-800 dark:text-amber-300 text-sm">
                Your private key will be encrypted with AES-256-GCM using your password. Without this password, the file cannot be decrypted.
              </AlertDescription>
            </Alert>

            <div className="space-y-2">
              <Label htmlFor="keyPassword">Password (minimum 8 characters)</Label>
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
              <Label htmlFor="confirmKeyPassword">Confirm Password</Label>
              <Input
                id="confirmKeyPassword"
                type={showPassword ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm your password"
              />
              {confirmPassword && !passwordsMatch && (
                <p className="text-xs text-red-500">Passwords do not match</p>
              )}
            </div>
          </div>
        ) : (
          <div className="space-y-4 py-4">
            <Alert className="bg-green-50 dark:bg-green-900/20 border-green-100 dark:border-green-900">
              <Lock className="h-4 w-4 text-green-600 dark:text-green-500" />
              <AlertDescription className="text-green-800 dark:text-green-300">
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
              className="bg-blue-600 hover:bg-blue-700"
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
  
  const checkIfNeedsPassword = (data: string) => {
    // This is a best-effort detection of password-encrypted data
    const isPgpMessage = data.includes('-----BEGIN PGP MESSAGE-----');
    if (isPgpMessage) {
      // These are not foolproof, but can help detect password-encrypted content
      const hints = ['PASSPHRASE', 'SYMMETRIC', 'PASSWORD'];
      const mightNeedPassword = hints.some(hint => data.includes(hint));
      setNeedsPassword(mightNeedPassword);
    } else {
      setNeedsPassword(false);
    }
  };
  
  const handleImport = async () => {
    if (!identityFingerprint || !importData) return;
    
    try {
      setLoading(true);
      setError(null);
      
      // Call the secure import API
      const response = await fetch('/api/contacts/secure-import', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fingerprint: identityFingerprint,
          encryptedContacts: importData,
          overwrite,
          password: needsPassword ? password : null
        }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to import contacts');
      }
      
      // Store the import count
      setImportCount(data.importCount);
      setImportComplete(true);
      
      // Call the completion callback if provided
      if (onImportComplete) {
        onImportComplete(data.importCount);
      }
      
    } catch (err) {
      console.error('Error importing contacts:', err);
      
      // If it's a decryption error, we might need a password
      const errorMessage = err instanceof Error ? err.message : 'An error occurred';
      
      if (errorMessage.includes('decrypt') || errorMessage.includes('password')) {
        setNeedsPassword(true);
      }
      
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };
  
  const handleClose = () => {
    // Reset the state
    setImportData('');
    setPassword('');
    setOverwrite(false);
    setNeedsPassword(false);
    setImportComplete(false);
    setImportCount(0);
    setError(null);
    
    // Call the close callback
    onClose();
  };
  
  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Secure Contact Import</DialogTitle>
          <DialogDescription>
            Import contacts from an encrypted export.
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
              className="bg-blue-600 hover:bg-blue-700"
            >
              {loading ? 
                <><RefreshCw className="h-4 w-4 mr-2 animate-spin" />Importing...</> : 
                <><Upload className="h-4 w-4 mr-2" />Secure Import</>
              }
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}