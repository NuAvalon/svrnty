"use client";

import React, { useState } from 'react';
import { 
  Dialog, DialogContent, DialogDescription, DialogHeader,
  DialogTitle, DialogFooter 
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Shield, Lock, Key, Download, Upload, RefreshCw, 
  CheckCircle, AlertTriangle, Eye, EyeOff 
} from 'lucide-react';

interface SecureExportDialogProps {
  open: boolean;
  onClose: () => void;
  identityFingerprint: string;
  onExportComplete?: (exportedData: string, encryptionMethod: string) => void;
}

interface SecureImportDialogProps {
  open: boolean;
  onClose: () => void;
  identityFingerprint: string;
  onImportComplete?: (importCount: number) => void;
}

export function SecureExportDialog({ 
  open, 
  onClose, 
  identityFingerprint, 
  onExportComplete 
}: SecureExportDialogProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exportedData, setExportedData] = useState('');
  const [encryptionMethod, setEncryptionMethod] = useState<'pgp' | 'password'>('pgp');
  const [password, setPassword] = useState('');
  const [includePublicKeys, setIncludePublicKeys] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [exportComplete, setExportComplete] = useState(false);

  const handleExport = async () => {
    if (!identityFingerprint) {
      setError('No identity fingerprint available');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const params = new URLSearchParams({
        fingerprint: identityFingerprint,
        includePublicKeys: includePublicKeys.toString(),
        usePassword: (encryptionMethod === 'password').toString(),
        ...(encryptionMethod === 'password' && password && { password })
      });

      const response = await fetch(`/api/contacts/secure-export?${params}`, {
        method: 'GET'
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to export contacts');
      }

      setExportedData(data.encryptedContacts);
      setExportComplete(true);
      
      if (onExportComplete) {
        onExportComplete(data.encryptedContacts, data.encryptionMethod);
      }

    } catch (err) {
      console.error('Export error:', err);
      setError(err instanceof Error ? err.message : 'Export failed');
    } finally {
      setLoading(false);
    }
  };

  const downloadExportedData = () => {
    if (!exportedData) return;

    const blob = new Blob([exportedData], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soverentity-contacts-encrypted-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const handleClose = () => {
    setExportedData('');
    setExportComplete(false);
    setError(null);
    setPassword('');
    onClose();
  };

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-green-600" />
            Secure Export
          </DialogTitle>
          <DialogDescription>
            Export your contacts with encryption for secure backup.
          </DialogDescription>
        </DialogHeader>

        {error && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Export Failed</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {!exportComplete ? (
          <div className="space-y-4 py-4">
            <Tabs value={encryptionMethod} onValueChange={(value) => setEncryptionMethod(value as 'pgp' | 'password')}>
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="pgp">PGP Encryption</TabsTrigger>
                <TabsTrigger value="password">Password Protection</TabsTrigger>
              </TabsList>
              
              <TabsContent value="pgp" className="space-y-4">
                <div className="flex items-center gap-2 p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
                  <Key className="h-4 w-4 text-green-600" />
                  <span className="text-sm text-green-800 dark:text-green-300">
                    Encrypted with your PGP key
                  </span>
                </div>
              </TabsContent>
              
              <TabsContent value="password" className="space-y-4">
                <div className="grid w-full items-center gap-1.5">
                  <label className="text-sm font-medium">Encryption Password</label>
                  <div className="relative">
                    <Input
                      type={showPassword ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Enter a strong password"
                      className="pr-10"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                      onClick={() => setShowPassword(!showPassword)}
                    >
                      {showPassword ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </div>
              </TabsContent>
            </Tabs>

            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="includePublicKeys"
                checked={includePublicKeys}
                onChange={(e) => setIncludePublicKeys(e.target.checked)}
                className="rounded border-gray-300"
              />
              <label htmlFor="includePublicKeys" className="text-sm">
                Include public keys in export
              </label>
            </div>
          </div>
        ) : (
          <div className="space-y-4 py-4">
            <div className="flex items-center gap-2 p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
              <CheckCircle className="h-4 w-4 text-green-600" />
              <span className="text-sm text-green-800 dark:text-green-300">
                Export completed successfully
              </span>
            </div>
            
            <Textarea
              value={exportedData}
              readOnly
              className="font-mono text-xs h-32"
              placeholder="Encrypted contact data will appear here..."
            />
            
            <Alert>
              <Lock className="h-4 w-4" />
              <AlertDescription>
                This encrypted data contains your contacts. Keep it secure and only import it into trusted applications.
              </AlertDescription>
            </Alert>
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={handleClose}>
            {exportComplete ? 'Close' : 'Cancel'}
          </Button>
          
          {!exportComplete ? (
            <Button 
              onClick={handleExport} 
              disabled={loading || (encryptionMethod === 'password' && !password)}
              className="bg-green-600 hover:bg-green-700"
            >
              {loading ? (
                <>
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                  Encrypting...
                </>
              ) : (
                <>
                  <Shield className="h-4 w-4 mr-2" />
                  Export Securely
                </>
              )}
            </Button>
          ) : (
            <Button 
              onClick={downloadExportedData}
              className="bg-blue-600 hover:bg-blue-700"
            >
              <Download className="h-4 w-4 mr-2" />
              Download File
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function SecureImportDialog({ 
  open, 
  onClose, 
  identityFingerprint, 
  onImportComplete 
}: SecureImportDialogProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [encryptedData, setEncryptedData] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [overwrite, setOverwrite] = useState(false);
  const [importResult, setImportResult] = useState<{
    success: boolean;
    count: number;
    method: string;
  } | null>(null);

  const handleImport = async () => {
    if (!identityFingerprint) {
      setError('No identity fingerprint available');
      return;
    }

    if (!encryptedData.trim()) {
      setError('Please paste the encrypted contact data');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/contacts/secure-import', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fingerprint: identityFingerprint,
          encryptedContacts: encryptedData,
          overwrite,
          password: password || null
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to import contacts');
      }

      setImportResult({
        success: true,
        count: data.importCount || 0,
        method: data.encryptionMethod || 'unknown'
      });

      if (onImportComplete) {
        onImportComplete(data.importCount || 0);
      }

    } catch (err) {
      console.error('Import error:', err);
      setError(err instanceof Error ? err.message : 'Import failed');
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setEncryptedData('');
    setPassword('');
    setError(null);
    setImportResult(null);
    setOverwrite(false);
    onClose();
  };

  const isPgpData = encryptedData.includes('-----BEGIN PGP MESSAGE-----');
  const isJsonData = encryptedData.trim().startsWith('{') || encryptedData.trim().startsWith('[');

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Lock className="h-5 w-5 text-blue-600" />
            Secure Import
          </DialogTitle>
          <DialogDescription>
            Import encrypted contacts from a secure backup.
          </DialogDescription>
        </DialogHeader>

        {error && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Import Failed</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {importResult ? (
          <div className="space-y-4 py-4">
            <div className="flex items-center gap-2 p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
              <CheckCircle className="h-4 w-4 text-green-600" />
              <span className="text-sm text-green-800 dark:text-green-300">
                Successfully imported {importResult.count} contacts
              </span>
            </div>
            
            <div className="flex items-center gap-2">
              <Badge variant="outline">
                {importResult.method} decryption
              </Badge>
            </div>
          </div>
        ) : (
          <div className="space-y-4 py-4">
            <div className="grid w-full items-center gap-1.5">
              <label className="text-sm font-medium">Encrypted Contact Data</label>
              <Textarea
                value={encryptedData}
                onChange={(e) => setEncryptedData(e.target.value)}
                placeholder="Paste your encrypted contact data here..."
                className="font-mono text-xs h-32"
              />
              
              {encryptedData && (
                <div className="flex items-center gap-2 mt-2">
                  {isPgpData ? (
                    <Badge variant="outline" className="text-green-600 border-green-600">
                      <Key className="h-3 w-3 mr-1" />
                      PGP Encrypted
                    </Badge>
                  ) : isJsonData ? (
                    <Badge variant="outline" className="text-blue-600 border-blue-600">
                      Plain JSON
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="text-gray-600 border-gray-600">
                      Unknown Format
                    </Badge>
                  )}
                </div>
              )}
            </div>

            {(isPgpData || !isJsonData) && (
              <div className="grid w-full items-center gap-1.5">
                <label className="text-sm font-medium">Decryption Password (if needed)</label>
                <div className="relative">
                  <Input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter password if data is password-protected"
                    className="pr-10"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>
            )}

            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="overwrite"
                checked={overwrite}
                onChange={(e) => setOverwrite(e.target.checked)}
                className="rounded border-gray-300"
              />
              <label htmlFor="overwrite" className="text-sm">
                Overwrite existing contacts with same fingerprint
              </label>
            </div>
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={handleClose}>
            {importResult ? 'Close' : 'Cancel'}
          </Button>
          
          {!importResult && (
            <Button 
              onClick={handleImport} 
              disabled={loading || !encryptedData.trim()}
              className="bg-blue-600 hover:bg-blue-700"
            >
              {loading ? (
                <>
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                  Importing...
                </>
              ) : (
                <>
                  <Upload className="h-4 w-4 mr-2" />
                  Import Contacts
                </>
              )}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}