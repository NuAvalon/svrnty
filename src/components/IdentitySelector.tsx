// src/components/IdentitySelector.tsx
"use client";

import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Shield, Key, UserCheck, Lock, Mail, CheckCircle2, 
  Fingerprint, RefreshCw, Users, Plus, Download, Upload,
  Trash2, Eye, EyeOff
} from 'lucide-react';
import { PersistentIdentityManager } from '@/lib/identity/persistent-manager';
import {
  Dialog, DialogContent, DialogDescription, DialogHeader,
  DialogTitle, DialogTrigger, DialogFooter 
} from '@/components/ui/dialog';
import { Textarea } from '@/components/ui/textarea';

interface StoredIdentity {
  fingerprint: string;
  name: string;
  email: string;
  created_at: string;
  verification_status: string;
  last_used: string;
}

interface IdentitySelectorProps {
  onIdentitySelected: (identity: any) => void;
}

export function IdentitySelector({ onIdentitySelected }: IdentitySelectorProps) {
  const [persistentManager, setPersistentManager] = useState<PersistentIdentityManager | null>(null);
  const [isClient, setIsClient] = useState(false);
  const [storedIdentities, setStoredIdentities] = useState<StoredIdentity[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [showImportDialog, setShowImportDialog] = useState(false);
  const [showExportDialog, setShowExportDialog] = useState(false);
  const [selectedForExport, setSelectedForExport] = useState<string | null>(null);
  
  // Form states
  const [createForm, setCreateForm] = useState({
    name: '',
    email: '',
    masterPassword: ''
  });
  const [importData, setImportData] = useState('');
  const [exportedBackup, setExportedBackup] = useState('');
  const [showMasterPassword, setShowMasterPassword] = useState(false);

  // Initialize only on client side
  useEffect(() => {
    if (typeof window !== 'undefined') {
      setIsClient(true);
      const manager = new PersistentIdentityManager();
      setPersistentManager(manager);
      loadStoredIdentities(manager);
      
      // Try to auto-load an existing identity
      autoLoadIdentity(manager);
    }
  }, []);

  const loadStoredIdentities = (manager: PersistentIdentityManager) => {
    try {
      const identities = manager.getStoredIdentities();
      setStoredIdentities(identities);
      console.log(`Loaded ${identities.length} stored identities`);
    } catch (error) {
      console.error('Failed to load stored identities:', error);
      setError('Failed to load stored identities');
    }
  };

  const autoLoadIdentity = async (manager: PersistentIdentityManager) => {
    try {
      setLoading(true);
      const identity = await manager.autoLoadIdentity();
      if (identity) {
        console.log('Auto-loaded identity:', identity.identity.fingerprint);
        onIdentitySelected(identity);
      }
    } catch (error) {
      console.warn('Auto-load failed:', error);
      // This is expected if no identities exist yet
    } finally {
      setLoading(false);
    }
  };

  const handleCreateIdentity = async () => {
    if (!persistentManager) return;

    try {
      setLoading(true);
      setError(null);

      const result = await persistentManager.createIdentity(
        createForm.name,
        createForm.email,
        createForm.masterPassword || undefined
      );

      // Refresh the stored identities list
      loadStoredIdentities(persistentManager);

      // Select the new identity
      onIdentitySelected(result);

      // Reset form and close dialog
      setCreateForm({ name: '', email: '', masterPassword: '' });
      setShowCreateForm(false);

      console.log('Created new identity:', result.fingerprint);
    } catch (error) {
      console.error('Failed to create identity:', error);
      setError(error instanceof Error ? error.message : 'Failed to create identity');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectIdentity = async (fingerprint: string) => {
    if (!persistentManager) return;

    try {
      setLoading(true);
      setError(null);

      const identity = await persistentManager.loadIdentity(fingerprint);
      if (identity) {
        onIdentitySelected(identity);
        console.log('Selected identity:', fingerprint);
      }
    } catch (error) {
      console.error('Failed to load identity:', error);
      setError(error instanceof Error ? error.message : 'Failed to load identity');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteIdentity = async (fingerprint: string) => {
    if (!persistentManager || !confirm('Are you sure you want to delete this identity? This action cannot be undone.')) {
      return;
    }

    try {
      setLoading(true);
      setError(null);

      await persistentManager.deleteIdentity(fingerprint);
      loadStoredIdentities(persistentManager);

      console.log('Deleted identity:', fingerprint);
    } catch (error) {
      console.error('Failed to delete identity:', error);
      setError(error instanceof Error ? error.message : 'Failed to delete identity');
    } finally {
      setLoading(false);
    }
  };

  const handleExportIdentity = async (fingerprint: string) => {
    if (!persistentManager) return;

    try {
      setLoading(true);
      setError(null);

      const backup = await persistentManager.createIdentityBackup(fingerprint, true);
      setExportedBackup(backup);
      setSelectedForExport(fingerprint);
      setShowExportDialog(true);

      console.log('Exported identity backup for:', fingerprint);
    } catch (error) {
      console.error('Failed to export identity:', error);
      setError(error instanceof Error ? error.message : 'Failed to export identity');
    } finally {
      setLoading(false);
    }
  };

  const handleImportIdentity = async () => {
    if (!persistentManager) return;

    try {
      setLoading(true);
      setError(null);

      const result = await persistentManager.restoreFromBackup(importData);
      
      // Refresh the stored identities list
      loadStoredIdentities(persistentManager);

      // Select the imported identity
      onIdentitySelected(result);

      // Reset form and close dialog
      setImportData('');
      setShowImportDialog(false);

      console.log('Imported identity:', result.fingerprint);
    } catch (error) {
      console.error('Failed to import identity:', error);
      setError(error instanceof Error ? error.message : 'Failed to import identity');
    } finally {
      setLoading(false);
    }
  };

  const downloadBackup = () => {
    if (!exportedBackup || !selectedForExport) return;

    const blob = new Blob([exportedBackup], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soverentity-backup-${selectedForExport.slice(0, 8)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const formatFingerprint = (fingerprint: string) => {
    return fingerprint?.match(/.{1,4}/g)?.join(' ') || fingerprint;
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString();
  };

  // Show loading state during SSR or initial client load
  if (!isClient || !persistentManager) {
    return (
      <Card className="w-full max-w-4xl mx-auto">
        <CardContent className="p-8 text-center">
          <RefreshCw className="h-8 w-8 animate-spin mx-auto mb-4 text-blue-600" />
          <p>Initializing decentralized identity system...</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-4xl mx-auto shadow-lg">
      <CardHeader className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-950/30 dark:to-indigo-950/30">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="bg-white dark:bg-slate-800 rounded-full p-2 shadow-sm">
              <Users className="h-6 w-6 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <CardTitle className="text-xl sm:text-2xl">Identity Manager</CardTitle>
              <CardDescription className="mt-1">
                Decentralized identity storage - your keys, your data, your control
              </CardDescription>
            </div>
          </div>
          
          <div className="flex gap-2">
            <Button 
              variant="outline" 
              size="sm"
              onClick={() => setShowImportDialog(true)}
              className="bg-white/80 dark:bg-slate-800/80"
            >
              <Upload className="h-4 w-4 mr-2" />
              Import
            </Button>
            <Button 
              onClick={() => setShowCreateForm(true)}
              className="bg-blue-600 hover:bg-blue-700 text-white"
            >
              <Plus className="h-4 w-4 mr-2" />
              Create Identity
            </Button>
          </div>
        </div>
      </CardHeader>

      <CardContent className="p-6">
        {error && (
          <Alert variant="destructive" className="mb-6">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {storedIdentities.length === 0 ? (
          <div className="text-center py-12">
            <div className="inline-flex justify-center items-center w-16 h-16 rounded-full bg-blue-100 dark:bg-blue-900/30 mb-4">
              <Shield className="h-8 w-8 text-blue-600 dark:text-blue-400" />
            </div>
            <h3 className="text-lg font-medium mb-2">No Identities Found</h3>
            <p className="text-slate-600 dark:text-slate-400 mb-6 max-w-md mx-auto">
              Create your first sovereign identity or import an existing backup to get started.
            </p>
            <div className="flex justify-center gap-3">
              <Button onClick={() => setShowCreateForm(true)} className="bg-blue-600 hover:bg-blue-700">
                <Plus className="h-4 w-4 mr-2" />
                Create New Identity
              </Button>
              <Button variant="outline" onClick={() => setShowImportDialog(true)}>
                <Upload className="h-4 w-4 mr-2" />
                Import Backup
              </Button>
            </div>
          </div>
        ) : (
          <div className="grid gap-4">
            {storedIdentities.map((identity) => (
              <div 
                key={identity.fingerprint} 
                className="border rounded-lg p-4 hover:shadow-md transition-shadow bg-white dark:bg-slate-900"
              >
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <div className={`rounded-full p-1.5 ${
                        identity.verification_status === 'verified' 
                          ? 'bg-green-100 dark:bg-green-900/30' 
                          : 'bg-yellow-100 dark:bg-yellow-900/30'
                      }`}>
                        <Key className={`h-4 w-4 ${
                          identity.verification_status === 'verified'
                            ? 'text-green-600 dark:text-green-500'
                            : 'text-yellow-600 dark:text-yellow-500'
                        }`} />
                      </div>
                      <div>
                        <h3 className="font-medium text-lg">{identity.name}</h3>
                        <p className="text-sm text-slate-600 dark:text-slate-400 flex items-center gap-1">
                          <Mail className="h-3 w-3" />
                          {identity.email}
                        </p>
                      </div>
                    </div>
                    
                    <div className="space-y-1 text-sm">
                      <div className="font-mono text-xs text-slate-500 dark:text-slate-400">
                        <Fingerprint className="h-3 w-3 inline mr-1" />
                        {formatFingerprint(identity.fingerprint)}
                      </div>
                      <div className="text-slate-600 dark:text-slate-400">
                        Created: {formatDate(identity.created_at)} • 
                        Last used: {formatDate(identity.last_used)}
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleExportIdentity(identity.fingerprint)}
                      disabled={loading}
                    >
                      <Download className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleDeleteIdentity(identity.fingerprint)}
                      disabled={loading}
                      className="text-red-600 hover:text-red-700"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                    <Button
                      onClick={() => handleSelectIdentity(identity.fingerprint)}
                      disabled={loading}
                      className="bg-blue-600 hover:bg-blue-700 text-white"
                    >
                      {loading ? (
                        <RefreshCw className="h-4 w-4 animate-spin" />
                      ) : (
                        'Select'
                      )}
                    </Button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Create Identity Dialog */}
        <Dialog open={showCreateForm} onOpenChange={setShowCreateForm}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Create New Identity</DialogTitle>
              <DialogDescription>
                Generate a new sovereign identity with PGP encryption.
              </DialogDescription>
            </DialogHeader>
            
            <div className="space-y-4 py-4">
              <div className="grid w-full items-center gap-1.5">
                <label htmlFor="name" className="text-sm font-medium">Full Name</label>
                <Input
                  id="name"
                  value={createForm.name}
                  onChange={(e) => setCreateForm(prev => ({ ...prev, name: e.target.value }))}
                  placeholder="Your name"
                />
              </div>
              
              <div className="grid w-full items-center gap-1.5">
                <label htmlFor="email" className="text-sm font-medium">Email Address</label>
                <Input
                  id="email"
                  type="email"
                  value={createForm.email}
                  onChange={(e) => setCreateForm(prev => ({ ...prev, email: e.target.value }))}
                  placeholder="your.email@example.com"
                />
              </div>
              
              <div className="grid w-full items-center gap-1.5">
                <label htmlFor="masterPassword" className="text-sm font-medium">
                  Master Password (Optional)
                </label>
                <div className="relative">
                  <Input
                    id="masterPassword"
                    type={showMasterPassword ? "text" : "password"}
                    value={createForm.masterPassword}
                    onChange={(e) => setCreateForm(prev => ({ ...prev, masterPassword: e.target.value }))}
                    placeholder="Optional master password for extra security"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                    onClick={() => setShowMasterPassword(!showMasterPassword)}
                  >
                    {showMasterPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </Button>
                </div>
                <p className="text-xs text-slate-500">
                  If set, you'll need this password to access your private keys
                </p>
              </div>
            </div>
            
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowCreateForm(false)}>
                Cancel
              </Button>
              <Button 
                onClick={handleCreateIdentity} 
                disabled={loading || !createForm.name || !createForm.email}
                className="bg-blue-600 hover:bg-blue-700"
              >
                {loading ? (
                  <>
                    <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                    Creating...
                  </>
                ) : (
                  <>
                    <Key className="h-4 w-4 mr-2" />
                    Create Identity
                  </>
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Import Dialog */}
        <Dialog open={showImportDialog} onOpenChange={setShowImportDialog}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Import Identity Backup</DialogTitle>
              <DialogDescription>
                Restore an identity from a backup file.
              </DialogDescription>
            </DialogHeader>
            
            <div className="space-y-4 py-4">
              <div className="grid w-full items-center gap-1.5">
                <label htmlFor="importData" className="text-sm font-medium">Backup Data</label>
                <Textarea
                  id="importData"
                  value={importData}
                  onChange={(e) => setImportData(e.target.value)}
                  placeholder="Paste your identity backup JSON here..."
                  className="font-mono text-xs"
                  rows={8}
                />
              </div>
            </div>
            
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowImportDialog(false)}>
                Cancel
              </Button>
              <Button 
                onClick={handleImportIdentity} 
                disabled={loading || !importData.trim()}
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
                    Import Identity
                  </>
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Export Dialog */}
        <Dialog open={showExportDialog} onOpenChange={setShowExportDialog}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Identity Backup</DialogTitle>
              <DialogDescription>
                Your identity has been exported. Save this backup securely.
              </DialogDescription>
            </DialogHeader>
            
            <div className="space-y-4 py-4">
              <Textarea
                value={exportedBackup}
                readOnly
                className="font-mono text-xs"
                rows={8}
              />
              
              <Alert>
                <Shield className="h-4 w-4" />
                <AlertDescription>
                  Keep this backup secure! It contains your encrypted private keys.
                </AlertDescription>
              </Alert>
            </div>
            
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowExportDialog(false)}>
                Close
              </Button>
              <Button onClick={downloadBackup} className="bg-blue-600 hover:bg-blue-700">
                <Download className="h-4 w-4 mr-2" />
                Download Backup
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}