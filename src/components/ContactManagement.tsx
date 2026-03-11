"use client";

import React, { useState, useEffect, useCallback } from 'react';
import {
  Card, CardHeader, CardTitle, CardContent, CardDescription
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import {
  Shield, Key, UserCheck, Lock, Mail, UserPlus, Search,
  QrCode, Link, Share2, Trash2, Check, X, Edit, Filter, Download, Upload, RefreshCw,
  FileJson, Eye, EyeOff, ChevronRight, ShieldOff, ShieldCheck, Copy
} from 'lucide-react';
import {
  Dialog, DialogContent, DialogDescription, DialogHeader,
  DialogTitle, DialogFooter
} from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger
} from '@/components/ui/dropdown-menu';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { SecureExportDialog, SecureImportDialog } from '@/components/SecureImportExportDialogs';

// --- Types ---
// Binary trust: known or trusted. No tiers.

interface Contact {
  id: string;
  name: string;
  email: string;
  fingerprint: string;
  public_key: string;
  trust_level: 'unverified' | 'verified' | 'trusted'; // legacy API format
  added_at: string;
  verified_at?: string;
  metadata?: {
    notes?: string;
    tags?: string[];
    connection_method?: 'manual' | 'qr' | 'burner_link' | 'mutual';
    mutual_contacts?: string[];
  };
}

// Map legacy API values to binary trust
function isTrusted(contact: Contact): boolean {
  return contact.trust_level === 'verified' || contact.trust_level === 'trusted';
}

function trustLabel(contact: Contact): string {
  return isTrusted(contact) ? 'Trusted' : 'Known';
}

interface ContactsProps {
  identity: any;
}

// --- Helpers ---

function TrustBadge({ contact }: { contact: Contact }) {
  const trusted = isTrusted(contact);
  return (
    <Badge className={`border font-medium ${
      trusted
        ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
        : 'bg-gray-500/10 text-gray-400 border-gray-500/20'
    }`}>
      {trustLabel(contact)}
    </Badge>
  );
}

function TrustIcon({ contact, className = "h-5 w-5" }: { contact: Contact; className?: string }) {
  const trusted = isTrusted(contact);
  if (trusted) {
    return <ShieldCheck className={`${className} text-amber-400`} />;
  }
  return <Eye className={`${className} text-gray-400`} />;
}

// --- Main Component ---

export function ContactManagement({ identity }: ContactsProps) {
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedContact, setSelectedContact] = useState<Contact | null>(null);

  // Dialog visibility
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [showDetailDialog, setShowDetailDialog] = useState(false);
  const [showQRDialog, setShowQRDialog] = useState(false);
  const [showShareDialog, setShowShareDialog] = useState(false);
  const [showImportDialog, setShowImportDialog] = useState(false);
  const [showSecureExportDialog, setShowSecureExportDialog] = useState(false);
  const [showSecureImportDialog, setShowSecureImportDialog] = useState(false);
  const [showShareIdentityDialog, setShowShareIdentityDialog] = useState(false);
  const [showImportExchangeDialog, setShowImportExchangeDialog] = useState(false);

  // Form state
  const [newContactForm, setNewContactForm] = useState({
    name: '', email: '', fingerprint: '', public_key: '',
  });
  const [editContactForm, setEditContactForm] = useState({
    id: '', name: '', email: '', fingerprint: '', public_key: '',
    notes: '',
  });

  // Share state
  const [qrCodeData, setQrCodeData] = useState('');
  const [burnerLink, setBurnerLink] = useState('');
  const [importData, setImportData] = useState('');
  const [importError, setImportError] = useState<string | null>(null);
  const [exchangePackage, setExchangePackage] = useState('');
  const [exchangeImportData, setExchangeImportData] = useState('');
  const [exchangeResult, setExchangeResult] = useState<{ success: boolean; message: string } | null>(null);

  const fingerprint = identity?.identity?.fingerprint;

  // --- API calls ---

  const apiCall = useCallback(async (
    url: string,
    options?: RequestInit,
  ): Promise<any> => {
    const response = await fetch(url, options);
    const contentType = response.headers.get('content-type');
    if (!contentType || !contentType.includes('application/json')) {
      throw new Error('Invalid response from server');
    }
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || `Request failed (${response.status})`);
    }
    return data;
  }, []);

  const loadContacts = useCallback(async () => {
    if (!fingerprint) return;
    try {
      setLoading(true);
      setError(null);
      const data = await apiCall(`/api/contacts?fingerprint=${fingerprint}`);
      setContacts(data.contacts || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load contacts');
      setContacts([]);
    } finally {
      setLoading(false);
    }
  }, [fingerprint, apiCall]);

  useEffect(() => {
    if (fingerprint) loadContacts();
  }, [fingerprint, loadContacts]);

  // Filter contacts — binary: all, trusted, known
  const filteredContacts = contacts.filter(contact => {
    if (activeTab === 'trusted' && !isTrusted(contact)) return false;
    if (activeTab === 'known' && isTrusted(contact)) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return contact.name.toLowerCase().includes(q) ||
        contact.email.toLowerCase().includes(q) ||
        contact.fingerprint.toLowerCase().includes(q);
    }
    return true;
  });

  const trustedCount = contacts.filter(c => isTrusted(c)).length;
  const knownCount = contacts.filter(c => !isTrusted(c)).length;

  // --- Handlers ---

  const handleAddContact = async () => {
    if (!fingerprint) return;
    try {
      setLoading(true);
      setError(null);
      if (!newContactForm.name || !newContactForm.email || !newContactForm.fingerprint || !newContactForm.public_key) {
        throw new Error('All fields are required');
      }
      if (!newContactForm.public_key.trim().startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
        throw new Error('Invalid PGP public key format');
      }
      if (newContactForm.fingerprint === fingerprint) {
        throw new Error('You cannot add yourself as a contact');
      }
      // New contacts start as known (unverified in legacy API)
      const data = await apiCall('/api/contacts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fingerprint,
          contact: { ...newContactForm, trust_level: 'unverified' },
        }),
      });
      setContacts(prev => [...prev, data.contact]);
      setNewContactForm({ name: '', email: '', fingerprint: '', public_key: '' });
      setShowAddDialog(false);
      await loadContacts();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add contact');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateContact = async () => {
    if (!fingerprint) return;
    try {
      setLoading(true);
      setError(null);
      if (!editContactForm.name || !editContactForm.email) {
        throw new Error('Name and email are required');
      }
      const updates = {
        name: editContactForm.name,
        email: editContactForm.email,
        metadata: {
          notes: editContactForm.notes,
          ...(selectedContact?.metadata ? {
            tags: selectedContact.metadata.tags,
            connection_method: selectedContact.metadata.connection_method,
            mutual_contacts: selectedContact.metadata.mutual_contacts,
          } : {}),
        },
      };
      await apiCall('/api/contacts', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fingerprint, contactId: editContactForm.id, updates }),
      });
      setShowEditDialog(false);
      await loadContacts();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update contact');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteContact = async (contactId: string) => {
    if (!fingerprint) return;
    try {
      setLoading(true);
      setError(null);
      await apiCall(`/api/contacts?fingerprint=${fingerprint}&contactId=${contactId}`, { method: 'DELETE' });
      setShowDetailDialog(false);
      setShowEditDialog(false);
      await loadContacts();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete contact');
    } finally {
      setLoading(false);
    }
  };

  const handleToggleTrust = async (contact: Contact) => {
    if (!fingerprint) return;
    const newLevel = isTrusted(contact) ? 'unverified' : 'trusted';
    try {
      setLoading(true);
      setError(null);
      await apiCall('/api/contacts', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fingerprint,
          contactId: contact.id,
          updates: {
            trust_level: newLevel,
            ...(newLevel === 'trusted' && { verified_at: new Date().toISOString() }),
          },
        }),
      });
      if (selectedContact && selectedContact.id === contact.id) {
        setSelectedContact({ ...selectedContact, trust_level: newLevel });
      }
      await loadContacts();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update trust');
    } finally {
      setLoading(false);
    }
  };

  const handleShareIdentity = async () => {
    if (!fingerprint) return;
    try {
      setLoading(true);
      setError(null);
      const data = await apiCall('/api/contacts/share', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fingerprint }),
      });
      setExchangePackage(data.exchangePackage);
      setShowShareIdentityDialog(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create exchange package');
    } finally {
      setLoading(false);
    }
  };

  const handleImportExchange = async () => {
    if (!fingerprint || !exchangeImportData.trim()) return;
    try {
      setLoading(true);
      setExchangeResult(null);
      const data = await apiCall('/api/contacts/process', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fingerprint, exchangeData: exchangeImportData.trim() }),
      });
      setExchangeResult({ success: true, message: data.message || 'Contact added successfully' });
      await loadContacts();
    } catch (err) {
      setExchangeResult({ success: false, message: err instanceof Error ? err.message : 'Failed to import' });
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateBurnerLink = async () => {
    if (!fingerprint) return;
    try {
      setLoading(true);
      setError(null);
      const data = await apiCall('/api/contacts/share', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fingerprint, type: 'burner', expireInHours: 48 }),
      });
      setBurnerLink(data.burnerLink);
      setShowShareDialog(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate link');
    } finally {
      setLoading(false);
    }
  };

  const handleImportContacts = async () => {
    if (!fingerprint || !importData) return;
    try {
      setLoading(true);
      setImportError(null);
      await apiCall('/api/contacts/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fingerprint, contactsData: importData, overwrite: false }),
      });
      setImportData('');
      setShowImportDialog(false);
      await loadContacts();
    } catch (err) {
      setImportError(err instanceof Error ? err.message : 'Failed to import');
    } finally {
      setLoading(false);
    }
  };

  const handleExportContacts = async () => {
    if (!fingerprint) return;
    try {
      setLoading(true);
      setError(null);
      const data = await apiCall(`/api/contacts/export?fingerprint=${fingerprint}`);
      const blob = new Blob([data.contacts], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'soverentity-contacts.json';
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to export');
    } finally {
      setLoading(false);
    }
  };

  const openEditDialog = (contact: Contact) => {
    setSelectedContact(contact);
    setEditContactForm({
      id: contact.id,
      name: contact.name,
      email: contact.email,
      fingerprint: contact.fingerprint,
      public_key: contact.public_key,
      notes: contact.metadata?.notes || '',
    });
    setShowEditDialog(true);
  };

  // --- Render ---

  return (
    <Card className="w-full border-border/40 bg-card/50 backdrop-blur-sm shadow-lg">
      <CardHeader className="border-b border-border/40">
        <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4">
          <CardTitle className="flex items-center gap-2 text-xl sm:text-2xl">
            <Shield className="h-6 w-6 text-amber-500" />
            <span>Trust Network</span>
          </CardTitle>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={handleShareIdentity} className="bg-amber-600 hover:bg-amber-700">
              <Share2 className="h-4 w-4 mr-2" />
              Share Identity
            </Button>
            <Button variant="outline" size="sm" onClick={() => setShowImportExchangeDialog(true)}>
              <Download className="h-4 w-4 mr-2" />
              Import Contact
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <Share2 className="h-4 w-4 mr-2" />
                  More
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuLabel>Import & Export</DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => setShowSecureExportDialog(true)}>
                  <Shield className="h-4 w-4 mr-2 text-emerald-500" />
                  Secure Export (Encrypted)
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setShowSecureImportDialog(true)}>
                  <Lock className="h-4 w-4 mr-2 text-blue-500" />
                  Secure Import (Encrypted)
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={handleExportContacts}>
                  <FileJson className="h-4 w-4 mr-2" />
                  Export as JSON
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setShowImportDialog(true)}>
                  <Upload className="h-4 w-4 mr-2" />
                  Import from JSON
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
        <CardDescription className="mt-2 text-muted-foreground">
          Your sovereign trust graph. Local-first, encrypted, auditable.
        </CardDescription>
      </CardHeader>

      <CardContent className="p-4 sm:p-6">
        {error && (
          <Alert variant="destructive" className="mb-4">
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Search + Add */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-6">
          <div className="relative w-full sm:w-64">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search by name, email, fingerprint..."
              className="pl-8"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
          <Button onClick={() => setShowAddDialog(true)}>
            <UserPlus className="h-4 w-4 mr-2" />
            Add Contact
          </Button>
        </div>

        {/* Tabs — binary: all, trusted, known */}
        <Tabs defaultValue="all" value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="mb-4 w-full sm:w-auto">
            <TabsTrigger value="all">
              All ({contacts.length})
            </TabsTrigger>
            <TabsTrigger value="trusted">
              Trusted ({trustedCount})
            </TabsTrigger>
            <TabsTrigger value="known">
              Known ({knownCount})
            </TabsTrigger>
          </TabsList>

          <TabsContent value={activeTab} className="mt-0">
            {loading ? (
              <div className="flex justify-center p-8">
                <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
              </div>
            ) : filteredContacts.length === 0 ? (
              <div className="text-center p-12 rounded-lg border border-dashed border-border/60">
                <div className="inline-flex justify-center items-center w-16 h-16 rounded-full bg-muted mb-4">
                  {searchQuery ? <Search className="h-8 w-8 text-muted-foreground" /> : <UserPlus className="h-8 w-8 text-muted-foreground" />}
                </div>
                <p className="text-lg font-medium">
                  {searchQuery ? 'No matching contacts' : 'No contacts yet'}
                </p>
                <p className="text-sm text-muted-foreground mt-2 max-w-md mx-auto">
                  {searchQuery ? 'Try a different search' : 'Add your first contact to begin building your trust network'}
                </p>
              </div>
            ) : (
              <div className="grid gap-4 sm:grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
                {filteredContacts.map(contact => (
                  <div
                    key={contact.id}
                    className="group border border-border/40 rounded-lg overflow-hidden bg-card hover:border-border transition-colors cursor-pointer"
                    onClick={() => { setSelectedContact(contact); setShowDetailDialog(true); }}
                  >
                    <div className="p-4">
                      <div className="flex justify-between items-start">
                        <div className="space-y-1 min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <TrustIcon contact={contact} className="h-4 w-4 flex-shrink-0" />
                            <h3 className="font-medium text-lg truncate">{contact.name}</h3>
                          </div>
                          <div className="text-sm text-muted-foreground flex items-center gap-1">
                            <Mail className="h-3 w-3 flex-shrink-0" />
                            <span className="truncate">{contact.email}</span>
                          </div>
                          <div className="font-mono text-xs text-muted-foreground/60 truncate">
                            {contact.fingerprint.match(/.{1,4}/g)?.join(' ')}
                          </div>
                        </div>
                        <ChevronRight className="h-4 w-4 text-muted-foreground/40 group-hover:text-muted-foreground transition-colors flex-shrink-0 mt-1" />
                      </div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        <TrustBadge contact={contact} />
                        {contact.metadata?.connection_method && (
                          <Badge variant="outline" className="text-xs">
                            {contact.metadata.connection_method === 'mutual' ? 'Mutual' :
                              contact.metadata.connection_method === 'qr' ? 'QR Code' :
                                contact.metadata.connection_method === 'burner_link' ? 'Burner Link' : 'Manual'}
                          </Badge>
                        )}
                      </div>
                    </div>
                    <div className="flex divide-x divide-border/40 border-t border-border/40 bg-muted/30" onClick={e => e.stopPropagation()}>
                      <Button
                        variant="ghost"
                        size="sm"
                        className={`flex-1 rounded-none ${isTrusted(contact) ? 'text-amber-400' : 'text-muted-foreground'}`}
                        onClick={() => handleToggleTrust(contact)}
                      >
                        {isTrusted(contact) ? <><ShieldOff className="h-4 w-4 mr-1" /> Break</> : <><ShieldCheck className="h-4 w-4 mr-1" /> Vouch</>}
                      </Button>
                      <Button variant="ghost" size="sm" className="flex-1 rounded-none text-muted-foreground" onClick={() => openEditDialog(contact)}>
                        <Edit className="h-4 w-4 mr-1" /> Edit
                      </Button>
                      <Button variant="ghost" size="sm" className="flex-1 rounded-none text-destructive hover:text-destructive" onClick={() => handleDeleteContact(contact.id)}>
                        <Trash2 className="h-4 w-4 mr-1" /> Remove
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </TabsContent>
        </Tabs>

        {/* === DIALOGS === */}

        {/* Add Contact */}
        <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Add Contact</DialogTitle>
              <DialogDescription>Enter their details. New contacts start as Known.</DialogDescription>
            </DialogHeader>
            {error && <Alert variant="destructive"><AlertTitle>Error</AlertTitle><AlertDescription>{error}</AlertDescription></Alert>}
            <div className="space-y-4 py-4">
              <div className="space-y-1.5">
                <label htmlFor="name" className="text-sm font-medium">Name</label>
                <Input id="name" value={newContactForm.name} onChange={e => setNewContactForm(p => ({ ...p, name: e.target.value }))} placeholder="Contact name" />
              </div>
              <div className="space-y-1.5">
                <label htmlFor="email" className="text-sm font-medium">Email</label>
                <Input id="email" type="email" value={newContactForm.email} onChange={e => setNewContactForm(p => ({ ...p, email: e.target.value }))} placeholder="contact@example.com" />
              </div>
              <div className="space-y-1.5">
                <label htmlFor="fp" className="text-sm font-medium">Fingerprint</label>
                <Input id="fp" value={newContactForm.fingerprint} onChange={e => setNewContactForm(p => ({ ...p, fingerprint: e.target.value }))} placeholder="PGP fingerprint" />
              </div>
              <div className="space-y-1.5">
                <label htmlFor="pubkey" className="text-sm font-medium">Public Key</label>
                <Textarea id="pubkey" value={newContactForm.public_key} onChange={e => setNewContactForm(p => ({ ...p, public_key: e.target.value }))} placeholder="Paste PGP public key" className="font-mono text-xs" rows={5} />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowAddDialog(false)}>Cancel</Button>
              <Button onClick={handleAddContact} disabled={loading || !newContactForm.name || !newContactForm.email || !newContactForm.fingerprint || !newContactForm.public_key}>
                {loading ? <><RefreshCw className="h-4 w-4 mr-2 animate-spin" />Adding...</> : <><UserPlus className="h-4 w-4 mr-2" />Add as Known</>}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Edit Contact */}
        <Dialog open={showEditDialog} onOpenChange={setShowEditDialog}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Edit Contact</DialogTitle>
              <DialogDescription>Update contact details.</DialogDescription>
            </DialogHeader>
            {error && <Alert variant="destructive"><AlertTitle>Error</AlertTitle><AlertDescription>{error}</AlertDescription></Alert>}
            <div className="space-y-4 py-4">
              <div className="space-y-1.5">
                <label htmlFor="edit-name" className="text-sm font-medium">Name</label>
                <Input id="edit-name" value={editContactForm.name} onChange={e => setEditContactForm(p => ({ ...p, name: e.target.value }))} />
              </div>
              <div className="space-y-1.5">
                <label htmlFor="edit-email" className="text-sm font-medium">Email</label>
                <Input id="edit-email" type="email" value={editContactForm.email} onChange={e => setEditContactForm(p => ({ ...p, email: e.target.value }))} />
              </div>
              <div className="space-y-1.5">
                <label htmlFor="edit-notes" className="text-sm font-medium">Notes</label>
                <Textarea id="edit-notes" value={editContactForm.notes} onChange={e => setEditContactForm(p => ({ ...p, notes: e.target.value }))} placeholder="Private notes about this contact..." rows={3} />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium">Fingerprint</label>
                <Input value={editContactForm.fingerprint} readOnly className="font-mono text-xs opacity-60" />
                <p className="text-xs text-muted-foreground">Fingerprint is immutable</p>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowEditDialog(false)}>Cancel</Button>
              <Button onClick={handleUpdateContact} disabled={loading || !editContactForm.name || !editContactForm.email}>
                {loading ? <><RefreshCw className="h-4 w-4 mr-2 animate-spin" />Saving...</> : <><Check className="h-4 w-4 mr-2" />Save</>}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Contact Detail */}
        <Dialog open={showDetailDialog} onOpenChange={setShowDetailDialog}>
          <DialogContent className="sm:max-w-lg">
            {selectedContact && (
              <>
                <DialogHeader>
                  <DialogTitle className="flex items-center gap-2">
                    <div className={`flex-shrink-0 rounded-full h-8 w-8 flex items-center justify-center ${
                      isTrusted(selectedContact) ? 'bg-amber-500/15' : 'bg-gray-500/15'
                    }`}>
                      <TrustIcon contact={selectedContact} />
                    </div>
                    <span>{selectedContact.name}</span>
                  </DialogTitle>
                  <DialogDescription>Contact details and trust management.</DialogDescription>
                </DialogHeader>

                <div className="space-y-5">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Email</h4>
                      <div className="flex items-center gap-1 mt-1">
                        <Mail className="h-4 w-4 text-muted-foreground" />
                        <span>{selectedContact.email}</span>
                      </div>
                    </div>
                    <div>
                      <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Trust</h4>
                      <div className="mt-1"><TrustBadge contact={selectedContact} /></div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Fingerprint</h4>
                    <div className="mt-1 font-mono text-sm bg-muted p-2 rounded border border-border/40">
                      {selectedContact.fingerprint.match(/.{1,4}/g)?.join(' ')}
                    </div>
                  </div>

                  {selectedContact.metadata?.notes && (
                    <div>
                      <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Notes</h4>
                      <div className="mt-1 p-3 bg-muted rounded-md">
                        <p className="text-sm whitespace-pre-wrap">{selectedContact.metadata.notes}</p>
                      </div>
                    </div>
                  )}

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                    <div>
                      <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Added</h4>
                      <p className="mt-1">{new Date(selectedContact.added_at).toLocaleDateString()}</p>
                    </div>
                    {selectedContact.verified_at && (
                      <div>
                        <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Trusted Since</h4>
                        <p className="mt-1">{new Date(selectedContact.verified_at).toLocaleDateString()}</p>
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="border-t border-border/40 pt-4 flex flex-col sm:flex-row gap-2 justify-between">
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => { handleToggleTrust(selectedContact); }}
                        className={isTrusted(selectedContact) ? 'text-amber-400 border-amber-500/30' : 'text-emerald-400 border-emerald-500/30'}
                      >
                        {isTrusted(selectedContact)
                          ? <><ShieldOff className="h-4 w-4 mr-1" /> Break Trust</>
                          : <><ShieldCheck className="h-4 w-4 mr-1" /> Vouch</>
                        }
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => { openEditDialog(selectedContact); setShowDetailDialog(false); }}>
                        <Edit className="h-4 w-4 mr-1" /> Edit
                      </Button>
                    </div>
                    <Button variant="destructive" size="sm" onClick={() => { handleDeleteContact(selectedContact.id); setShowDetailDialog(false); }}>
                      <Trash2 className="h-4 w-4 mr-1" /> Remove
                    </Button>
                  </div>
                </div>
              </>
            )}
          </DialogContent>
        </Dialog>

        {/* QR Code */}
        <Dialog open={showQRDialog} onOpenChange={setShowQRDialog}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Share via QR Code</DialogTitle>
              <DialogDescription>Let others scan this to add you to their trust network.</DialogDescription>
            </DialogHeader>
            <div className="flex justify-center py-4">
              {qrCodeData ? (
                <div className="bg-white p-4 rounded-lg">
                  <div className="text-center text-sm text-muted-foreground">QR code placeholder</div>
                </div>
              ) : (
                <div className="text-center text-sm text-muted-foreground p-8">
                  QR generation not yet connected
                </div>
              )}
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowQRDialog(false)}>Close</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Burner Link */}
        <Dialog open={showShareDialog} onOpenChange={setShowShareDialog}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Burner Link</DialogTitle>
              <DialogDescription>Share this link. Expires in 48 hours. Single use.</DialogDescription>
            </DialogHeader>
            <div className="py-4">
              {burnerLink ? (
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <Input value={burnerLink} readOnly className="font-mono text-sm" />
                    <Button variant="outline" size="sm" onClick={() => navigator.clipboard.writeText(burnerLink)}>Copy</Button>
                  </div>
                  <p className="text-xs text-muted-foreground">This link expires in 48 hours and can only be used once.</p>
                </div>
              ) : (
                <div className="text-center text-sm text-muted-foreground p-8">Generating...</div>
              )}
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowShareDialog(false)}>Close</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Import */}
        <Dialog open={showImportDialog} onOpenChange={setShowImportDialog}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Import Contacts</DialogTitle>
              <DialogDescription>Paste exported JSON to import.</DialogDescription>
            </DialogHeader>
            {importError && <Alert variant="destructive"><AlertTitle>Error</AlertTitle><AlertDescription>{importError}</AlertDescription></Alert>}
            <div className="py-4">
              <Textarea value={importData} onChange={e => setImportData(e.target.value)} placeholder="Paste contacts JSON here..." className="font-mono text-xs" rows={8} />
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowImportDialog(false)}>Cancel</Button>
              <Button onClick={handleImportContacts} disabled={loading || !importData}>
                {loading ? <><RefreshCw className="h-4 w-4 mr-2 animate-spin" />Importing...</> : <><Upload className="h-4 w-4 mr-2" />Import</>}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Share Identity — signed exchange package */}
        <Dialog open={showShareIdentityDialog} onOpenChange={setShowShareIdentityDialog}>
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle>Share Your Identity</DialogTitle>
              <DialogDescription>
                Copy this signed package and send it to someone via Signal, email, or any trusted channel. They can import it to add you as a contact.
              </DialogDescription>
            </DialogHeader>
            <div className="py-4 space-y-3">
              <Textarea
                value={exchangePackage}
                readOnly
                className="font-mono text-xs h-48"
                onClick={(e) => (e.target as HTMLTextAreaElement).select()}
              />
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="flex-1"
                  onClick={() => {
                    navigator.clipboard.writeText(exchangePackage);
                  }}
                >
                  <Copy className="h-4 w-4 mr-2" />
                  Copy to Clipboard
                </Button>
                {typeof navigator !== 'undefined' && 'share' in navigator && (
                  <Button
                    variant="outline"
                    size="sm"
                    className="flex-1"
                    onClick={() => {
                      navigator.share({
                        title: 'SVRNTY Identity',
                        text: exchangePackage,
                      }).catch(() => {});
                    }}
                  >
                    <Share2 className="h-4 w-4 mr-2" />
                    Share
                  </Button>
                )}
              </div>
              <p className="text-xs text-muted-foreground">
                This package is dual-signed (ED25519 + ML-DSA-65). The recipient can verify it came from you.
              </p>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowShareIdentityDialog(false)}>Close</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Import Contact from Exchange Package */}
        <Dialog open={showImportExchangeDialog} onOpenChange={(open) => {
          setShowImportExchangeDialog(open);
          if (!open) { setExchangeImportData(''); setExchangeResult(null); }
        }}>
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle>Import Contact</DialogTitle>
              <DialogDescription>
                Paste a signed identity package from someone who wants to connect. Their signature will be verified automatically.
              </DialogDescription>
            </DialogHeader>
            <div className="py-4 space-y-3">
              <Textarea
                value={exchangeImportData}
                onChange={(e) => setExchangeImportData(e.target.value)}
                placeholder="Paste the signed identity package here..."
                className="font-mono text-xs h-48"
              />
              {exchangeResult && (
                <Alert variant={exchangeResult.success ? 'default' : 'destructive'}>
                  <AlertDescription className={exchangeResult.success ? 'text-emerald-400' : ''}>
                    {exchangeResult.message}
                  </AlertDescription>
                </Alert>
              )}
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => { setShowImportExchangeDialog(false); setExchangeImportData(''); setExchangeResult(null); }}>
                Cancel
              </Button>
              <Button
                onClick={handleImportExchange}
                disabled={loading || !exchangeImportData.trim()}
              >
                {loading ? <><RefreshCw className="h-4 w-4 mr-2 animate-spin" />Verifying...</> : <><ShieldCheck className="h-4 w-4 mr-2" />Verify & Import</>}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Secure Export/Import */}
        <SecureExportDialog
          open={showSecureExportDialog}
          onClose={() => setShowSecureExportDialog(false)}
          identityFingerprint={fingerprint || ''}
          onExportComplete={() => {}}
        />
        <SecureImportDialog
          open={showSecureImportDialog}
          onClose={() => setShowSecureImportDialog(false)}
          identityFingerprint={fingerprint || ''}
          onImportComplete={() => loadContacts()}
        />
      </CardContent>
    </Card>
  );
}
