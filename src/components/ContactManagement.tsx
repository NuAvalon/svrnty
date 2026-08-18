"use client";

import React, { useState, useEffect, useCallback } from 'react';
import {
  Card, CardHeader, CardTitle, CardContent, CardDescription
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { SVRNTY_DOMAIN } from '@/lib/config/domain';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import {
  Shield, Mail, UserPlus, Search,
  Share2, Trash2, Check, Edit, Download, Upload, RefreshCw,
  FileJson, Eye, ChevronRight, ShieldOff, ShieldCheck, Copy, HeartCrack
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
import { ContactShareDialog } from '@/components/ContactShareDialog';
import { ImportContactsDialog } from '@/components/ImportContactsDialog';
import { ShardGiveDialog } from '@/components/ShardGiveDialog';
import {
  getAllContacts, addContact, updateContact, removeContact,
  getContactByFingerprint, loadKey,
  type ContactRecord,
} from '@/lib/identity/client-store';
import { buildSignedIdentityCard, classifyImportedCard } from '@/lib/identity/identity-card-sign';

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
  onContactsChange?: () => void;
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

// Convert IndexedDB ContactRecord to component Contact type
function recordToContact(r: ContactRecord): Contact {
  return {
    id: r.id,
    name: r.name || '',
    email: r.email || '',
    fingerprint: r.fingerprint || '',
    public_key: r.public_key || '',
    trust_level: (r.trust_level as Contact['trust_level']) || 'unverified',
    added_at: r.added_at || new Date().toISOString(),
    verified_at: r.verified_at,
    metadata: r.metadata,
  };
}

// --- Main Component ---

export function ContactManagement({ identity, onContactsChange }: ContactsProps) {
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
  const [showImportDialog, setShowImportDialog] = useState(false);
  const [showShareIdentityDialog, setShowShareIdentityDialog] = useState(false);
  const [showImportExchangeDialog, setShowImportExchangeDialog] = useState(false);
  const [showVcardImport, setShowVcardImport] = useState(false);
  const [showShardGiveDialog, setShowShardGiveDialog] = useState(false);
  const [vaultExporting, setVaultExporting] = useState(false);

  // Form state
  const [newContactForm, setNewContactForm] = useState({
    name: '', email: '', fingerprint: '', public_key: '',
  });
  const [lookupInput, setLookupInput] = useState('');
  const [lookupLoading, setLookupLoading] = useState(false);
  const [lookupMessage, setLookupMessage] = useState<string | null>(null);
  const [editContactForm, setEditContactForm] = useState({
    id: '', name: '', email: '', fingerprint: '', public_key: '',
    notes: '',
  });

  // Share state
  const [importData, setImportData] = useState('');
  const [importError, setImportError] = useState<string | null>(null);
  const [exchangePackage, setExchangePackage] = useState('');
  const [exchangeImportData, setExchangeImportData] = useState('');
  const [exchangeResult, setExchangeResult] = useState<{ success: boolean; message: string } | null>(null);

  const fingerprint = identity?.identity?.fingerprint;

  // --- IndexedDB operations ---

  const loadContacts = useCallback(async () => {
    if (!fingerprint) return;
    try {
      setLoading(true);
      setError(null);
      const records = await getAllContacts(fingerprint);
      setContacts(records.map(recordToContact));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load contacts');
      setContacts([]);
    } finally {
      setLoading(false);
    }
  }, [fingerprint]);

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

  const handleLookup = async () => {
    if (!lookupInput.trim()) return;
    setLookupLoading(true);
    setLookupMessage(null);
    setError(null);
    try {
      // Strip URL prefix if given
      let slug = lookupInput.trim();
      slug = slug.replace(/^https?:\/\//, '').replace(/^(www\.)?svrnty\.is\/?/, '').replace(/^\/?(u\/)?/, '');
      if (!slug) throw new Error('Enter a slug or fingerprint');

      // Try slug lookup first
      const res = await fetch(`/slug/${slug}`);
      if (!res.ok) throw new Error(`Not found: ${slug}`);
      const slugData = await res.json();

      if (slugData.available) throw new Error(`No identity found for "${slug}"`);

      // Fetch full identity from /u/ endpoint
      const idRes = await fetch(`/u/${slug}`);
      if (!idRes.ok) throw new Error(`Could not load identity for "${slug}"`);

      // The /u/ page returns HTML, so use the registration API
      const regRes = await fetch(`/api/auth/slug/${slug}`);
      if (!regRes.ok) throw new Error(`Could not load identity for "${slug}"`);
      const data = await regRes.json();

      setNewContactForm({
        name: data.display_name || slug,
        email: data.email || '',
        fingerprint: data.fingerprint || '',
        public_key: data.public_key || '',
      });
      setLookupMessage(`Found: ${data.display_name || slug}`);
    } catch (err) {
      setLookupMessage(null);
      setError(err instanceof Error ? err.message : 'Lookup failed');
    } finally {
      setLookupLoading(false);
    }
  };

    const handleAddContact = async () => {
    if (!fingerprint) return;
    try {
      setLoading(true);
      setError(null);
      if (!newContactForm.name || !newContactForm.fingerprint) {
        throw new Error('Name and fingerprint are required');
      }
      if (newContactForm.fingerprint === fingerprint) {
        throw new Error('You cannot add yourself as a contact');
      }
      await addContact(fingerprint, {
        name: newContactForm.name,
        email: newContactForm.email,
        fingerprint: newContactForm.fingerprint,
        public_key: newContactForm.public_key,
        trust_level: 'unverified',
      });
      setNewContactForm({ name: '', email: '', fingerprint: '', public_key: '' });
      setShowAddDialog(false);
      await loadContacts();
      onContactsChange?.();
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
      await updateContact(editContactForm.id, {
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
      });
      setShowEditDialog(false);
      await loadContacts();
      onContactsChange?.();
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
      await removeContact(contactId);
      setShowDetailDialog(false);
      setShowEditDialog(false);
      await loadContacts();
      onContactsChange?.();
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
      await updateContact(contact.id, {
        trust_level: newLevel,
        ...(newLevel === 'trusted' && { verified_at: new Date().toISOString() }),
      });
      // Satellite trust commitment (blind — satellite never sees who you're trusting)
      if (contact.fingerprint) {
        const fps = [fingerprint, contact.fingerprint].sort();
        const hashInput = fps.join('') + 'trust-v1';
        const encoder = new TextEncoder();
        const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(hashInput));
        const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        try {
          if (newLevel === 'trusted') {
            await fetch('/api/trust/commit', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ fingerprint, commitment_hash: hashHex }),
            });
          } else {
            await fetch('/api/trust/revoke', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ fingerprint, commitment_hash: hashHex }),
            });
          }
        } catch { /* satellite offline — local trust still works */ }
      }
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
    if (!fingerprint || !identity) return;
    try {
      setLoading(true);
      setError(null);
      // Build + SIGN the exchange package (carries pq_kem/pq_sig under the signature). Copy/paste is
      // an untrusted carrier — the card MUST be signed so the receiver can re-verify pq wasn't swapped
      // (an unsigned card is the HNDL hole). Signing needs the unlocked private key.
      const key = await loadKey(fingerprint);
      if (!key) throw new Error('Unlock your identity first to share a signed card.');
      const signed = await buildSignedIdentityCard(identity, key.privateKey, key.passphrase);
      setExchangePackage(JSON.stringify(signed, null, 2));
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
      const card = JSON.parse(exchangeImportData.trim());
      const contactIdentity = card.identity || card;
      if (!contactIdentity.fingerprint || !contactIdentity.public_key) {
        throw new Error('Invalid exchange package: missing fingerprint or public key');
      }
      if (contactIdentity.fingerprint === fingerprint) {
        throw new Error('You cannot import yourself as a contact');
      }

      // Fail-closed disposition — copy/paste is an untrusted carrier, so it re-verifies the card
      // exactly like the relay/QR path (Flint spec §4/§5; the ONE shared decision, no drift).
      const d = await classifyImportedCard(card);
      if (!d.importClassical) {
        // Branch 1 — fp↔key mismatch / malformed: refuse the card entirely.
        setExchangeResult({ success: false, message: 'This card could not be verified — its fingerprint does not match its key, so it was not imported. Ask them to send a fresh one.' });
        return;
      }

      const displayName = contactIdentity.display_name || contactIdentity.name || 'Unknown';
      const pqFields = d.pq
        ? { pq_kem_public_key: d.pq.pq_kem_public_key, pq_sig_public_key: d.pq.pq_sig_public_key }
        : {};

      const existing = await getContactByFingerprint(fingerprint, contactIdentity.fingerprint);
      if (existing) {
        // Upgrade-on-re-exchange (Flint §7#5): a known contact re-sharing a VALID pq card back-fills
        // pq on the existing edge — no duplicate; NEVER silently replaces a different stored pq
        // (that's a deliberate, lineage-tracked rotation, not a re-import side effect).
        if (d.alarm === 'loud') {
          setExchangeResult({ success: false, message: `A card for "${displayName}" could not be verified — possible tampering. Your existing contact is unchanged; ask them to re-share over a secure link.` });
        } else if (d.pq && !existing.pq_kem_public_key) {
          await updateContact(existing.id, pqFields);
          setExchangeResult({ success: true, message: `Updated "${displayName}" — their post-quantum key is now stored.` });
        } else {
          setExchangeResult({ success: true, message: `You already have "${displayName}".` });
        }
      } else {
        await addContact(fingerprint, {
          name: displayName,
          email: contactIdentity.email || '',
          fingerprint: contactIdentity.fingerprint,
          public_key: contactIdentity.public_key,
          trust_level: 'unverified',
          metadata: { connection_method: 'manual' as const },
          ...pqFields, // present ONLY on branch 4b (authenticated pq); dropped on 2/3/4a/4c
        } as Omit<ContactRecord, 'id' | 'added_at' | 'owner_fingerprint'>);
        // Message tracks the pq disposition — loud only on a present-but-invalid signature (branch 3).
        const message =
          d.alarm === 'loud'
            ? `Added "${displayName}" (classical only) — could not verify their key material; possible tampering. Ask them to re-share over a secure link.`
            : d.alarm === 'soft-info'
              ? `Added "${displayName}" — their post-quantum key uses an unsupported format, so classical only.`
              : `Contact "${displayName}" added successfully.`;
        setExchangeResult({ success: d.alarm !== 'loud', message });
      }
      await loadContacts();
    } catch (err) {
      if (err instanceof SyntaxError) {
        setExchangeResult({ success: false, message: 'Invalid JSON — paste a valid identity exchange package' });
      } else {
        setExchangeResult({ success: false, message: err instanceof Error ? err.message : 'Failed to import' });
      }
    } finally {
      setLoading(false);
    }
  };

  const handleVaultExport = async () => {
    if (!fingerprint) return;
    try {
      setVaultExporting(true);
      setError(null);
      // Load all data from IndexedDB
      const { exportAll, loadPQKeys, loadVault: loadVaultData } = await import('@/lib/identity/client-store');
      const backup = await exportAll(fingerprint, true);
      const pqKeys = await loadPQKeys(fingerprint);
      const vaultData = await loadVaultData(fingerprint);

      // Format identity for vault module (VaultIdentity shape)
      const vaultIdentity = backup.identity; // already in full identity format from storeIdentity

      // Format keys for vault module (VaultKeys shape)
      const vaultKeys = {
        classical: backup.keys || { privateKey: '', passphrase: '' },
        pq: pqKeys || null,
      };

      // Build trust graph from contacts
      const trustGraph = {
        edges: backup.contacts.map((c: any) => ({
          source: fingerprint,
          target: c.fingerprint,
          trust_level: c.trust_level || 'unverified',
          added_at: c.added_at,
          metadata: { name: c.name, email: c.email, public_key: c.public_key, ...c.metadata },
        })),
        contacts: backup.contacts,
      };

      // Pack into vault format
      const { createVaultContents, packVault, downloadVault } = await import('@/lib/sync/vault');
      const contents = createVaultContents(
        vaultIdentity,
        vaultKeys,
        trustGraph,
        { safeWord: '' },
        vaultData || null,
      );
      const passphrase = prompt('Enter a passphrase to encrypt your vault.\nThis protects your private keys, contacts, and trust network.\n\nAt least 12 characters. This is your vault passphrase, not your recovery phrase — you will need it to restore.');
      if (!passphrase) { setVaultExporting(false); return; }
      const packed = await packVault(contents, passphrase);
      downloadVault(packed);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to export vault');
    } finally {
      setVaultExporting(false);
    }
  };

  const handleImportContacts = async () => {
    if (!fingerprint || !importData) return;
    try {
      setLoading(true);
      setImportError(null);
      const parsed = JSON.parse(importData);
      const contactList = Array.isArray(parsed) ? parsed : (parsed.contacts || []);
      for (const c of contactList) {
        if (c.fingerprint && c.public_key) {
          await addContact(fingerprint, {
            name: c.name || c.display_name || 'Unknown',
            email: c.email || '',
            fingerprint: c.fingerprint,
            public_key: c.public_key,
            trust_level: c.trust_level || 'unverified',
            metadata: c.metadata,
          });
        }
      }
      setImportData('');
      setShowImportDialog(false);
      await loadContacts();
    } catch (err) {
      if (err instanceof SyntaxError) {
        setImportError('Invalid JSON format');
      } else {
        setImportError(err instanceof Error ? err.message : 'Failed to import');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleExportContacts = async () => {
    if (!fingerprint) return;
    try {
      setLoading(true);
      setError(null);
      const records = await getAllContacts(fingerprint);
      const exportData = JSON.stringify({ contacts: records, exported_at: new Date().toISOString() }, null, 2);
      const blob = new Blob([exportData], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'soverentity-contacts.json';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
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
            <Button variant="outline" size="sm" onClick={() => setShowVcardImport(true)} data-testid="import-contacts-trigger">
              <Upload className="h-4 w-4 mr-2" />
              Import contacts
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <Share2 className="h-4 w-4 mr-2" />
                  More
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuLabel>Vault</DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={handleVaultExport} disabled={vaultExporting}>
                  <Download className="h-4 w-4 mr-2 text-amber-500" />
                  {vaultExporting ? 'Exporting...' : 'Export Vault (.svrnty)'}
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuLabel>Data</DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={handleExportContacts}>
                  <FileJson className="h-4 w-4 mr-2" />
                  Export Contacts as JSON
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setShowImportDialog(true)}>
                  <Upload className="h-4 w-4 mr-2" />
                  Import Contacts from JSON
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

        {/* Tabs — contacts (all) and trusted (subset) */}
        <Tabs defaultValue="all" value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="mb-4 w-full sm:w-auto">
            <TabsTrigger value="all">
              Contacts ({contacts.length})
            </TabsTrigger>
            <TabsTrigger value="trusted">
              Trusted ({trustedCount})
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
                        {isTrusted(contact) ? <><ShieldOff className="h-4 w-4 mr-1" /> Untrust</> : <><ShieldCheck className="h-4 w-4 mr-1" /> Trust</>}
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
                <label className="text-sm font-medium">Look up by URL</label>
                <div className="flex gap-2">
                  <Input
                    value={lookupInput}
                    onChange={e => setLookupInput(e.target.value)}
                    placeholder={`${SVRNTY_DOMAIN}/name or slug`}
                    onKeyDown={e => e.key === 'Enter' && handleLookup()}
                  />
                  <Button variant="outline" onClick={handleLookup} disabled={lookupLoading || !lookupInput.trim()}>
                    {lookupLoading ? 'Looking up...' : 'Lookup'}
                  </Button>
                </div>
                {lookupMessage && <p className="text-xs text-green-500">{lookupMessage}</p>}
                <p className="text-xs text-muted-foreground">Or fill in manually below</p>
              </div>
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
              <Button onClick={handleAddContact} disabled={loading || !newContactForm.name || !newContactForm.fingerprint}>
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
                          ? <><ShieldOff className="h-4 w-4 mr-1" /> Untrust</>
                          : <><ShieldCheck className="h-4 w-4 mr-1" /> Trust</>
                        }
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => { openEditDialog(selectedContact); setShowDetailDialog(false); }}>
                        <Edit className="h-4 w-4 mr-1" /> Edit
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => { setShowShardGiveDialog(true); setShowDetailDialog(false); }}
                        className="text-amber-400 border-amber-500/30"
                      >
                        <HeartCrack className="h-4 w-4 mr-1" /> Give a piece
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

        {/* Share Identity — QR, NFC, Short Code, Copy */}
        <ContactShareDialog
          open={showShareIdentityDialog}
          onClose={() => setShowShareIdentityDialog(false)}
          exchangePackage={exchangePackage}
          fingerprint={fingerprint || ''}
        />

        {/* Give a piece of your recovery — "the tear" */}
        <ShardGiveDialog
          open={showShardGiveDialog}
          onClose={() => setShowShardGiveDialog(false)}
          ownerFingerprint={fingerprint || ''}
          ownerName={identity?.identity?.name || identity?.identity?.display_name || 'a keeper'}
          contact={selectedContact}
          onGiven={() => { /* custody recorded in IndexedDB; lattice/custody badges are #484 */ }}
        />

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

        {fingerprint && (
          <ImportContactsDialog
            ownerFingerprint={fingerprint}
            open={showVcardImport}
            onOpenChange={setShowVcardImport}
            onImported={loadContacts}
          />
        )}

      </CardContent>
    </Card>
  );
}
