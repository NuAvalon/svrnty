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
  FileJson, Shield as ShieldIcon, Eye, EyeOff
} from 'lucide-react';
import { 
  Dialog, DialogContent, DialogDescription, DialogHeader,
  DialogTitle, DialogTrigger, DialogFooter 
} from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger
} from '@/components/ui/dropdown-menu';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';

// Import the secure import/export dialogs
import { SecureExportDialog, SecureImportDialog } from '@/components/SecureImportExportDialogs';

// Define the Contact type here since you might not have the full import path ready
interface Contact {
  id: string;
  name: string;
  email: string;
  fingerprint: string;
  public_key: string;
  trust_level: 'unverified' | 'verified' | 'trusted';
  added_at: string;
  verified_at?: string;
  metadata?: {
    notes?: string;
    tags?: string[];
    connection_method?: 'manual' | 'qr' | 'burner_link' | 'mutual';
    mutual_contacts?: string[]; // Array of fingerprints
  };
}

interface ContactsProps {
  identity: any; // Using any for now since we don't have the full identity type
}

export function ContactManagement({ identity }: ContactsProps) {
  // State for contacts
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedContact, setSelectedContact] = useState<Contact | null>(null);
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [showQRDialog, setShowQRDialog] = useState(false);
  const [showShareDialog, setShowShareDialog] = useState(false);
  const [showImportDialog, setShowImportDialog] = useState(false);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [showDetailDialog, setShowDetailDialog] = useState(false);
  const [showSecureExportDialog, setShowSecureExportDialog] = useState(false);
  const [showSecureImportDialog, setShowSecureImportDialog] = useState(false);
  
  // Form state for adding contacts
  const [newContactForm, setNewContactForm] = useState({
    name: '',
    email: '',
    fingerprint: '',
    public_key: '',
  });

  // Edit Contact form state
  const [editContactForm, setEditContactForm] = useState({
    id: '',
    name: '',
    email: '',
    fingerprint: '',
    public_key: '',
    trust_level: 'unverified' as 'unverified' | 'verified' | 'trusted',
    notes: ''
  });

  // QR code state
  const [qrCodeData, setQrCodeData] = useState('');
  const [burnerLink, setBurnerLink] = useState('');
  
  // Import/Export state
  const [importData, setImportData] = useState('');
  const [importError, setImportError] = useState<string | null>(null);
  
  // Load contacts on component mount and when identity changes
  const loadContacts = useCallback(async () => {
    if (!identity?.identity?.fingerprint) {
      console.log('No identity fingerprint found, skipping contact load');
      return;
    }
    
    try {
      setLoading(true);
      setError(null);
      
      console.log(`Loading contacts for fingerprint: ${identity.identity.fingerprint}`);
      const response = await fetch(
        `/api/contacts?fingerprint=${identity.identity.fingerprint}`, 
        { method: 'GET' }
      );
      
      console.log('Response status:', response.status);
      const contentType = response.headers.get('content-type');
      console.log('Content type:', contentType);
      
      if (!contentType || !contentType.includes('application/json')) {
        console.error('Non-JSON response received');
        throw new Error('Invalid response from server');
      }
      
      const data = await response.json();
      console.log('Contact API response:', data);
      
      if (!response.ok) {
        console.error('API returned error:', data);
        throw new Error(data.error || 'Failed to load contacts');
      }
      
      setContacts(data.contacts || []);
      console.log(`Loaded ${data.contacts?.length || 0} contacts using ${data.storage} storage`);
      
      // Show a storage mode warning for in-memory
      if (data.storage === 'in-memory') {
        console.warn('Using in-memory storage. Reason:', data.fallbackReason);
      }
    } catch (err) {
      console.error('Error loading contacts:', err);
      setError(err instanceof Error ? err.message : 'An error occurred loading contacts');
      setContacts([]);
    } finally {
      setLoading(false);
    }
  }, [identity?.identity?.fingerprint]);

  useEffect(() => {
    if (identity?.identity?.fingerprint) {
      loadContacts();
    }
  }, [identity, loadContacts]);
  
  // Filter contacts based on active tab and search query
  const filteredContacts = contacts.filter(contact => {
    // First filter by tab
    if (activeTab !== 'all' && contact.trust_level !== activeTab) {
      return false;
    }
    
    // Then filter by search query if any
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        contact.name.toLowerCase().includes(query) ||
        contact.email.toLowerCase().includes(query) ||
        contact.fingerprint.toLowerCase().includes(query)
      );
    }
    
    return true;
  });

  // Open the edit dialog for a contact
  const openEditDialog = (contact: Contact) => {
    setSelectedContact(contact);
    setEditContactForm({
      id: contact.id,
      name: contact.name,
      email: contact.email,
      fingerprint: contact.fingerprint,
      public_key: contact.public_key,
      trust_level: contact.trust_level,
      notes: contact.metadata?.notes || ''
    });
    setShowEditDialog(true);
  };

  // Open the detail view for a contact
  const openDetailView = (contact: Contact) => {
    setSelectedContact(contact);
    setShowDetailDialog(true);
  };

  const handleAddContact = async () => {
    if (!identity?.identity?.fingerprint) return;
    
    try {
      setLoading(true);
      setError(null);
      
      // Validate form
      if (!newContactForm.name || !newContactForm.email || !newContactForm.fingerprint || !newContactForm.public_key) {
        throw new Error('All fields are required');
      }
      
      const normalizedPublicKey = newContactForm.public_key.trim();
      if (!normalizedPublicKey.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
        setError('Invalid PGP public key format');
        return;
      }

      // Add this check before submission:
      if (newContactForm.fingerprint === identity.identity.fingerprint) {
        setError('You cannot add yourself as a contact');
        return;
      }

      console.log('Adding contact with data:', {
        fingerprint: identity.identity.fingerprint,
        contactData: {
          ...newContactForm,
          trust_level: 'unverified'
        }
      });

      const response = await fetch(`/api/contacts`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fingerprint: identity.identity.fingerprint,
          contact: {
            ...newContactForm,
            trust_level: 'unverified'
          }
        }),
      });
      
      const contentType = response.headers.get('content-type');
      console.log('Response content type:', contentType);
      console.log('Response status:', response.status);
      
      if (!contentType || !contentType.includes('application/json')) {
        console.error('Non-JSON response received');
        const textResponse = await response.text();
        console.error('Raw response:', textResponse);
        throw new Error('Invalid response from server');
      }
      
      const data = await response.json();
      console.log('Add contact API response:', data);
      
      if (!response.ok) {
        const errorMessage = data.error || `Failed to add contact (${response.status})`;
        console.log('Contact validation failed:', errorMessage); // Changed from error to log
        throw new Error(errorMessage);
      }
      
      // Add the contact to local state immediately
      setContacts(prev => [...prev, data.contact]);
      
      // Reset form
      setNewContactForm({
        name: '',
        email: '',
        fingerprint: '',
        public_key: '',
      });
      setShowAddDialog(false);
      
      // Also reload contacts to be sure
      await loadContacts();
      
    } catch (err) {
      console.error('Error adding contact:', err);
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateContact = async () => {
    if (!identity?.identity?.fingerprint) return;
    
    try {
      setLoading(true);
      setError(null);
      
      // Validate form
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
            mutual_contacts: selectedContact.metadata.mutual_contacts
          } : {})
        }
      };
      
      console.log('Updating contact with data:', {
        fingerprint: identity.identity.fingerprint,
        contactId: editContactForm.id,
        updates
      });
      
      const response = await fetch('/api/contacts', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fingerprint: identity.identity.fingerprint,
          contactId: editContactForm.id,
          updates
        }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to update contact');
      }
      
      // Update the contact in local state
      setContacts(prevContacts => 
        prevContacts.map(c => 
          c.id === editContactForm.id ? { ...c, ...updates } : c
        )
      );
      
      // Reset form and close dialog
      setShowEditDialog(false);
      
      // Reload contacts to be sure
      await loadContacts();
      
    } catch (err) {
      console.error('Error updating contact:', err);
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };
  
  const handleDeleteContact = async (contactId: string) => {
    if (!identity?.identity?.fingerprint) return;
    
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch(
        `/api/contacts?fingerprint=${identity.identity.fingerprint}&contactId=${contactId}`,
        { method: 'DELETE' }
      );
      
      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        throw new Error('Invalid response from server');
      }
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to delete contact');
      }
      
      // Close any open dialogs that might be showing the deleted contact
      setShowDetailDialog(false);
      setShowEditDialog(false);
      
      // Reload contacts
      await loadContacts();
      
    } catch (err) {
      console.error('Error deleting contact:', err);
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };
  
  // Update contact trust level
  const handleUpdateTrustLevel = async (contactId: string, trustLevel: 'unverified' | 'verified' | 'trusted') => {
    if (!identity?.identity?.fingerprint) return;
    
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch('/api/contacts', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fingerprint: identity.identity.fingerprint,
          contactId,
          updates: {
            trust_level: trustLevel,
            ...(trustLevel === 'verified' && { verified_at: new Date().toISOString() })
          }
        }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to update contact');
      }
      
      // Update local state if detail dialog is open
      if (selectedContact && selectedContact.id === contactId) {
        setSelectedContact({
          ...selectedContact,
          trust_level: trustLevel,
          ...(trustLevel === 'verified' && { verified_at: new Date().toISOString() })
        });
      }
      
      // Reload contacts
      await loadContacts();
      
    } catch (err) {
      console.error('Error updating contact:', err);
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };
  
  // Generate QR code for sharing
  const handleGenerateQRCode = async () => {
    if (!identity?.identity?.fingerprint) return;
    
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch('/api/contacts/share', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fingerprint: identity.identity.fingerprint,
          type: 'qr'
        }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to generate QR code');
      }
      
      setQrCodeData(data.qrData);
      setShowQRDialog(true);
      
    } catch (err) {
      console.error('Error generating QR code:', err);
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };
  
  // Generate burner link
  const handleGenerateBurnerLink = async () => {
    if (!identity?.identity?.fingerprint) return;
    
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch('/api/contacts/share', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fingerprint: identity.identity.fingerprint,
          type: 'burner',
          expireInHours: 48
        }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to generate burner link');
      }
      
      setBurnerLink(data.burnerLink);
      setShowShareDialog(true);
      
    } catch (err) {
      console.error('Error generating burner link:', err);
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };
  
  // Import contacts
  const handleImportContacts = async () => {
    if (!identity?.identity?.fingerprint) return;
    
    try {
      setLoading(true);
      setImportError(null);
      
      // Validate import data
      if (!importData) {
        throw new Error('Import data is required');
      }
      
      const response = await fetch('/api/contacts/import', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fingerprint: identity.identity.fingerprint,
          contactsData: importData,
          overwrite: false
        }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to import contacts');
      }
      
      // Reset form and reload contacts
      setImportData('');
      setShowImportDialog(false);
      await loadContacts();
      
    } catch (err) {
      console.error('Error importing contacts:', err);
      setImportError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };
  
  // Export contacts
  const handleExportContacts = async () => {
    if (!identity?.identity?.fingerprint) return;
    
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch(`/api/contacts/export?fingerprint=${identity.identity.fingerprint}`, {
        method: 'GET'
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to export contacts');
      }
      
      // Create download link
      const blob = new Blob([data.contacts], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'soverentity-contacts.json';
      document.body.appendChild(a);
      a.click();
      a.remove();
      
    } catch (err) {
      console.error('Error exporting contacts:', err);
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };
  
  // Process a contact exchange package
  const handleProcessExchangeData = async (exchangeData: string) => {
    if (!identity?.identity?.fingerprint) return;
    
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch('/api/contacts/process', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fingerprint: identity.identity.fingerprint,
          exchangeData
        }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to process contact data');
      }
      
      // Reload contacts
      await loadContacts();
      
    } catch (err) {
      console.error('Error processing contact data:', err);
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="w-full shadow-md">
      <CardHeader className="bg-gradient-to-r from-slate-100 to-slate-50 dark:from-slate-900 dark:to-slate-800">
        <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4">
          <CardTitle className="flex items-center gap-2 text-xl sm:text-2xl">
            <UserCheck className="h-6 w-6 text-blue-600 dark:text-blue-400" />
            <span>Sovereign Contacts</span>
          </CardTitle>
          <div className="flex flex-wrap gap-2">
            <Button 
              variant="outline" 
              size="sm"
              className="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm hover:bg-white dark:hover:bg-slate-700"
              onClick={() => setShowQRDialog(true)}
            >
              <QrCode className="h-4 w-4 mr-2 text-indigo-600 dark:text-indigo-400" />
              Share via QR
            </Button>
            <Button 
              variant="outline" 
              size="sm"
              className="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm hover:bg-white dark:hover:bg-slate-700"
              onClick={handleGenerateBurnerLink}
            >
              <Link className="h-4 w-4 mr-2 text-emerald-600 dark:text-emerald-400" />
              Create Burner Link
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button 
                  variant="outline" 
                  size="sm"
                  className="bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm hover:bg-white dark:hover:bg-slate-700"
                >
                  <Share2 className="h-4 w-4 mr-2 text-violet-600 dark:text-violet-400" />
                  More
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuLabel>Import & Export</DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => setShowSecureExportDialog(true)}>
                  <ShieldIcon className="h-4 w-4 mr-2 text-green-600" />
                  Secure Export (Encrypted)
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setShowSecureImportDialog(true)}>
                  <Lock className="h-4 w-4 mr-2 text-blue-600" />
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
        <CardDescription className="mt-2">
          Your encrypted contact book. All data is secured with PGP encryption.
        </CardDescription>
      </CardHeader>

      <CardContent className="p-4 sm:p-6">
        {error && (
          <Alert variant="destructive" className="mb-4">
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-6">
          <div className="relative w-full sm:w-64">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search contacts..."
              className="pl-8 bg-slate-50 dark:bg-slate-900 focus:bg-white"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
          <Button 
            onClick={() => setShowAddDialog(true)}
            className="w-full sm:w-auto bg-blue-600 hover:bg-blue-700 text-white"
          >
            <UserPlus className="h-4 w-4 mr-2" />
            Add Contact
          </Button>
        </div>

        {/* Add Contact Dialog */}
        <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Add New Contact</DialogTitle>
              <DialogDescription>
                Enter the contact details to add a new contact securely.
              </DialogDescription>
            </DialogHeader>
            
            {error && (
              <Alert variant="destructive" className="mb-4">
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            
            <div className="space-y-4 py-4">
              <div className="grid w-full items-center gap-1.5">
                <label htmlFor="name" className="text-sm font-medium">Name</label>
                <Input
                  id="name"
                  value={newContactForm.name}
                  onChange={(e) => setNewContactForm(prev => ({ ...prev, name: e.target.value }))}
                  placeholder="Contact name"
                />
              </div>
              
              <div className="grid w-full items-center gap-1.5">
                <label htmlFor="email" className="text-sm font-medium">Email</label>
                <Input
                  id="email"
                  type="email"
                  value={newContactForm.email}
                  onChange={(e) => setNewContactForm(prev => ({ ...prev, email: e.target.value }))}
                  placeholder="contact@example.com"
                />
              </div>
              
              <div className="grid w-full items-center gap-1.5">
                <label htmlFor="fingerprint" className="text-sm font-medium">PGP Fingerprint</label>
                <Input
                  id="fingerprint"
                  value={newContactForm.fingerprint}
                  onChange={(e) => setNewContactForm(prev => ({ ...prev, fingerprint: e.target.value }))}
                  placeholder="Enter PGP fingerprint"
                />
              </div>
              
              <div className="grid w-full items-center gap-1.5">
                <label htmlFor="public_key" className="text-sm font-medium">Public Key</label>
                <Textarea
                  id="public_key"
                  value={newContactForm.public_key}
                  onChange={(e) => setNewContactForm(prev => ({ ...prev, public_key: e.target.value }))}
                  placeholder="Paste PGP public key here"
                  className="font-mono text-xs"
                  rows={6}
                />
              </div>
            </div>
            
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowAddDialog(false)}>Cancel</Button>
              <Button 
                onClick={handleAddContact} 
                disabled={loading || !newContactForm.name || !newContactForm.email || 
                        !newContactForm.fingerprint || !newContactForm.public_key}
                className="bg-blue-600 hover:bg-blue-700"
              >
                {loading ? 
                  <><RefreshCw className="h-4 w-4 mr-2 animate-spin" />Adding...</> : 
                  <><UserPlus className="h-4 w-4 mr-2" />Add Contact</>
                }
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Edit Contact Dialog */}
        <Dialog open={showEditDialog} onOpenChange={setShowEditDialog}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Edit Contact</DialogTitle>
              <DialogDescription>
                Update contact details.
              </DialogDescription>
            </DialogHeader>
            
            {error && (
              <Alert variant="destructive" className="mb-4">
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            
            <div className="space-y-4 py-4">
              <div className="grid w-full items-center gap-1.5">
                <label htmlFor="edit-name" className="text-sm font-medium">Name</label>
                <Input
                  id="edit-name"
                  value={editContactForm.name}
                  onChange={(e) => setEditContactForm(prev => ({ ...prev, name: e.target.value }))}
                  placeholder="Contact name"
                />
              </div>
              
              <div className="grid w-full items-center gap-1.5">
                <label htmlFor="edit-email" className="text-sm font-medium">Email</label>
                <Input
                  id="edit-email"
                  type="email"
                  value={editContactForm.email}
                  onChange={(e) => setEditContactForm(prev => ({ ...prev, email: e.target.value }))}
                  placeholder="contact@example.com"
                />
              </div>
              
              <div className="grid w-full items-center gap-1.5">
                <label htmlFor="edit-notes" className="text-sm font-medium">Notes</label>
                <Textarea
                  id="edit-notes"
                  value={editContactForm.notes}
                  onChange={(e) => setEditContactForm(prev => ({ ...prev, notes: e.target.value }))}
                  placeholder="Add notes about this contact..."
                  rows={3}
                />
              </div>
              
              <div className="grid w-full items-center gap-1.5">
                <label htmlFor="edit-fingerprint" className="text-sm font-medium">PGP Fingerprint</label>
                <Input
                  id="edit-fingerprint"
                  value={editContactForm.fingerprint}
                  readOnly
                  className="bg-slate-50 dark:bg-slate-800 font-mono text-xs"
                />
                <p className="text-xs text-slate-500">Fingerprint cannot be changed</p>
              </div>
            </div>
            
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowEditDialog(false)}>Cancel</Button>
              <Button 
                onClick={handleUpdateContact} 
                disabled={loading || !editContactForm.name || !editContactForm.email}
                className="bg-blue-600 hover:bg-blue-700"
              >
                {loading ? 
                  <><RefreshCw className="h-4 w-4 mr-2 animate-spin" />Updating...</> : 
                  <><Check className="h-4 w-4 mr-2" />Save Changes</>
                }
              </Button>
            </DialogFooter>
            </DialogContent>
        </Dialog>

        {/* Contact Detail Dialog */}

        <Dialog open={showDetailDialog} onOpenChange={setShowDetailDialog}>
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <div className={`flex-shrink-0 rounded-full h-8 w-8 flex items-center justify-center 
                  ${selectedContact?.trust_level === 'trusted' ? 'bg-green-100 dark:bg-green-900/30' : 
                    selectedContact?.trust_level === 'verified' ? 'bg-blue-100 dark:bg-blue-900/30' : 
                    'bg-yellow-100 dark:bg-yellow-900/30'}`}
                >
                  {selectedContact?.trust_level === 'trusted' ? (
                    <Check className="h-5 w-5 text-green-600 dark:text-green-500" />
                  ) : selectedContact?.trust_level === 'verified' ? (
                    <UserCheck className="h-5 w-5 text-blue-600 dark:text-blue-500" />
                  ) : (
                    <Lock className="h-5 w-5 text-yellow-600 dark:text-yellow-500" />
                  )}
                </div>
                <span>{selectedContact?.name}</span>
              </DialogTitle>
              <DialogDescription>
                Contact details and management options.
              </DialogDescription>
            </DialogHeader>
            
            {selectedContact && (
              <div className="space-y-6">
                {/* Basic info */}
                <div className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Email</h4>
                      <div className="flex items-center gap-1 mt-1">
                        <Mail className="h-4 w-4 text-slate-400" />
                        <span className="text-base">{selectedContact.email}</span>
                      </div>
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Trust Level</h4>
                      <div className="mt-1">
                        <Badge className={`
                          ${selectedContact.trust_level === 'trusted' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100' : 
                            selectedContact.trust_level === 'verified' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-100' : 
                            'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-100'}
                        `}>
                          {selectedContact.trust_level === 'trusted' ? 'Trusted' : 
                          selectedContact.trust_level === 'verified' ? 'Verified' : 'Unverified'}
                        </Badge>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">PGP Fingerprint</h4>
                    <div className="mt-1 font-mono text-sm bg-slate-50 dark:bg-slate-800 p-2 rounded border border-slate-200 dark:border-slate-700">
                      {selectedContact.fingerprint.match(/.{1,4}/g)?.join(' ')}
                    </div>
                  </div>

                  {selectedContact.metadata?.notes && (
                    <div>
                      <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">Notes</h4>
                      <div className="mt-1 p-3 bg-slate-50 dark:bg-slate-800 rounded-md">
                        <p className="text-sm whitespace-pre-wrap">{selectedContact.metadata.notes}</p>
                      </div>
                    </div>
                  )}

                  {/* Additional info */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                    <div>
                      <h4 className="font-medium text-gray-500 dark:text-gray-400">Added</h4>
                      <p>{new Date(selectedContact.added_at).toLocaleDateString()}</p>
                    </div>
                    {selectedContact.verified_at && (
                      <div>
                        <h4 className="font-medium text-gray-500 dark:text-gray-400">Verified</h4>
                        <p>{new Date(selectedContact.verified_at).toLocaleDateString()}</p>
                      </div>
                    )}
                    {selectedContact.metadata?.connection_method && (
                      <div>
                        <h4 className="font-medium text-gray-500 dark:text-gray-400">Connection Method</h4>
                        <p className="capitalize">
                          {selectedContact.metadata.connection_method.replace('_', ' ')}
                        </p>
                      </div>
                    )}
                  </div>
                </div>

                {/* Actions */}
                <div className="border-t pt-4 flex flex-col sm:flex-row gap-2 justify-between">
                  <div className="flex gap-2">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="outline" size="sm">
                          <Filter className="h-4 w-4 mr-1" />
                          Trust Level
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent>
                        <DropdownMenuLabel>Set Trust Level</DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem 
                          onClick={() => {
                            handleUpdateTrustLevel(selectedContact.id, 'trusted');
                            setShowDetailDialog(false);
                          }}
                          disabled={selectedContact.trust_level === 'trusted'}
                        >
                          <Check className="h-4 w-4 mr-2 text-green-500" />
                          Trusted
                        </DropdownMenuItem>
                        <DropdownMenuItem 
                          onClick={() => {
                            handleUpdateTrustLevel(selectedContact.id, 'verified');
                            setShowDetailDialog(false);
                          }}
                          disabled={selectedContact.trust_level === 'verified'}
                        >
                          <UserCheck className="h-4 w-4 mr-2 text-blue-500" />
                          Verified
                        </DropdownMenuItem>
                        <DropdownMenuItem 
                          onClick={() => {
                            handleUpdateTrustLevel(selectedContact.id, 'unverified');
                            setShowDetailDialog(false);
                          }}
                          disabled={selectedContact.trust_level === 'unverified'}
                        >
                          <X className="h-4 w-4 mr-2 text-yellow-500" />
                          Unverified
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                    
                    <Button 
                      variant="outline" 
                      size="sm" 
                      onClick={() => {
                        openEditDialog(selectedContact);
                        setShowDetailDialog(false);
                      }}
                    >
                      <Edit className="h-4 w-4 mr-1" />
                      Edit
                    </Button>
                  </div>
                  
                  <Button 
                    variant="destructive" 
                    size="sm"
                    onClick={() => {
                      handleDeleteContact(selectedContact.id);
                      setShowDetailDialog(false);
                    }}
                  >
                    <Trash2 className="h-4 w-4 mr-1" />
                    Delete
                  </Button>
                </div>
              </div>
            )}
          </DialogContent>
        </Dialog>

        {/* QR Code Dialog */}
        <Dialog open={showQRDialog} onOpenChange={setShowQRDialog}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Share Contact via QR Code</DialogTitle>
              <DialogDescription>
                Let others scan this QR code to add you to their contacts.
              </DialogDescription>
            </DialogHeader>
            
            <div className="flex justify-center py-4">
              {qrCodeData ? (
                <div className="bg-white p-4 rounded-lg">
                  {/* This would be where you render the QR code using a library */}
                  <div className="text-center text-sm text-slate-500">
                    QR Code would be displayed here.
                  </div>
                </div>
              ) : (
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
              )}
            </div>
            
            <DialogFooter>
              <Button 
                variant="outline" 
                onClick={() => setShowQRDialog(false)}
              >
                Close
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Share Link Dialog */}
        <Dialog open={showShareDialog} onOpenChange={setShowShareDialog}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Share Contact via Link</DialogTitle>
              <DialogDescription>
                Share this link with others to add you to their contacts. The link expires in 48 hours.
              </DialogDescription>
            </DialogHeader>
            
            <div className="py-4">
              {burnerLink ? (
                <div className="space-y-4">
                  <div className="flex items-center gap-2">
                    <Input
                      value={burnerLink}
                      readOnly
                      className="font-mono text-sm"
                    />
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        navigator.clipboard.writeText(burnerLink);
                      }}
                    >
                      Copy
                    </Button>
                  </div>
                  <p className="text-sm text-slate-500">
                    This link will expire in 48 hours and can only be used once.
                  </p>
                </div>
              ) : (
                <div className="flex justify-center">
                  <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
                </div>
              )}
            </div>
            
            <DialogFooter>
              <Button 
                variant="outline" 
                onClick={() => setShowShareDialog(false)}
              >
                Close
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Import Contacts Dialog */}
        <Dialog open={showImportDialog} onOpenChange={setShowImportDialog}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Import Contacts</DialogTitle>
              <DialogDescription>
                Paste exported contacts JSON to import.
              </DialogDescription>
            </DialogHeader>
            
            {importError && (
              <Alert variant="destructive" className="mb-4">
                <AlertTitle>Error</AlertTitle>
                <AlertDescription>{importError}</AlertDescription>
              </Alert>
            )}
            
            <div className="space-y-4 py-4">
              <Textarea
                value={importData}
                onChange={(e) => setImportData(e.target.value)}
                placeholder="Paste contacts JSON here..."
                className="font-mono text-xs"
                rows={10}
              />
            </div>
            
            <DialogFooter>
              <Button 
                variant="outline" 
                onClick={() => setShowImportDialog(false)}
              >
                Cancel
              </Button>
              <Button 
                onClick={handleImportContacts} 
                disabled={loading || !importData}
                className="bg-blue-600 hover:bg-blue-700"
              >
                {loading ? 
                  <><RefreshCw className="h-4 w-4 mr-2 animate-spin" />Importing...</> : 
                  <><Upload className="h-4 w-4 mr-2" />Import Contacts</>
                }
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <Tabs defaultValue="all" value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="mb-4 w-full sm:w-auto bg-slate-100 dark:bg-slate-800 p-1 rounded-md">
            <TabsTrigger 
              value="all" 
              className="rounded-md data-[state=active]:bg-white data-[state=active]:shadow-sm"
            >
              All ({contacts.length})
            </TabsTrigger>
            <TabsTrigger 
              value="trusted"
              className="rounded-md data-[state=active]:bg-white data-[state=active]:shadow-sm"
            >
              Trusted ({contacts.filter(c => c.trust_level === 'trusted').length})
            </TabsTrigger>
            <TabsTrigger 
              value="verified"
              className="rounded-md data-[state=active]:bg-white data-[state=active]:shadow-sm"
            >
              Verified ({contacts.filter(c => c.trust_level === 'verified').length})
            </TabsTrigger>
            <TabsTrigger 
              value="unverified"
              className="rounded-md data-[state=active]:bg-white data-[state=active]:shadow-sm"
            >
              Unverified ({contacts.filter(c => c.trust_level === 'unverified').length})
            </TabsTrigger>
          </TabsList>

          <TabsContent value={activeTab} className="mt-0">
            {loading ? (
              <div className="flex justify-center p-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              </div>
            ) : filteredContacts.length === 0 ? (
              <div className="text-center p-12 bg-slate-50 dark:bg-slate-900 rounded-lg border border-dashed border-slate-200 dark:border-slate-700">
                <div className="inline-flex justify-center items-center w-16 h-16 rounded-full bg-slate-100 dark:bg-slate-800 mb-4">
                  {searchQuery ? (
                    <Search className="h-8 w-8 text-slate-400" />
                  ) : (
                    <UserPlus className="h-8 w-8 text-slate-400" />
                  )}
                </div>
                <p className="text-lg font-medium text-slate-700 dark:text-slate-300">
                  {searchQuery ? 'No matching contacts' : 'No contacts yet'}
                </p>
                <p className="text-sm text-slate-500 dark:text-slate-400 mt-2 max-w-md mx-auto">
                  {searchQuery 
                    ? 'Try changing your search query or filters' 
                    : 'Add your first contact using the "Add Contact" button above'}
                </p>
              </div>
            ) : (
              <div className="grid gap-4 sm:grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
                {filteredContacts.map(contact => (
                  <div key={contact.id} className="border rounded-lg overflow-hidden bg-white dark:bg-slate-900 hover:shadow-md transition-shadow duration-200">
                    <div className="p-4 cursor-pointer"
                      onClick={() => openDetailView(contact)}
                    >
                      <div className="flex justify-between items-start">
                        <div className="space-y-1">
                          <h3 className="font-medium text-lg truncate">{contact.name}</h3>
                          <div className="text-sm text-slate-600 dark:text-slate-400 flex items-center gap-1">
                            <Mail className="h-3 w-3 flex-shrink-0" />
                            <span className="truncate">{contact.email}</span>
                          </div>
                          <div className="font-mono text-xs text-slate-500 dark:text-slate-500 break-all">
                            {contact.fingerprint.match(/.{1,4}/g)?.join(' ')}
                          </div>
                        </div>
                      </div>
                      
                      <div className="mt-3 flex flex-wrap gap-2">
                        <Badge className={`
                          ${contact.trust_level === 'trusted' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100' : 
                            contact.trust_level === 'verified' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-100' : 
                            'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-100'}
                        `}>
                          {contact.trust_level === 'trusted' ? 'Trusted' : 
                          contact.trust_level === 'verified' ? 'Verified' : 'Unverified'}
                        </Badge>
                        {contact.metadata?.connection_method && (
                          <Badge variant="outline" className="bg-slate-50 dark:bg-slate-800">
                            {contact.metadata.connection_method === 'mutual' ? 'Mutual' :
                            contact.metadata.connection_method === 'qr' ? 'QR Code' :
                            contact.metadata.connection_method === 'burner_link' ? 'Burner Link' : 'Manual'}
                          </Badge>
                        )}
                      </div>
                    </div>
                    
                    <div className="flex divide-x bg-slate-50 dark:bg-slate-800">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm" className="flex-1 rounded-none text-slate-600 dark:text-slate-400">
                            <Filter className="h-4 w-4 mr-1" />
                            Trust
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent>
                          <DropdownMenuLabel>Set Trust Level</DropdownMenuLabel>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem 
                            onClick={() => handleUpdateTrustLevel(contact.id, 'trusted')}
                            disabled={contact.trust_level === 'trusted'}
                          >
                            <Check className="h-4 w-4 mr-2 text-green-500" />
                            Trusted
                          </DropdownMenuItem>
                          <DropdownMenuItem 
                            onClick={() => handleUpdateTrustLevel(contact.id, 'verified')}
                            disabled={contact.trust_level === 'verified'}
                          >
                            <UserCheck className="h-4 w-4 mr-2 text-blue-500" />
                            Verified
                          </DropdownMenuItem>
                          <DropdownMenuItem 
                            onClick={() => handleUpdateTrustLevel(contact.id, 'unverified')}
                            disabled={contact.trust_level === 'unverified'}
                          >
                            <X className="h-4 w-4 mr-2 text-yellow-500" />
                            Unverified
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                      <Button 
                        variant="ghost" 
                        size="sm"
                        className="flex-1 rounded-none text-slate-600 dark:text-slate-400"
                        onClick={(e) => {
                          e.stopPropagation(); // Prevent triggering the card click
                          openEditDialog(contact);
                        }}
                      >
                        <Edit className="h-4 w-4 mr-1" />
                        Edit
                      </Button>
                      <Button 
                        variant="ghost" 
                        size="sm"
                        className="flex-1 rounded-none text-red-600 hover:text-red-700 dark:text-red-400"
                        onClick={(e) => {
                          e.stopPropagation(); // Prevent triggering the card click
                          handleDeleteContact(contact.id);
                        }}
                      >
                        <Trash2 className="h-4 w-4 mr-1" />
                        Delete
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </TabsContent>
        </Tabs>

        {/* Secure Export Dialog */}
        <SecureExportDialog
          open={showSecureExportDialog}
          onClose={() => setShowSecureExportDialog(false)}
          identityFingerprint={identity?.identity?.fingerprint || ''}
          onExportComplete={(exportedData, encryptionMethod) => {
            console.log(`Export completed using ${encryptionMethod} encryption`);
          }}
        />

        {/* Secure Import Dialog */}
        <SecureImportDialog
          open={showSecureImportDialog}
          onClose={() => setShowSecureImportDialog(false)}
          identityFingerprint={identity?.identity?.fingerprint || ''}
          onImportComplete={(importCount) => {
            console.log(`Imported ${importCount} contacts`);
            loadContacts();
          }}
        />
      </CardContent>
    </Card>
  );
}            