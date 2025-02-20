"use client";

import React, { useState, useEffect } from 'react';
import { 
  Card, CardHeader, CardTitle, CardContent, CardFooter,
  CardDescription
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Shield, Key, UserCheck, Lock, Mail, UserPlus, Search, 
  QrCode, Link, Share2, Trash2, Check, X, Edit, Filter, Download, Upload
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
  
  // Form state for adding contacts
  const [newContactForm, setNewContactForm] = useState({
    name: '',
    email: '',
    fingerprint: '',
    public_key: '',
  });

  // QR code state
  const [qrCodeData, setQrCodeData] = useState('');
  const [burnerLink, setBurnerLink] = useState('');
  
  // Import/Export state
  const [importData, setImportData] = useState('');
  const [importError, setImportError] = useState<string | null>(null);
  
  // Load contacts on component mount and when identity changes
  useEffect(() => {
    if (identity?.identity?.fingerprint) {
      loadContacts();
    }
  }, [identity]);
  
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
  
  // Load contacts from API
  const loadContacts = async () => {
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
      
      const data = await response.json();
      console.log('Contact API response:', data);
      
      if (!response.ok) {
        console.error('API returned error:', data);
        throw new Error(data.error || 'Failed to load contacts');
      }
      
      setContacts(data.contacts || []);
      console.log(`Loaded ${data.contacts?.length || 0} contacts`);
    } catch (err) {
      console.error('Error loading contacts:', err);
      setError(err instanceof Error ? err.message : 'An error occurred loading contacts');
      setContacts([]);
    } finally {
      setLoading(false);
    }
  };
  
  // Add a new contact
  const handleAddContact = async () => {
    if (!identity?.identity?.fingerprint) return;
    
    try {
      setLoading(true);
      setError(null);
      
      // Validate form
      if (!newContactForm.name || !newContactForm.email || !newContactForm.fingerprint || !newContactForm.public_key) {
        throw new Error('All fields are required');
      }
      
      const response = await fetch('/api/contacts', {
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
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to add contact');
      }
      
      // Reset form and reload contacts
      setNewContactForm({
        name: '',
        email: '',
        fingerprint: '',
        public_key: '',
      });
      setShowAddDialog(false);
      await loadContacts();
      
    } catch (err) {
      console.error('Error adding contact:', err);
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };
  
  // Delete a contact
  const handleDeleteContact = async (contactId: string) => {
    if (!identity?.identity?.fingerprint) return;
    
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch(
        `/api/contacts?fingerprint=${identity.identity.fingerprint}&contactId=${contactId}`,
        { method: 'DELETE' }
      );
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to delete contact');
      }
      
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

  // Render trust level badge
  const renderTrustBadge = (trustLevel: string) => {
    switch(trustLevel) {
      case 'trusted':
        return <Badge className="bg-green-500">Trusted</Badge>;
      case 'verified':
        return <Badge className="bg-blue-500">Verified</Badge>;
      default:
        return <Badge className="bg-yellow-500">Unverified</Badge>;
    }
  };

  return (
    <Card className="w-full max-w-4xl mx-auto mt-8">
      <CardHeader>
        <div className="flex justify-between items-center">
          <CardTitle className="flex items-center gap-2">
            <UserCheck className="h-6 w-6" />
            Sovereign Contacts
          </CardTitle>
          <div className="flex gap-2">
            <Button 
              variant="outline" 
              size="sm"
              onClick={() => setShowQRDialog(true)}
            >
              <QrCode className="h-4 w-4 mr-2" />
              Share via QR
            </Button>
            <Button 
              variant="outline" 
              size="sm"
              onClick={handleGenerateBurnerLink}
            >
              <Link className="h-4 w-4 mr-2" />
              Create Burner Link
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <Share2 className="h-4 w-4 mr-2" />
                  More
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuItem onClick={handleExportContacts}>
                  <Download className="h-4 w-4 mr-2" />
                  Export Contacts
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setShowImportDialog(true)}>
                  <Upload className="h-4 w-4 mr-2" />
                  Import Contacts
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
        <CardDescription>
          Manage your secure, private contacts. All data is encrypted using your PGP key.
        </CardDescription>
      </CardHeader>

      <CardContent>
        {error && (
          <Alert variant="destructive" className="mb-4">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <div className="flex justify-between items-center mb-4">
          <div className="relative w-64">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search contacts..."
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

        <Tabs defaultValue="all" value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="mb-4">
            <TabsTrigger value="all">All Contacts ({contacts.length})</TabsTrigger>
            <TabsTrigger value="trusted">
              Trusted ({contacts.filter(c => c.trust_level === 'trusted').length})
            </TabsTrigger>
            <TabsTrigger value="verified">
              Verified ({contacts.filter(c => c.trust_level === 'verified').length})
            </TabsTrigger>
            <TabsTrigger value="unverified">
              Unverified ({contacts.filter(c => c.trust_level === 'unverified').length})
            </TabsTrigger>
          </TabsList>

          <TabsContent value={activeTab} className="mt-0">
            {loading ? (
              <div className="flex justify-center p-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900"></div>
              </div>
            ) : filteredContacts.length === 0 ? (
              <div className="text-center p-8 text-muted-foreground">
                {searchQuery ? 'No contacts found matching your search.' : 'No contacts found. Add some contacts to get started.'}
              </div>
            ) : (
              <div className="space-y-4">
                {filteredContacts.map(contact => (
                  <div key={contact.id} className="border rounded-md p-4 hover:bg-gray-50 transition-colors">
                    <div className="flex justify-between items-start">
                      <div>
                        <div className="font-medium text-lg">{contact.name}</div>
                        <div className="text-sm text-muted-foreground flex items-center gap-1">
                          <Mail className="h-3 w-3" />
                          {contact.email}
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">
                          {contact.fingerprint.substring(0, 16)}...
                        </div>
                        <div className="mt-2 flex gap-2">
                          {renderTrustBadge(contact.trust_level)}
                          {contact.metadata?.connection_method && (
                            <Badge variant="outline">
                              {contact.metadata.connection_method === 'mutual' ? 'Mutual Connection' :
                               contact.metadata.connection_method === 'qr' ? 'QR Code' :
                               contact.metadata.connection_method === 'burner_link' ? 'Burner Link' : 'Manual'}
                            </Badge>
                          )}
                        </div>
                      </div>
                      <div className="flex gap-1">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="sm">
                              <Filter className="h-4 w-4" />
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
                          onClick={() => setSelectedContact(contact)}
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button 
                          variant="ghost" 
                          size="sm"
                          onClick={() => handleDeleteContact(contact.id)}
                        >
                          <Trash2 className="h-4 w-4 text-red-500" />
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </TabsContent>
        </Tabs>
      </CardContent>

      {/* Add Contact Dialog */}
      <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add New Contact</DialogTitle>
            <DialogDescription>
              Enter the contact details to add a new contact securely.
            </DialogDescription>
          </DialogHeader>
          
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
            <Button onClick={handleAddContact} disabled={loading}>
              {loading ? 'Adding...' : 'Add Contact'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* QR Code Dialog */}
      <Dialog open={showQRDialog} onOpenChange={setShowQRDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Share Your Identity</DialogTitle>
            <DialogDescription>
              Scan this QR code to share your identity details securely.
            </DialogDescription>
          </DialogHeader>
          
          <div className="flex justify-center py-4">
            {/* Placeholder for QR code - in a real app you'd render the QR code here */}
            <div className="w-64 h-64 bg-gray-100 border flex items-center justify-center">
              {qrCodeData ? 'QR Code would render here' : 'Loading QR code...'}
            </div>
          </div>
          
          <DialogFooter>
            <Button onClick={() => setShowQRDialog(false)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Share Dialog for Burner Link */}
      <Dialog open={showShareDialog} onOpenChange={setShowShareDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Burner Link Generated</DialogTitle>
            <DialogDescription>
              Share this link to allow someone to add you as a contact. The link will expire in 48 hours.
            </DialogDescription>
          </DialogHeader>
          
          <div className="py-4">
            <Input
              value={burnerLink}
              readOnly
              className="font-mono text-sm"
            />
            <p className="text-xs text-muted-foreground mt-2">
              This link can only be used once and will expire in 48 hours for security.
            </p>
          </div>
          
          <DialogFooter>
            <Button 
              onClick={() => {
                navigator.clipboard.writeText(burnerLink);
                // You could add a toast notification here
              }}
            >
              Copy Link
            </Button>
            <Button onClick={() => setShowShareDialog(false)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Import Dialog */}
      <Dialog open={showImportDialog} onOpenChange={setShowImportDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Import Contacts</DialogTitle>
            <DialogDescription>
              Paste exported contact data to import contacts.
            </DialogDescription>
          </DialogHeader>
          
          <div className="py-4">
            {importError && (
              <Alert variant="destructive" className="mb-4">
                <AlertDescription>{importError}</AlertDescription>
              </Alert>
            )}
            
            <Textarea
              value={importData}
              onChange={(e) => setImportData(e.target.value)}
              placeholder="Paste exported contact data here"
              className="font-mono text-xs"
              rows={10}
            />
          </div>
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowImportDialog(false)}>Cancel</Button>
            <Button onClick={handleImportContacts} disabled={loading}>
              {loading ? 'Importing...' : 'Import Contacts'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}