// src/components/ContactManagement.tsx
"use client";

import React, { useState, useEffect } from 'react';
import { 
  Card, CardHeader, CardTitle, CardContent, CardFooter,
  CardDescription
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Alert, AlertDescription,AlertTitle } from '@/components/ui/alert';
import { 
  Shield, Key, UserCheck, Lock, Mail, UserPlus, Search, 
  QrCode, Link, Share2, Trash2, Check, X, Edit, Filter, Download, Upload, RefreshCw
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

// Define the Contact type
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
  identity: any;
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
  
  // Form state for adding contacts
  const [newContactForm, setNewContactForm] = useState({
    name: '',
    email: '',
    fingerprint: '',
    public_key: '',
  });

  // Helper function to get identity data from the complex structure
  const getIdentityData = () => {
    if (!identity) return null;
    
    console.log('ContactManagement identity structure:', identity);
    
    return {
      fingerprint: identity?.fingerprint || identity?.identity?.fingerprint || identity?.identity?.identity?.fingerprint,
      name: identity?.identity?.identity?.name || identity?.identity?.name || identity?.name,
      email: identity?.identity?.identity?.email || identity?.identity?.email || identity?.email
    };
  };
  
  // Load contacts on component mount and when identity changes
  useEffect(() => {
    const identityData = getIdentityData();
    if (identityData?.fingerprint) {
      console.log('Loading contacts for identity:', identityData);
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

  // Use simple contacts API for better reliability
  const API_BASE = '/api/simple-contacts';

  const loadContacts = async () => {
    const identityData = getIdentityData();
    if (!identityData?.fingerprint) {
      console.log('No identity fingerprint found, skipping contact load');
      return;
    }
    
    try {
      setLoading(true);
      setError(null);
      
      console.log(`Loading contacts for fingerprint: ${identityData.fingerprint}`);
      const response = await fetch(
        `${API_BASE}?fingerprint=${identityData.fingerprint}`, 
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
  };
  
  const handleAddContact = async () => {
    const identityData = getIdentityData();
    if (!identityData?.fingerprint) {
      setError('No valid identity found');
      return;
    }
    
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

      // Check if adding yourself
      if (newContactForm.fingerprint === identityData.fingerprint) {
        setError('You cannot add yourself as a contact');
        return;
      }

      console.log('Adding contact with data:', {
        fingerprint: identityData.fingerprint,
        contactData: {
          ...newContactForm,
          trust_level: 'unverified'
        }
      });

      const response = await fetch(`${API_BASE}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fingerprint: identityData.fingerprint,
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
        console.log('Contact validation failed:', errorMessage);
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
  
  const handleDeleteContact = async (contactId: string) => {
    const identityData = getIdentityData();
    if (!identityData?.fingerprint) {
      setError('No valid identity found');
      return;
    }
    
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch(
        `${API_BASE}?fingerprint=${identityData.fingerprint}&contactId=${contactId}`,
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
      
      // Reload contacts
      await loadContacts();
      
    } catch (err) {
      console.error('Error deleting contact:', err);
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

  const identityData = getIdentityData();

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
              onClick={() => setShowAddDialog(true)}
              className="bg-blue-600 hover:bg-blue-700 text-white"
            >
              <UserPlus className="h-4 w-4 mr-2" />
              Add Contact
            </Button>
          </div>
        </div>
        <CardDescription className="mt-2">
          Your encrypted contact book. All data is secured with PGP encryption.
          {identityData && (
            <div className="mt-2 text-xs">
              Identity: {identityData.name} ({identityData.fingerprint?.slice(0, 8)}...)
            </div>
          )}
        </CardDescription>
      </CardHeader>

      <CardContent className="p-4 sm:p-6">
        {error && (
          <Alert variant="destructive" className="mb-4">
            <div className="font-semibold">Error</div>
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
                <div className="font-semibold">Error</div>
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
                    <div className="p-4">
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
                      </div>
                    </div>
                    
                    <div className="flex divide-x bg-slate-50 dark:bg-slate-800">
                      <Button 
                        variant="ghost" 
                        size="sm"
                        className="flex-1 rounded-none text-red-600 hover:text-red-700 dark:text-red-400"
                        onClick={() => handleDeleteContact(contact.id)}
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
      </CardContent>
    </Card>
  );
}