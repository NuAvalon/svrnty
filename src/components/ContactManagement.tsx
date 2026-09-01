"use client";

import React, { useState, useEffect, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { SVRNTY_DOMAIN } from '@/lib/config/domain';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import {
  Shield, Mail, UserPlus, Search,
  Share2, Check, Download, Upload, RefreshCw,
  FileJson, Eye, Phone, Link2, AtSign, ShieldCheck, Copy, ChevronDown
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
import { TwoSidedBook } from '@/components/TwoSidedBook';
import { VaultExportDialog } from '@/components/export/VaultExportDialog';
import { ExportAuthGate } from '@/components/export/ExportAuthGate';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import {
  getAllContacts, addContact, updateContact, removeContact,
  getContactByFingerprint, loadKey,
  type ContactRecord,
} from '@/lib/identity/client-store';
import { contactRecordToEdge } from '@/lib/trust/contact-edge';
import { subscribeContactChanges } from '@/lib/contacts/contact-events';
import { startLiveBookPolling } from '@/lib/sync/live-book-poll';
import { buildSignedIdentityCard, classifyImportedCard } from '@/lib/identity/identity-card-sign';
import { toVCardFile } from '@/lib/contacts/vcard';
import type { TrustEdge } from '@/lib/trust/types';
import { ContactMethodLink } from '@/components/contacts/ContactMethodLink';
import {
  safeEmailLink,
  safePhoneLink,
  safeUrlLink,
  safeHandleLink,
} from '@/lib/contacts/safe-contact-link';
import { ownerHasVerified, ownerVerifyPersistPatch, TRUST_RECIPE_COPY } from '@/lib/trust/trust-recipe';
import { TrustActionConfirmDialog } from '@/components/trust-actions/TrustActionConfirmDialog';
import {
  applyTrustAction,
  isContactBlocked,
  type TrustActionKind,
  type TrustActionTarget,
} from '@/components/trust-actions/trust-actions';

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
  /** Owner-local mute (CUR-5) — never publish. */
  blocked?: boolean;
  metadata?: {
    notes?: string;
    tags?: string[];
    connection_method?: 'manual' | 'qr' | 'burner_link' | 'mutual';
    mutual_contacts?: string[];
    blocked?: boolean;
  };
  // Imported contact channels (vCard). Phones parse + persist on the ContactRecord but were never
  // surfaced to the UI (Chaos#40) — carry them so the detail view can render them.
  contact_info?: {
    phones?: string[];
    emails?: string[];
    urls?: string[];
    handles?: Record<string, string>;
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
    <Badge
      className="border font-medium"
      style={{
        fontFamily: E.fontMono,
        letterSpacing: '0.06em',
        background: trusted
          ? 'color-mix(in srgb, var(--se-accent) 12%, transparent)'
          : 'color-mix(in srgb, var(--se-dim) 12%, transparent)',
        color: trusted ? E.accent : E.dim,
        borderColor: trusted ? E.borderLit : E.border,
      }}
    >
      {trustLabel(contact)}
    </Badge>
  );
}

function TrustIcon({ contact, className = "h-5 w-5" }: { contact: Contact; className?: string }) {
  const trusted = isTrusted(contact);
  if (trusted) {
    return <ShieldCheck className={className} style={{ color: E.accent }} />;
  }
  return <Eye className={className} style={{ color: E.dim }} />;
}

// Convert IndexedDB ContactRecord to component Contact type
function recordToContact(r: ContactRecord): Contact {
  const blocked = isContactBlocked(r as { blocked?: boolean; metadata?: { blocked?: boolean } });
  return {
    id: r.id,
    name: r.name || '',
    email: r.email || '',
    fingerprint: r.fingerprint || '',
    public_key: r.public_key || '',
    trust_level: (r.trust_level as Contact['trust_level']) || 'unverified',
    added_at: r.added_at || new Date().toISOString(),
    verified_at: r.verified_at,
    blocked,
    metadata: r.metadata,
    contact_info: r.contact_info, // vCard-imported phones/emails/urls (Chaos#40 display fix)
  };
}

// --- Main Component ---

export function ContactManagement({ identity, onContactsChange }: ContactsProps) {
  const [contacts, setContacts] = useState<Contact[]>([]);
  // Live-beat: contact ids whose latest repaint came from a peer's incoming apply (reason:'live-apply') → data-live="push".
  const [liveIds, setLiveIds] = useState<Set<string>>(() => new Set());
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
  const [showVaultExportDialog, setShowVaultExportDialog] = useState(false);
  const [pendingBookExport, setPendingBookExport] = useState<'json' | 'vcard' | null>(null);
  const [vaultExporting, setVaultExporting] = useState(false);
  const [confirmKind, setConfirmKind] = useState<TrustActionKind | null>(null);
  const [confirmBusy, setConfirmBusy] = useState(false);

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

  // Live-beat (Apollo): a peer's edit → the return-channel caller applies it IN Alice's page → emits reason:'live-apply'.
  // We re-project the book IN-PLACE (no reload / no navigation — the honest hinge) and mark the ignited rows
  // data-live="push" so beat-4 can prove Alice self-updated LIVE, not via pull-to-refresh. `source:'broadcast'`
  // (cross-tab) is a separate uninstantiable invariant; the single-Alice-page demo rides source:'local' + reason:'live-apply'.
  useEffect(() => {
    return subscribeContactChanges((evt) => {
      loadContacts(); // reflect the applied update in place (any reason keeps the book fresh, incl. cross-tab)
      if (evt.reason === 'live-apply' && evt.ids.length > 0) {
        setLiveIds(new Set(evt.ids)); // only a real incoming apply earns the "push" marker
      }
    });
  }, [loadContacts]);

  // Live-beat poll (Athena): the runtime call-site that drives the return-channel consume on an interval,
  // so a peer's verified contact.update self-applies IN this page → the caller emits reason:'live-apply' →
  // the subscription above repaints the row data-live="push" (beat-4). startLiveBookPolling re-reads the
  // unlocked key each tick and no-ops while the session is locked, so this effect keys only on the stable
  // fingerprint; `identity` is closed over for the armored public key (stable per fingerprint).
  useEffect(() => {
    if (!fingerprint) return;
    const handle = startLiveBookPolling(identity);
    return () => handle.stop();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- keyed on the stable fingerprint; identity's
    // object ref is intentionally not a dep (public key stable per fp; private key re-loaded each tick).
  }, [fingerprint]);

  // Filter contacts — binary: all, trusted, known; blocked is a separate local list
  const filteredContacts = contacts.filter(contact => {
    const blocked = isContactBlocked(contact);
    if (activeTab === 'blocked') {
      if (!blocked) return false;
    } else {
      if (blocked) return false; // blocked stay off the main book tabs
      if (activeTab === 'trusted' && !isTrusted(contact)) return false;
      if (activeTab === 'known' && isTrusted(contact)) return false;
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return contact.name.toLowerCase().includes(q) ||
        contact.email.toLowerCase().includes(q) ||
        contact.fingerprint.toLowerCase().includes(q);
    }
    return true;
  });

  const activeContacts = contacts.filter(c => !isContactBlocked(c));
  const trustedCount = activeContacts.filter(c => isTrusted(c)).length;
  const blockedCount = contacts.filter(c => isContactBlocked(c)).length;
  const bookEdges = filteredContacts.map(contactRecordToEdge);

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
        trusted: newLevel === 'trusted',
        trusted_since: newLevel === 'trusted' ? new Date().toISOString() : null,
        ...(newLevel === 'trusted' && { verified_at: new Date().toISOString() }),
      } as any);
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
        setSelectedContact({
          ...selectedContact,
          trust_level: newLevel,
          blocked: selectedContact.blocked,
        });
      }
      await loadContacts();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update trust');
    } finally {
      setLoading(false);
    }
  };

  const handleSetBlocked = async (contact: Contact, blocked: boolean) => {
    if (!fingerprint) return;
    try {
      setLoading(true);
      setError(null);
      await updateContact(contact.id, {
        blocked,
        ...(blocked
          ? {
              trusted: false,
              trust_level: 'unverified',
              trusted_since: null,
            }
          : {}),
        metadata: {
          ...(contact.metadata || {}),
          blocked,
        },
      } as any);
      setShowDetailDialog(false);
      await loadContacts();
      onContactsChange?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update block');
    } finally {
      setLoading(false);
    }
  };

  const confirmTarget: TrustActionTarget | null = selectedContact
    ? {
        id: selectedContact.id,
        fingerprint: selectedContact.fingerprint,
        name: selectedContact.name,
        trusted: isTrusted(selectedContact),
        ownerVerified: ownerHasVerified(selectedContact as any),
        blocked: isContactBlocked(selectedContact),
      }
    : null;

  const runConfirmedAction = async (kind: TrustActionKind, opts?: { reason?: string }) => {
    if (!selectedContact || !confirmTarget) return;
    setConfirmBusy(true);
    try {
      const result = await applyTrustAction(kind, confirmTarget, {
        applyLocal: async (patch) => {
          if (patch.kind === 'remove') {
            await handleDeleteContact(selectedContact.id);
            return;
          }
          if (patch.kind === 'trust' || patch.kind === 'break') {
            await handleToggleTrust(selectedContact);
            return;
          }
          if (patch.kind === 'block') {
            await handleSetBlocked(selectedContact, true);
            return;
          }
          if (patch.kind === 'unblock') {
            await handleSetBlocked(selectedContact, false);
          }
        },
      }, opts);
      setConfirmKind(null);
      if (!result.ok) setError(result.message);
    } finally {
      setConfirmBusy(false);
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

  const handleVaultExport = () => {
    if (!fingerprint) return;
    setShowVaultExportDialog(true);
  };

  const runBookExport = async (kind: 'json' | 'vcard') => {
    if (!fingerprint) return;
    try {
      setLoading(true);
      setError(null);
      const records = await getAllContacts(fingerprint);
      if (kind === 'json') {
        const exportData = JSON.stringify(
          { contacts: records, exported_at: new Date().toISOString() },
          null,
          2,
        );
        const blob = new Blob([exportData], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `svrnty-contacts-${new Date().toISOString().slice(0, 10)}.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      } else {
        const edges = records.map((r) => contactRecordToEdge(r)) as TrustEdge[];
        const vcf = toVCardFile(edges);
        const blob = new Blob([vcf], { type: 'text/vcard' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `svrnty-contacts-${new Date().toISOString().slice(0, 10)}.vcf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to export');
    } finally {
      setLoading(false);
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
    <div
      className="w-full"
      style={{
        fontFamily: E.fontSans,
        color: E.text,
        borderRadius: 16,
        border: `1px solid ${E.border}`,
        background: E.surface,
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        boxShadow: 'var(--se-glass-shadow)',
        overflow: 'hidden',
      }}
    >
      <div style={{ borderBottom: `1px solid ${E.border}`, padding: '20px 20px 16px' }}>
        <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start gap-4">
          <div>
            <p
              style={{
                margin: 0,
                fontSize: 11,
                letterSpacing: '0.2em',
                textTransform: 'uppercase',
                color: E.accent,
                fontFamily: E.fontSans,
                fontWeight: 500,
              }}
            >
              Living book
            </p>
            <h2
              style={{
                margin: '6px 0 0',
                fontFamily: E.fontSerif,
                fontWeight: 300,
                fontSize: 28,
                letterSpacing: '0.03em',
                color: E.text,
                display: 'flex',
                alignItems: 'center',
                gap: 10,
              }}
            >
              <Shield className="h-5 w-5" style={{ color: E.accent }} />
              Your circle
            </h2>
            <p
              style={{
                margin: '8px 0 0',
                fontSize: 14,
                fontWeight: 300,
                color: E.muted,
                fontFamily: E.fontSans,
                maxWidth: 420,
                lineHeight: 1.55,
              }}
            >
              People you hold — living and resting. Local-first, never a global map.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" onClick={handleShareIdentity} style={emberPrimaryBtn}>
              <Share2 className="h-4 w-4 mr-2" />
              Share Identity
            </Button>
            <Button variant="outline" size="sm" onClick={() => setShowImportExchangeDialog(true)} style={emberGhostBtn}>
              <Download className="h-4 w-4 mr-2" />
              Import Contact
            </Button>
            <Button variant="outline" size="sm" onClick={() => setShowVcardImport(true)} data-testid="import-contacts-trigger" style={emberGhostBtn}>
              <Upload className="h-4 w-4 mr-2" />
              Import contacts
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm" style={emberGhostBtn}>
                  <Share2 className="h-4 w-4 mr-2" />
                  More
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent>
                <DropdownMenuLabel>Vault</DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={handleVaultExport}>
                  <Download className="h-4 w-4 mr-2" style={{ color: E.accent }} />
                  Export Vault (.svrnty)
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuLabel>Data</DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => setPendingBookExport('json')}>
                  <FileJson className="h-4 w-4 mr-2" />
                  Export Contacts as JSON
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setPendingBookExport('vcard')}>
                  <Download className="h-4 w-4 mr-2" />
                  Export all as vCard
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setShowImportDialog(true)}>
                  <Upload className="h-4 w-4 mr-2" />
                  Import Contacts from JSON
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </div>

      <div className="p-4 sm:p-6">
        {error && (
          <Alert variant="destructive" className="mb-4">
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Search + Add */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-6">
          <div className="relative w-full sm:w-72">
            <Search className="absolute left-2 top-2.5 h-4 w-4" style={{ color: E.dim }} />
            <Input
              placeholder="Search by name, email, fingerprint..."
              className="pl-8"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                fontFamily: E.fontSans,
                background: E.inputBg,
                borderColor: E.border,
                color: E.text,
              }}
            />
          </div>
          <Button onClick={() => setShowAddDialog(true)} style={emberPrimaryBtn}>
            <UserPlus className="h-4 w-4 mr-2" />
            Add Contact
          </Button>
        </div>

        {/* Tabs — contacts (all) and trusted (subset) */}
        <Tabs defaultValue="all" value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList
            className="mb-4 w-full sm:w-auto"
            style={{
              background: E.surface,
              border: `1px solid ${E.border}`,
              fontFamily: E.fontSans,
            }}
          >
            <TabsTrigger value="all" style={{ fontFamily: E.fontSans }}>
              Contacts ({activeContacts.length})
            </TabsTrigger>
            <TabsTrigger value="trusted" style={{ fontFamily: E.fontSans }}>
              Trusted ({trustedCount})
            </TabsTrigger>
            <TabsTrigger value="blocked" style={{ fontFamily: E.fontSans }}>
              Blocked ({blockedCount})
            </TabsTrigger>
          </TabsList>

          <TabsContent value={activeTab} className="mt-0">
            {loading ? (
              <div className="flex justify-center p-8">
                <RefreshCw className="h-8 w-8 animate-spin" style={{ color: E.dim }} />
              </div>
            ) : filteredContacts.length === 0 ? (
              <div
                className="text-center p-12 rounded-lg"
                style={{ border: `1px dashed ${E.border}` }}
              >
                <div
                  className="inline-flex justify-center items-center w-16 h-16 rounded-full mb-4"
                  style={{
                    background: 'color-mix(in srgb, var(--se-accent) 10%, transparent)',
                    border: `1px solid ${E.border}`,
                  }}
                >
                  {searchQuery ? <Search className="h-8 w-8" style={{ color: E.dim }} /> : <UserPlus className="h-8 w-8" style={{ color: E.dim }} />}
                </div>
                <p style={{ fontFamily: E.fontSerif, fontSize: 22, fontWeight: 300, color: E.text, margin: 0 }}>
                  {searchQuery ? 'No matching contacts' : 'No contacts yet'}
                </p>
                <p style={{ fontFamily: E.fontSans, fontSize: 13, fontWeight: 300, color: E.muted, marginTop: 8, maxWidth: 360, marginLeft: 'auto', marginRight: 'auto', lineHeight: 1.55 }}>
                  {searchQuery ? 'Try a different search' : 'Add your first contact to begin building your circle'}
                </p>
              </div>
            ) : (
              <TwoSidedBook
                edges={bookEdges}
                liveIds={liveIds}
                onSelect={(edge) => {
                  const contact = contacts.find(c => c.id === edge.id);
                  if (!contact) return;
                  setSelectedContact(contact);
                  setShowDetailDialog(true);
                }}
              />
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
                        <ContactMethodLink safe={safeEmailLink(selectedContact.email)} />
                      </div>
                    </div>
                    <div>
                      <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Trust</h4>
                      <div className="mt-1"><TrustBadge contact={selectedContact} /></div>
                    </div>
                  </div>

                  {selectedContact.contact_info?.emails?.some(Boolean) && (
                    <div>
                      <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                        More email{selectedContact.contact_info.emails.filter(Boolean).length > 1 ? 's' : ''}
                      </h4>
                      <div className="mt-1 space-y-1">
                        {selectedContact.contact_info.emails.filter(Boolean).map((email, i) => (
                          <div key={i} className="flex items-center gap-1">
                            <Mail className="h-4 w-4 text-muted-foreground" />
                            <ContactMethodLink safe={safeEmailLink(email)} />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedContact.contact_info?.phones?.some(Boolean) && (
                    <div>
                      <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                        Phone{selectedContact.contact_info.phones.filter(Boolean).length > 1 ? 's' : ''}
                      </h4>
                      <div className="mt-1 space-y-1">
                        {selectedContact.contact_info.phones.filter(Boolean).map((phone, i) => (
                          <div key={i} className="flex items-center gap-1">
                            <Phone className="h-4 w-4 text-muted-foreground" />
                            <ContactMethodLink safe={safePhoneLink(phone)} />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedContact.contact_info?.urls?.some(Boolean) && (
                    <div>
                      <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                        Link{selectedContact.contact_info.urls.filter(Boolean).length > 1 ? 's' : ''}
                      </h4>
                      <div className="mt-1 space-y-1">
                        {selectedContact.contact_info.urls.filter(Boolean).map((url, i) => (
                          <div key={i} className="flex items-center gap-1 min-w-0">
                            <Link2 className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                            <ContactMethodLink safe={safeUrlLink(url)} className="truncate" />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedContact.contact_info?.handles && Object.keys(selectedContact.contact_info.handles).length > 0 && (
                    <div>
                      <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Handles</h4>
                      <div className="mt-1 space-y-1">
                        {Object.entries(selectedContact.contact_info.handles).map(([platform, handle]) => (
                          <div key={platform} className="flex items-center gap-1 min-w-0">
                            <AtSign className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                            <span className="truncate">
                              <span className="text-muted-foreground">{platform}: </span>
                              <ContactMethodLink safe={safeHandleLink(platform, handle)} />
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

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

                  {/* Actions — nested under one control */}
                  <div className="border-t border-border/40 pt-4">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="outline" size="sm">
                          Actions
                          <ChevronDown className="h-4 w-4 ml-1" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="start" className="w-56">
                        {!isContactBlocked(selectedContact) && !isTrusted(selectedContact) && !ownerHasVerified(selectedContact as any) && (
                          <>
                            <DropdownMenuItem
                              onSelect={async () => {
                                const rec = await getContactByFingerprint(fingerprint, selectedContact.fingerprint).catch(() => null);
                                const patch = ownerVerifyPersistPatch(
                                  { ...(selectedContact.metadata || {}), ...(rec as any)?.metadata },
                                  'in_person',
                                );
                                await updateContact(selectedContact.id, patch as any);
                                await loadContacts();
                                onContactsChange?.();
                              }}
                            >
                              {TRUST_RECIPE_COPY.verifyInPerson}
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onSelect={async () => {
                                const rec = await getContactByFingerprint(fingerprint, selectedContact.fingerprint).catch(() => null);
                                const patch = ownerVerifyPersistPatch(
                                  { ...(selectedContact.metadata || {}), ...(rec as any)?.metadata },
                                  'other_channel',
                                );
                                await updateContact(selectedContact.id, patch as any);
                                await loadContacts();
                                onContactsChange?.();
                              }}
                            >
                              {TRUST_RECIPE_COPY.verifyOtherChannel}
                            </DropdownMenuItem>
                          </>
                        )}
                        {!isContactBlocked(selectedContact) && (
                          <DropdownMenuItem
                            onSelect={() => {
                              if (isTrusted(selectedContact)) {
                                setConfirmKind('break');
                                return;
                              }
                              if (!ownerHasVerified(selectedContact as any)) return;
                              setConfirmKind('trust');
                            }}
                          >
                            {isTrusted(selectedContact)
                              ? 'Untrust'
                              : ownerHasVerified(selectedContact as any) ? 'Trust' : 'Verify first, then Trust'}
                          </DropdownMenuItem>
                        )}
                        <DropdownMenuItem onSelect={() => { openEditDialog(selectedContact); setShowDetailDialog(false); }}>
                          Edit
                        </DropdownMenuItem>
                        <DropdownMenuItem onSelect={() => { setShowShardGiveDialog(true); setShowDetailDialog(false); }}>
                          Give a piece
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onSelect={() =>
                            setConfirmKind(isContactBlocked(selectedContact) ? 'unblock' : 'block')
                          }
                        >
                          {isContactBlocked(selectedContact) ? 'Unblock' : 'Block'}
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          className="text-destructive focus:text-destructive"
                          onSelect={() => setConfirmKind('remove')}
                        >
                          Remove
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </div>
              </>
            )}
          </DialogContent>
        </Dialog>

        <TrustActionConfirmDialog
          open={!!confirmKind && !!confirmTarget}
          kind={confirmKind}
          target={confirmTarget}
          busy={confirmBusy || loading}
          onCancel={() => setConfirmKind(null)}
          onConfirm={(opts) => {
            if (!confirmKind) return;
            return runConfirmedAction(confirmKind, opts);
          }}
        />

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

        {fingerprint && (
          <>
            <VaultExportDialog
              open={showVaultExportDialog}
              onClose={() => setShowVaultExportDialog(false)}
              fingerprint={fingerprint}
              onSessionLocked={() => {
                window.location.reload();
              }}
            />
            <ExportAuthGate
              open={pendingBookExport !== null}
              fingerprint={fingerprint}
              exportLabel={
                pendingBookExport === 'vcard'
                  ? 'all contacts as vCard'
                  : 'contacts as JSON'
              }
              onClose={() => setPendingBookExport(null)}
              onAuthenticated={() => {
                const kind = pendingBookExport;
                setPendingBookExport(null);
                if (kind) void runBookExport(kind);
              }}
              onSessionLocked={() => {
                window.location.reload();
              }}
            />
          </>
        )}

      </div>
    </div>
  );
}

const emberPrimaryBtn: React.CSSProperties = {
  background: 'color-mix(in srgb, var(--se-accent) 14%, transparent)',
  border: `1px solid ${E.borderLit}`,
  color: E.accent,
  fontFamily: E.fontSans,
  letterSpacing: '0.04em',
};

const emberGhostBtn: React.CSSProperties = {
  background: 'transparent',
  border: `1px solid ${E.border}`,
  color: E.muted,
  fontFamily: E.fontSans,
};
