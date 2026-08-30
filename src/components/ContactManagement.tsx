"use client";

import React, { useState, useEffect, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { SVRNTY_DOMAIN } from '@/lib/config/domain';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import {
  Shield, UserPlus, Search, Share2,
  Check, Edit, Download, Upload, RefreshCw, FileJson, Eye,
  ShieldCheck, Copy, MoreHorizontal, Users
} from 'lucide-react';
import {
  Dialog, DialogContent, DialogDescription, DialogHeader,
  DialogTitle, DialogFooter
} from '@/components/ui/dialog';
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger
} from '@/components/ui/dropdown-menu';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { ContactShareDialog } from '@/components/ContactShareDialog';
import { ImportContactsDialog } from '@/components/ImportContactsDialog';
import { ShardGiveDialog } from '@/components/ShardGiveDialog';
import { MasterAddressBookList } from '@/components/contacts/MasterAddressBookList';
import { ContactDetailDialog } from '@/components/contacts/ContactDetailDialog';
import { InviteToSvrntyDialog } from '@/components/contacts/InviteToSvrntyDialog';
import { isSvrnNetworkContact } from '@/lib/contacts/is-svrn-contact';
import {
  buildLinkToSvrntyUpdate,
  isPendingSvrntyContact,
  type ContactShareSettings,
} from '@/lib/contacts/contact-lane';
import { createRelay } from '@/lib/sync/relay';
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
import {
  ClassicalFieldsEditor,
  fieldsFromContactInfo,
  fieldsToContactInfo,
  type BookField,
} from '@/components/contacts/ClassicalFieldsEditor';
import type { TrustEdge } from '@/lib/trust/types';
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
    connection_status?: string;
    pending?: boolean;
    share_settings?: import('@/lib/contacts/contact-lane').ContactShareSettings;
    classical_extras?: import('@/lib/contacts/contact-lane').ClassicalExtras;
  };
  // Imported contact channels (vCard). Phones parse + persist on the ContactRecord but were never
  // surfaced to the UI (Chaos#40) — carry them so the detail view can render them.
  contact_info?: {
    phones?: string[];
    emails?: string[];
    urls?: string[];
    handles?: Record<string, string>;
    org?: string;
    title?: string;
    nickname?: string;
    bday?: string;
    adr?: string;
    extras?: Array<{ label: string; value: string }>;
  };
  connection_status?: string;
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
    connection_status: (r as any).connection_status,
  };
}

// --- Main Component ---

export function ContactManagement({ identity, onContactsChange }: ContactsProps) {
  const [contacts, setContacts] = useState<Contact[]>([]);
  // Live-beat: contact ids whose latest repaint came from a peer's incoming apply (reason:'live-apply') → data-live="push".
  const [liveIds, setLiveIds] = useState<Set<string>>(() => new Set());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
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
  /** Master book scope — Classical vs SVRNTY (not living/resting). */
  const [bookScope, setBookScope] = useState<'classical' | 'svrn'>('classical');
  /** Quiet: view blocked list (⋯ menu — not a primary tab). */
  const [showBlocked, setShowBlocked] = useState(false);
  /** Within SVRNTY: known vs trusted (binary trust, not a score). */
  const [svrnFilter, setSvrnFilter] = useState<'all' | 'known' | 'trusted'>('all');
  const [selectionMode, setSelectionMode] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  /** Inline group label for multi-select (same local-tag model as Social Graph). */
  const [bulkGroupName, setBulkGroupName] = useState('');
  const [bulkGroupNote, setBulkGroupNote] = useState<string | null>(null);
  const [groupsOpen, setGroupsOpen] = useState(false);
  const [editingGroupTag, setEditingGroupTag] = useState<string | null>(null);
  const [editGroupTagName, setEditGroupTagName] = useState('');
  const [groupFilterTag, setGroupFilterTag] = useState<string | null>(null);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteUrl, setInviteUrl] = useState<string | null>(null);
  const [inviteLoading, setInviteLoading] = useState(false);
  const [inviteError, setInviteError] = useState<string | null>(null);


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
    phonesText: '',
    emailsText: '',
    urlsText: '',
    handlesText: '',
  });
  const [linkDialogOpen, setLinkDialogOpen] = useState(false);
  const [linkFingerprint, setLinkFingerprint] = useState('');
  const [linkPublicKey, setLinkPublicKey] = useState('');
  const [linkError, setLinkError] = useState<string | null>(null);
  const [bookFields, setBookFields] = useState<BookField[]>([]);

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
    const q = searchQuery.trim().toLowerCase();
    if (q) {
      const hay = `${contact.name} ${contact.email} ${contact.fingerprint}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    const svrn = isSvrnNetworkContact(contact);
    const blocked = isContactBlocked(contact);

    if (showBlocked) {
      if (!blocked) return false;
      if (bookScope === 'classical' && svrn) return false;
      if (bookScope === 'svrn' && !svrn) return false;
      return true;
    }

    if (blocked) return false;
    if (bookScope === 'classical' && svrn) return false;
    if (bookScope === 'svrn' && !svrn) return false;
    if (bookScope === 'svrn') {
      if (svrnFilter === 'trusted' && !isTrusted(contact)) return false;
      if (svrnFilter === 'known' && isTrusted(contact)) return false;
    }
    if (groupFilterTag && !(contact.metadata?.tags || []).includes(groupFilterTag)) return false;
    return true;
  });

  const masterRows = filteredContacts.map((c) => ({
    id: c.id,
    name: c.name,
    email: c.email,
    fingerprint: c.fingerprint,
    public_key: c.public_key,
    trust_level: c.trust_level,
    blocked: isContactBlocked(c),
    tags: c.metadata?.tags || [],
    pending: isPendingSvrntyContact(c),
  }));

  const knownGroupTags = Array.from(
    new Set(contacts.flatMap((c) => c.metadata?.tags || []).filter(Boolean)),
  ).sort((a, b) => a.localeCompare(b));

  const selectedHasSvrn = contacts.some(
    (c) => selectedIds.has(c.id) && isSvrnNetworkContact(c),
  );

  const classicalCount = contacts.filter((c) => !isSvrnNetworkContact(c) && !isContactBlocked(c)).length;
  const svrnCount = contacts.filter((c) => isSvrnNetworkContact(c) && !isContactBlocked(c)).length;
  const trustedCount = contacts.filter((c) => isSvrnNetworkContact(c) && isTrusted(c) && !isContactBlocked(c)).length;
  const knownCount = contacts.filter((c) => isSvrnNetworkContact(c) && !isTrusted(c) && !isContactBlocked(c)).length;
  const blockedCount = contacts.filter((c) => isContactBlocked(c)).length;
  const activeContacts = contacts.filter((c) => !isContactBlocked(c));

  const toggleSelected = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const prepareInvite = async () => {
    if (!fingerprint || !identity) return;
    setInviteLoading(true);
    setInviteError(null);
    setInviteUrl(null);
    try {
      const key = await loadKey(fingerprint);
      if (!key) throw new Error('Unlock your identity first to build an invite.');
      const signed = await buildSignedIdentityCard(identity, key.privateKey, key.passphrase);
      const packed = JSON.stringify(signed);
      const result = await createRelay(packed);
      setInviteUrl(result.url);
    } catch (e) {
      setInviteError(e instanceof Error ? e.message : 'Could not prepare invite.');
    } finally {
      setInviteLoading(false);
    }
  };


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
      if (!editContactForm.name) {
        throw new Error('Name is required');
      }
      const info = fieldsToContactInfo(bookFields);
      // Classical-only edit — refuse to mutate SVRNTY profile fields here.
      if (selectedContact && isSvrnNetworkContact(selectedContact)) {
        throw new Error('SVRNTY contacts are key-bound — edit is locked. Change trust, groups, or share settings instead.');
      }
      await updateContact(editContactForm.id, {
        name: editContactForm.name,
        email: editContactForm.email || '',
        contact_info: info,
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
    if (isSvrnNetworkContact(contact)) {
      setError('SVRNTY contacts are key-bound — profile edit is locked.');
      return;
    }
    setSelectedContact(contact);
    setEditContactForm({
      id: contact.id,
      name: contact.name,
      email: contact.email,
      fingerprint: contact.fingerprint,
      public_key: contact.public_key,
      notes: contact.metadata?.notes || '',
      phonesText: '',
      emailsText: '',
      urlsText: '',
      handlesText: '',
    });
    setBookFields(fieldsFromContactInfo(contact.contact_info));
    setShowEditDialog(true);
  };

  const handleLinkToSvrnty = async () => {
    if (!selectedContact || !fingerprint) return;
    try {
      setLinkError(null);
      setLoading(true);
      const fp = linkFingerprint.trim();
      const pk = linkPublicKey.trim();
      if (fp.length < 16 || !pk) {
        throw new Error('Paste their SVRNTY fingerprint (16+ chars) and public key.');
      }
      const patch = buildLinkToSvrntyUpdate({
        fingerprint: fp,
        public_key: pk,
        existing: {
          name: selectedContact.name,
          email: selectedContact.email,
          contact_info: selectedContact.contact_info,
          metadata: selectedContact.metadata as Record<string, unknown> | null,
        },
      });
      await updateContact(selectedContact.id, {
        fingerprint: patch.fingerprint,
        public_key: patch.public_key,
        connection_status: patch.connection_status,
        metadata: patch.metadata,
        // Keep classical channels on the living card as contact_info + classical_extras.
        contact_info: selectedContact.contact_info,
        trust_level: 'unverified',
      } as any);
      setLinkDialogOpen(false);
      setLinkFingerprint('');
      setLinkPublicKey('');
      setShowDetailDialog(false);
      await loadContacts();
      onContactsChange?.();
    } catch (err) {
      setLinkError(err instanceof Error ? err.message : 'Could not link contact');
    } finally {
      setLoading(false);
    }
  };

  const handleToggleGroup = async (tag: string) => {
    if (!selectedContact || !fingerprint) return;
    const prev = selectedContact.metadata?.tags || [];
    const tags = prev.includes(tag) ? prev.filter((t) => t !== tag) : [...prev, tag];
    await updateContact(selectedContact.id, {
      metadata: { ...selectedContact.metadata, tags },
    } as any);
    const next = { ...selectedContact, metadata: { ...selectedContact.metadata, tags } };
    setSelectedContact(next);
    await loadContacts();
    onContactsChange?.();
  };

  const handleShareSettingsChange = async (next: ContactShareSettings) => {
    if (!selectedContact || !fingerprint) return;
    if (!isSvrnNetworkContact(selectedContact)) return;
    await updateContact(selectedContact.id, {
      metadata: { ...selectedContact.metadata, share_settings: next },
    } as any);
    setSelectedContact({
      ...selectedContact,
      metadata: { ...selectedContact.metadata, share_settings: next },
    });
    await loadContacts();
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
              Address book
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
              Master Address Book
            </h2>
            <p
              style={{
                margin: '8px 0 0',
                fontSize: 14,
                fontWeight: 300,
                color: E.muted,
                fontFamily: E.fontSans,
                maxWidth: 480,
                lineHeight: 1.55,
              }}
            >
              Every imported contact (VCF and exchange). Classical entries you can edit;
              SVRN network peers are key-bound — edit their living methods on their card, not here.
              Share your own identity from the Identity tab.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
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

        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-4">
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

        {/* Primary tabs: Classical / SVRNTY — Blocked lives in ⋯ */}
        <div className="flex flex-wrap items-center gap-2 mb-3">
          {([
            ['classical', `Classical (${classicalCount})`],
            ['svrn', `SVRNTY (${svrnCount})`],
          ] as const).map(([id, label]) => (
            <button
              key={id}
              type="button"
              onClick={() => {
                setBookScope(id);
                setSelectedIds(new Set());
                setShowBlocked(false);
              }}
              style={{
                fontFamily: E.fontSans,
                fontSize: 12,
                padding: '6px 12px',
                borderRadius: 999,
                border: `1px solid ${bookScope === id && !showBlocked ? E.borderLit : E.border}`,
                background:
                  bookScope === id && !showBlocked
                    ? 'color-mix(in srgb, var(--se-accent) 14%, transparent)'
                    : 'transparent',
                color: bookScope === id && !showBlocked ? E.accent : E.muted,
                cursor: 'pointer',
              }}
            >
              {label}
            </button>
          ))}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                aria-label="Book options"
                title="Book options"
                style={{
                  fontFamily: E.fontSans,
                  fontSize: 11,
                  padding: '6px 8px',
                  borderRadius: 8,
                  border: `1px solid ${E.border}`,
                  background: showBlocked
                    ? 'color-mix(in srgb, var(--se-accent) 10%, transparent)'
                    : 'transparent',
                  color: E.muted,
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                }}
              >
                <MoreHorizontal className="h-4 w-4" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" style={{ fontFamily: E.fontSans }}>
              <DropdownMenuLabel style={{ fontFamily: E.fontSans }}>Book</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() => {
                  setShowBlocked((v) => !v);
                  setSelectedIds(new Set());
                  setSelectionMode(false);
                }}
                style={{ fontFamily: E.fontSans, cursor: 'pointer' }}
              >
                {showBlocked ? 'Hide blocked contacts' : 'View blocked contacts'}
                {!showBlocked && blockedCount > 0 ? ` (${blockedCount})` : ''}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <button
            type="button"
            data-testid="book-groups-btn"
            onClick={() => setGroupsOpen((v) => !v)}
            style={{
              fontFamily: E.fontSans,
              fontSize: 11,
              padding: '4px 10px',
              borderRadius: 8,
              border: `1px solid ${groupsOpen || groupFilterTag ? E.borderLit : E.border}`,
              background: groupsOpen
                ? 'color-mix(in srgb, var(--se-accent) 14%, transparent)'
                : 'transparent',
              color: E.accent,
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <Users className="h-3.5 w-3.5" />
            Groups{groupFilterTag ? ` · ${groupFilterTag}` : knownGroupTags.length ? ` (${knownGroupTags.length})` : ''}
          </button>
          <button
            type="button"
            onClick={() => {
              setSelectionMode((v) => !v);
              setSelectedIds(new Set());
              setBulkGroupName('');
              setBulkGroupNote(null);
            }}
            style={{
              marginLeft: 'auto',
              fontFamily: E.fontSans,
              fontSize: 11,
              padding: '4px 10px',
              borderRadius: 8,
              border: `1px solid ${E.border}`,
              background: selectionMode ? 'color-mix(in srgb, var(--se-accent) 14%, transparent)' : 'transparent',
              color: E.accent,
              cursor: 'pointer',
            }}
          >
            {selectionMode ? 'Done selecting' : 'Select multiple'}
          </button>
        </div>

        {groupsOpen ? (
          <div
            data-testid="book-groups-panel"
            className="mb-3 p-3 rounded-xl"
            style={{ border: `1px solid ${E.border}`, background: E.surfaceSolid, fontFamily: E.fontSans }}
          >
            <div className="flex justify-between gap-2 mb-2">
              <p style={{ margin: 0, fontSize: 12, color: E.muted }}>
                Local groups · select · rename · remove · never published
              </p>
              <button
                type="button"
                onClick={() => {
                  setGroupFilterTag(null);
                  setGroupsOpen(false);
                }}
                style={{
                  fontSize: 11,
                  padding: '4px 8px',
                  borderRadius: 8,
                  border: `1px solid ${E.border}`,
                  background: 'transparent',
                  color: E.muted,
                  cursor: 'pointer',
                  fontFamily: E.fontSans,
                }}
              >
                Close
              </button>
            </div>
            <div className="flex flex-wrap gap-1.5 mb-2">
              <button
                type="button"
                onClick={() => setGroupFilterTag(null)}
                style={{
                  fontSize: 11,
                  padding: '4px 10px',
                  borderRadius: 8,
                  border: `1px solid ${groupFilterTag === null ? E.borderLit : E.border}`,
                  background: groupFilterTag === null ? 'color-mix(in srgb, var(--se-accent) 12%, transparent)' : 'transparent',
                  color: E.muted,
                  cursor: 'pointer',
                  fontFamily: E.fontSans,
                }}
              >
                All contacts
              </button>
            </div>
            {knownGroupTags.length === 0 ? (
              <p style={{ margin: 0, fontSize: 12, color: E.dim }}>
                No groups yet — Select multiple, then Add to group.
              </p>
            ) : (
              <ul className="flex flex-col gap-2" style={{ listStyle: 'none', margin: 0, padding: 0 }}>
                {knownGroupTags.map((tag) => {
                  const count = contacts.filter((c) => (c.metadata?.tags || []).includes(tag)).length;
                  const isEditing = editingGroupTag === tag;
                  return (
                    <li
                      key={tag}
                      className="flex flex-wrap gap-2 items-center"
                      style={{
                        padding: '8px 10px',
                        borderRadius: 10,
                        border: `1px solid ${groupFilterTag === tag ? E.borderLit : E.border}`,
                        background:
                          groupFilterTag === tag
                            ? 'color-mix(in srgb, var(--se-accent) 10%, transparent)'
                            : 'transparent',
                      }}
                    >
                      {isEditing ? (
                        <>
                          <Input
                            value={editGroupTagName}
                            onChange={(e) => setEditGroupTagName(e.target.value)}
                            className="flex-1 min-w-[120px]"
                            aria-label={`Rename ${tag}`}
                          />
                          <Button
                            type="button"
                            size="sm"
                            disabled={loading || !editGroupTagName.trim()}
                            onClick={async () => {
                              const next = editGroupTagName.trim();
                              if (!next || next === tag) return;
                              try {
                                for (const c of contacts) {
                                  const prev = c.metadata?.tags || [];
                                  if (!prev.includes(tag)) continue;
                                  const tags = Array.from(new Set(prev.map((t) => (t === tag ? next : t))));
                                  await updateContact(c.id, { metadata: { ...c.metadata, tags } } as any);
                                }
                                if (groupFilterTag === tag) setGroupFilterTag(next);
                                setEditingGroupTag(null);
                                setEditGroupTagName('');
                                setBulkGroupNote(`Renamed “${tag}” → “${next}” (local only).`);
                                await loadContacts();
                              } catch (err) {
                                setError(err instanceof Error ? err.message : 'Could not rename group');
                              }
                            }}
                          >
                            Save
                          </Button>
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              setEditingGroupTag(null);
                              setEditGroupTagName('');
                            }}
                          >
                            Cancel
                          </Button>
                        </>
                      ) : (
                        <>
                          <button
                            type="button"
                            onClick={() => setGroupFilterTag((cur) => (cur === tag ? null : tag))}
                            style={{
                              flex: 1,
                              textAlign: 'left',
                              background: 'none',
                              border: 'none',
                              color: E.text,
                              cursor: 'pointer',
                              fontFamily: E.fontSans,
                              fontSize: 13,
                              padding: 0,
                            }}
                          >
                            {tag}
                            <span style={{ color: E.dim, marginLeft: 8, fontSize: 11 }}>{count}</span>
                          </button>
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              const ids = contacts
                                .filter((c) => (c.metadata?.tags || []).includes(tag))
                                .map((c) => c.id);
                              setSelectedIds(new Set(ids));
                              setSelectionMode(true);
                              setGroupFilterTag(tag);
                              setGroupsOpen(false);
                            }}
                          >
                            Select
                          </Button>
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              setEditingGroupTag(tag);
                              setEditGroupTagName(tag);
                            }}
                          >
                            Edit
                          </Button>
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            disabled={loading}
                            onClick={async () => {
                              if (!window.confirm(`Remove group “${tag}” from all contacts? Tags are local-only.`)) return;
                              try {
                                for (const c of contacts) {
                                  const prev = c.metadata?.tags || [];
                                  if (!prev.includes(tag)) continue;
                                  const tags = prev.filter((t) => t !== tag);
                                  await updateContact(c.id, { metadata: { ...c.metadata, tags } } as any);
                                }
                                if (groupFilterTag === tag) setGroupFilterTag(null);
                                setBulkGroupNote(`Removed group “${tag}”.`);
                                await loadContacts();
                              } catch (err) {
                                setError(err instanceof Error ? err.message : 'Could not remove group');
                              }
                            }}
                          >
                            Remove
                          </Button>
                        </>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        ) : null}

        {showBlocked ? (
          <p
            style={{
              margin: '0 0 10px',
              fontSize: 12,
              color: E.dim,
              fontFamily: E.fontSans,
            }}
          >
            Showing blocked · turn off via ⋯
          </p>
        ) : null}

        {!showBlocked && bookScope === 'svrn' ? (
          <div className="flex flex-wrap items-center gap-2 mb-3">
            {([
              ['all', 'All SVRNTY'],
              ['known', `Known (${knownCount})`],
              ['trusted', `Trusted (${trustedCount})`],
            ] as const).map(([id, label]) => (
              <button
                key={id}
                type="button"
                onClick={() => setSvrnFilter(id)}
                style={{
                  fontFamily: E.fontSans,
                  fontSize: 11,
                  padding: '4px 10px',
                  borderRadius: 8,
                  border: `1px solid ${svrnFilter === id ? E.borderLit : E.border}`,
                  background: svrnFilter === id ? 'color-mix(in srgb, var(--se-accent) 10%, transparent)' : 'transparent',
                  color: E.text,
                  cursor: 'pointer',
                }}
              >
                {label}
              </button>
            ))}
          </div>
        ) : null}

        {selectionMode && (
          <div
            className="flex flex-col gap-2 mb-4 p-3 rounded-xl"
            style={{ border: `1px solid ${E.border}`, background: E.surfaceSolid }}
          >
            <div className="flex flex-wrap gap-2 items-center">
              <span style={{ fontSize: 12, color: E.muted, fontFamily: E.fontSans, alignSelf: 'center' }}>
                {selectedIds.size} selected
              </span>
              <input
                type="text"
                value={bulkGroupName}
                onChange={(e) => {
                  setBulkGroupName(e.target.value);
                  setBulkGroupNote(null);
                }}
                placeholder="Group label (local private tag)"
                disabled={selectedIds.size === 0 || loading}
                style={{
                  flex: 1,
                  minWidth: 160,
                  fontFamily: E.fontSans,
                  fontSize: 12,
                  padding: '6px 10px',
                  borderRadius: 8,
                  border: `1px solid ${E.border}`,
                  background: E.inputBg,
                  color: E.text,
                  outline: 'none',
                }}
              />
              <Button
                size="sm"
                variant="outline"
                style={emberGhostBtn}
                disabled={loading || selectedIds.size === 0 || !bulkGroupName.trim()}
                onClick={() => {
                  const name = bulkGroupName.trim();
                  if (!name || selectedIds.size === 0) return;
                  void (async () => {
                    setLoading(true);
                    try {
                      for (const id of selectedIds) {
                        const c = contacts.find((x) => x.id === id);
                        if (!c) continue;
                        const tags = Array.from(new Set([...(c.metadata?.tags || []), name]));
                        await updateContact(id, { metadata: { ...c.metadata, tags } } as any);
                      }
                      await loadContacts();
                      onContactsChange?.();
                      setBulkGroupNote(`Added “${name}” to ${selectedIds.size} contact(s). Local only — never published.`);
                      setBulkGroupName('');
                      setSelectedIds(new Set());
                    } catch (err) {
                      setError(err instanceof Error ? err.message : 'Could not assign group');
                    } finally {
                      setLoading(false);
                    }
                  })();
                }}
              >
                Add to group
              </Button>
              {selectedHasSvrn ? (
                <>
                  <Button
                    size="sm"
                    variant="outline"
                    style={emberGhostBtn}
                    disabled={loading || selectedIds.size === 0}
                    onClick={() => {
                      void (async () => {
                        const targets = contacts.filter((c) => selectedIds.has(c.id) && isSvrnNetworkContact(c));
                        for (const c of targets) {
                          if (!isTrusted(c)) await handleToggleTrust(c);
                        }
                        setSelectedIds(new Set());
                      })();
                    }}
                  >
                    Trust
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    style={emberGhostBtn}
                    disabled={loading || selectedIds.size === 0}
                    onClick={() => {
                      void (async () => {
                        const targets = contacts.filter(
                          (c) => selectedIds.has(c.id) && isSvrnNetworkContact(c) && isTrusted(c),
                        );
                        for (const c of targets) {
                          await handleToggleTrust(c);
                        }
                        setSelectedIds(new Set());
                      })();
                    }}
                  >
                    Revoke trust
                  </Button>
                </>
              ) : null}
              <Button
                size="sm"
                variant="outline"
                style={emberGhostBtn}
                disabled={loading || selectedIds.size === 0}
                onClick={() => {
                  void (async () => {
                    const targets = contacts.filter((c) => selectedIds.has(c.id));
                    for (const c of targets) {
                      await handleSetBlocked(c, true);
                    }
                    setSelectedIds(new Set());
                  })();
                }}
              >
                Block
              </Button>
              <Button
                size="sm"
                variant="outline"
                style={emberGhostBtn}
                disabled={loading || selectedIds.size === 0}
                onClick={() => {
                  if (!window.confirm(`Delete ${selectedIds.size} contact(s)? This cannot be undone.`)) return;
                  void (async () => {
                    for (const id of [...selectedIds]) {
                      await handleDeleteContact(id);
                    }
                    setSelectedIds(new Set());
                    setSelectionMode(false);
                  })();
                }}
              >
                Delete
              </Button>
            </div>
            {knownGroupTags.length > 0 ? (
              <div className="flex flex-wrap gap-1.5 items-center">
                <span style={{ fontSize: 10, color: E.dim, fontFamily: E.fontSans }}>Reuse:</span>
                {knownGroupTags.map((tag) => (
                  <button
                    key={tag}
                    type="button"
                    onClick={() => setBulkGroupName(tag)}
                    style={{
                      fontSize: 10,
                      fontFamily: E.fontSans,
                      color: E.muted,
                      border: `1px solid ${E.border}`,
                      borderRadius: 6,
                      padding: '2px 8px',
                      background: bulkGroupName === tag ? 'color-mix(in srgb, var(--se-accent) 12%, transparent)' : 'transparent',
                      cursor: 'pointer',
                    }}
                  >
                    {tag}
                  </button>
                ))}
              </div>
            ) : null}
            {bulkGroupNote ? (
              <p style={{ margin: 0, fontSize: 11, color: E.ok, fontFamily: E.fontSans }}>{bulkGroupNote}</p>
            ) : (
              <p style={{ margin: 0, fontSize: 11, color: E.dim, fontFamily: E.fontSans }}>
                Groups are local private tags (stripped on the wire). Introduce / resync / privacy need fleet.
              </p>
            )}
          </div>
        )}

        <div className="w-full">
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
                  {searchQuery
                    ? 'No matching contacts'
                    : showBlocked
                      ? 'No blocked contacts'
                      : 'No contacts yet'}
                </p>
                <p style={{ fontFamily: E.fontSans, fontSize: 13, fontWeight: 300, color: E.muted, marginTop: 8, maxWidth: 360, marginLeft: 'auto', marginRight: 'auto', lineHeight: 1.55 }}>
                  {searchQuery
                    ? 'Try a different search'
                    : showBlocked
                      ? 'Blocked stays out of the main book — exit via ⋯'
                      : 'Import a VCF or add someone to start your master book'}
                </p>
              </div>
            ) : (
              <MasterAddressBookList
                rows={masterRows}
                selectedIds={selectedIds}
                selectionMode={selectionMode}
                onToggleSelect={toggleSelected}
                onOpen={(id) => {
                  const contact = contacts.find((c) => c.id === id);
                  if (!contact) return;
                  setSelectedContact(contact);
                  setShowDetailDialog(true);
                }}
              />
            )}
          </div>

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
              <ClassicalFieldsEditor fields={bookFields} onChange={setBookFields} />
              <div className="space-y-1.5">
                <label className="text-sm font-medium">Fingerprint</label>
                <Input value={editContactForm.fingerprint} readOnly className="font-mono text-xs opacity-60" />
                <p className="text-xs text-muted-foreground">Fingerprint is immutable</p>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowEditDialog(false)}>Cancel</Button>
              <Button onClick={handleUpdateContact} disabled={loading || !editContactForm.name}>
                {loading ? <><RefreshCw className="h-4 w-4 mr-2 animate-spin" />Saving...</> : <><Check className="h-4 w-4 mr-2" />Save</>}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <ContactDetailDialog
          open={showDetailDialog}
          contact={selectedContact}
          onClose={() => setShowDetailDialog(false)}
          trustBadge={selectedContact ? <TrustBadge contact={selectedContact} /> : null}
          trustIcon={selectedContact ? <TrustIcon contact={selectedContact} className="h-4 w-4" /> : null}
          isTrusted={!!selectedContact && isTrusted(selectedContact)}
          isBlocked={!!selectedContact && isContactBlocked(selectedContact)}
          onTrustToggle={() => {
            if (!selectedContact) return;
            if (!isSvrnNetworkContact(selectedContact)) {
              setError('Trust is SVRNTY-only — link this classical contact first.');
              return;
            }
            setConfirmKind(isTrusted(selectedContact) ? 'break' : 'trust');
          }}
          onEdit={() => {
            if (!selectedContact) return;
            openEditDialog(selectedContact);
            setShowDetailDialog(false);
          }}
          onGivePiece={() => {
            setShowShardGiveDialog(true);
            setShowDetailDialog(false);
          }}
          onBlockToggle={() => {
            if (!selectedContact) return;
            setConfirmKind(isContactBlocked(selectedContact) ? 'unblock' : 'block');
          }}
          onRemove={() => setConfirmKind('remove')}
          onInvite={() => setInviteOpen(true)}
          onLinkToSvrnty={() => {
            setLinkError(null);
            setLinkDialogOpen(true);
          }}
          availableGroups={Array.from(new Set(contacts.flatMap(c => c.metadata?.tags || []))).sort()}
          onToggleGroup={(tag) => { void handleToggleGroup(tag); }}
          onShareSettingsChange={(next) => { void handleShareSettingsChange(next); }}
        />

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

        
        <Dialog open={linkDialogOpen} onOpenChange={setLinkDialogOpen}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Link to SVRNTY</DialogTitle>
              <DialogDescription>
                Paste their living fingerprint and public key. They leave Classical and appear under SVRNTY as pending until they add you back. Classical numbers stay on the card as additional information.
              </DialogDescription>
            </DialogHeader>
            {linkError && <Alert variant="destructive"><AlertTitle>Error</AlertTitle><AlertDescription>{linkError}</AlertDescription></Alert>}
            <div className="space-y-3 py-2">
              <div className="space-y-1.5">
                <label className="text-sm font-medium" htmlFor="link-fp">Fingerprint</label>
                <Input id="link-fp" value={linkFingerprint} onChange={e => setLinkFingerprint(e.target.value)} placeholder="64-hex fingerprint" className="font-mono text-xs" />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium" htmlFor="link-pk">Public key</label>
                <Textarea id="link-pk" value={linkPublicKey} onChange={e => setLinkPublicKey(e.target.value)} placeholder="Armored or base64 public key" className="font-mono text-xs" rows={4} />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setLinkDialogOpen(false)}>Cancel</Button>
              <Button onClick={() => { void handleLinkToSvrnty(); }} disabled={loading || !linkFingerprint.trim() || !linkPublicKey.trim()}>
                {loading ? 'Linking…' : 'Link & move to SVRNTY'}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <InviteToSvrntyDialog
          open={inviteOpen}
          contactName={selectedContact?.name || 'contact'}
          inviteUrl={inviteUrl}
          loading={inviteLoading}
          error={inviteError}
          onClose={() => setInviteOpen(false)}
          onPrepare={prepareInvite}
        />

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
