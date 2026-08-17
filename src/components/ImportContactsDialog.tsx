"use client";

// ImportContactsDialog — the 0.12 "import the gray sea" flow (Apollo; Athena wires the entry trigger).
// vCard (.vcf) → gray contacts → dedup preview → CONFIRM-GATE (never silent, Archie #115904/B2) →
// applyImportPlan → addContact/updateContact → onImported(). LOCAL-only: the file is read in-browser,
// nothing is uploaded. Grays are keyless (addContact's fp↔key check is skipped when no key present).
//
// Contract (Athena #116015): props below; she renders <ImportContactsDialog .../> in the contacts view
// with a trigger + showVcardImport state, onImported → her loadContacts() refreshes the book.

import React, { useRef, useState } from 'react';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Upload, Users, GitMerge, UserPlus, AlertTriangle } from 'lucide-react';
import type { TrustEdge } from '@/lib/trust/types';
import { fromVCard } from '@/lib/contacts/vcard';
import { dedupeContacts, type DedupPlan } from '@/lib/contacts/import-dedup';
import { applyImportPlan } from '@/lib/contacts/import-apply';
import { getAllContacts, addContact, updateContact } from '@/lib/identity/client-store';

interface ImportContactsDialogProps {
  ownerFingerprint: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onImported: () => void;
}

// Project a stored ContactRecord → TrustEdge for dedup's `existing`. Minimal: only the fields
// dedup reads (peer_email + contact_info channels) + identity/name for the merge.
// TODO(#21): replace with contactRecordToEdge from '@/lib/trust/contact-edge' when it lands
// (adds pq carry — moot for grays; transparent upgrade per Athena #116012).
function recordToEdge(c: any): TrustEdge {
  const contact_info = c.contact_info ?? {
    phones: c.phones ?? (c.phone ? [c.phone] : []),
    emails: c.emails ?? [],
  };
  return {
    id: c.id,
    peer_fingerprint: c.peer_fingerprint || c.fingerprint || '',
    peer_name: c.peer_name || c.name || '',
    peer_email: c.peer_email || c.email || '',
    peer_public_key: c.public_key || '',
    contact_info,
    trusted: false, trusted_since: null, last_interaction: c.added_at || '',
    decay_days: 730, trust_history: [],
    verification: { method: 'none', verified_at: null },
    mutual: { they_trust_me: null, last_sync: null, reciprocal: false },
    tags: c.tags ?? [], notes: c.notes || '', connection_channels: [], added_at: c.added_at || '',
  } as TrustEdge;
}

// Edge → the ContactRecord fields to persist for a gray (keyless) contact.
// NOTE(Athena review): mirrors your 0.14 FIELD_MAP — primary phone/email + phones/emails lists +
// contact_info. A gray has no fingerprint/public_key, so it lands keyless (book derives "gray" from that).
function edgeToRecordFields(e: Partial<TrustEdge>) {
  const phones = e.contact_info?.phones ?? [];
  const emails = e.contact_info?.emails ?? [];
  return {
    fingerprint: e.peer_fingerprint || '',
    name: e.peer_name || '',
    email: e.peer_email || emails[0] || '',
    public_key: e.peer_public_key || '',
    trust_level: 'unverified',
    phone: phones[0] || '',
    phones,
    emails,
    notes: e.notes || '',
    contact_info: e.contact_info ?? { phones, emails },
  };
}

export function ImportContactsDialog({ ownerFingerprint, open, onOpenChange, onImported }: ImportContactsDialogProps) {
  const [plan, setPlan] = useState<DedupPlan | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [importedCount, setImportedCount] = useState<number | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const reset = () => { setPlan(null); setError(null); setImportedCount(null); setLoading(false); };
  const close = (o: boolean) => { if (!o) reset(); onOpenChange(o); };

  // Parse the chosen .vcf LOCALLY and build the dedup plan against the current book.
  const handleFile = async (file: File) => {
    reset();
    try {
      const text = await file.text();                 // in-browser read — nothing leaves the device
      const incoming = fromVCard(text);
      if (incoming.length === 0) { setError('No contacts found in that .vcf file.'); return; }
      const existing = (await getAllContacts(ownerFingerprint)).map(recordToEdge);
      setPlan(dedupeContacts(incoming, existing));    // preview shown BEFORE any write (confirm-gate)
    } catch (err: any) {
      setError(err?.message || 'Could not read that file.');
    }
  };

  // Apply ONLY on explicit confirm (B2 never-silent). v1: auto-merges + fresh; ambiguous review rows
  // fall back to fresh via applyImportPlan's fail-safe. (Per-row review card-stack = polish follow-up.)
  const handleConfirm = async () => {
    if (!plan) return;
    setLoading(true); setError(null);
    try {
      const ops = applyImportPlan(plan);
      for (const add of ops.adds) {
        await addContact(ownerFingerprint, edgeToRecordFields(add) as any);
      }
      for (const up of ops.updates) {
        await updateContact(up.id, edgeToRecordFields(up.survivor) as any);
      }
      setImportedCount(ops.adds.length + ops.updates.length);
      onImported();
    } catch (err: any) {
      setError(err?.message || 'Import failed.');
    } finally {
      setLoading(false);
    }
  };

  const applyCount = plan ? plan.fresh.length + plan.autoMerge.length : 0;

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent data-testid="import-contacts-dialog">
        <DialogHeader>
          <DialogTitle>Import contacts</DialogTitle>
          <DialogDescription>
            Import a .vcf (vCard) file from your phone or email. Everything stays on your device — nothing is uploaded.
          </DialogDescription>
        </DialogHeader>

        {error && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Import problem</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {importedCount !== null ? (
          <Alert data-testid="import-done">
            <Users className="h-4 w-4" />
            <AlertTitle>Imported {importedCount} contact{importedCount === 1 ? '' : 's'}</AlertTitle>
            <AlertDescription>Your address book has them now.</AlertDescription>
          </Alert>
        ) : plan ? (
          <div className="space-y-2" data-testid="import-preview">
            <div className="flex items-center gap-2 text-sm">
              <UserPlus className="h-4 w-4 text-emerald-400" />
              <span data-testid="fresh-count">{plan.fresh.length}</span>&nbsp;new contact{plan.fresh.length === 1 ? '' : 's'}
            </div>
            <div className="flex items-center gap-2 text-sm">
              <GitMerge className="h-4 w-4 text-amber-400" />
              <span data-testid="merge-count">{plan.autoMerge.length}</span>&nbsp;merge into existing (living data wins)
            </div>
            {plan.review.length > 0 && (
              <div className="flex items-center gap-2 text-sm">
                <AlertTriangle className="h-4 w-4 text-amber-400" />
                <span data-testid="review-count">{plan.review.length}</span>&nbsp;need a closer look
              </div>
            )}
          </div>
        ) : (
          <div className="py-6 flex flex-col items-center gap-3">
            <input
              ref={fileRef}
              type="file"
              accept=".vcf,text/vcard,text/x-vcard"
              className="hidden"
              data-testid="vcf-input"
              onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
            />
            <Button onClick={() => fileRef.current?.click()} data-testid="choose-vcf">
              <Upload className="h-4 w-4 mr-2" />Choose a .vcf file
            </Button>
          </div>
        )}

        <DialogFooter>
          {plan && importedCount === null && (
            <Button onClick={handleConfirm} disabled={loading} data-testid="import-confirm">
              {loading ? 'Importing…' : `Import ${applyCount} contact${applyCount === 1 ? '' : 's'}`}
            </Button>
          )}
          <Button variant="outline" onClick={() => close(false)}>
            {importedCount !== null ? 'Done' : 'Cancel'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
