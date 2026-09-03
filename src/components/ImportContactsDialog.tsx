"use client";

// ImportContactsDialog — the 0.12 "import the gray sea" flow.
// vCard (.vcf) → gray contacts → dedup preview → CONFIRM-GATE (never silent, B2) →
// applyImportPlan → addContact/updateContact → onImported(). LOCAL-only: the file is read in-browser,
// nothing is uploaded. Grays are keyless (addContact's fp↔key check is skipped when no key present).
//
// Contract: props below; the parent renders <ImportContactsDialog .../> in the contacts view
// with a trigger + showVcardImport state, onImported → the parent's loadContacts() refreshes the book.

import React, { useRef, useState } from 'react';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Upload, Users, GitMerge, UserPlus, AlertTriangle } from 'lucide-react';
import type { TrustEdge } from '@/lib/trust/types';
import { migrateTrustLevel } from '@/lib/trust/types';
import { fromVCard } from '@/lib/contacts/vcard';
import { dedupeContacts, type DedupPlan } from '@/lib/contacts/import-dedup';
import { applyImportPlan } from '@/lib/contacts/import-apply';
import { mergeProvenance, type ChannelChange } from '@/lib/contacts/import-diff';
import { getAllContacts, addContact, updateContact } from '@/lib/identity/client-store';

interface ImportContactsDialogProps {
  ownerFingerprint: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onImported: () => void;
}

// Project a stored ContactRecord → TrustEdge for dedup's `existing`. Minimal: only the fields
// dedup reads (peer_email + contact_info channels) + identity/name for the merge.
// TODO: replace with contactRecordToEdge from '@/lib/trust/contact-edge' when it lands
// (adds pq carry — moot for grays; transparent upgrade).
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
    // Project the REAL trust state (was hardcoded false, discarding trust_level) so a merge
    // INTO a trusted contact can be flagged — the precondition for (A)'s review-routing + the diff warning.
    trusted: migrateTrustLevel(c.trust_level), trusted_since: null, last_interaction: c.added_at || '',
    decay_days: 730, trust_history: [],
    verification: { method: 'none', verified_at: null },
    mutual: { they_trust_me: null, last_sync: null, reciprocal: false },
    tags: c.tags ?? [], notes: c.notes || '', connection_channels: [], added_at: c.added_at || '',
  } as TrustEdge;
}

// Edge → the ContactRecord fields to persist for a gray (keyless) contact.
// NOTE: mirrors the 0.14 FIELD_MAP — primary phone/email + phones/emails lists + contact_info
// (verified no drift). A gray has no fingerprint/public_key → lands keyless (store keeps an
// empty fingerprint ABSENT, not '', so multi-gray import doesn't collide the UNIQUE index).
// trust_level:'unverified' → projects trusted:false → the book renders it GRAY (getContactState,
// contact-state.ts:27). The absent fingerprint is NOT the gray trigger; `trusted` is.
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

/** Format channels for the preview: "phone +1..., signal @handle". */
const fmtChannels = (cs: ChannelChange[]): string => cs.map((c) => `${c.type} ${c.value}`).join(', ');

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
          <div className="space-y-3" data-testid="import-preview">
            <div className="flex items-center gap-2 text-sm">
              <UserPlus className="h-4 w-4 text-emerald-400" />
              <span data-testid="fresh-count">{plan.fresh.length}</span>&nbsp;new contact{plan.fresh.length === 1 ? '' : 's'}
            </div>

            <div className="space-y-1">
              <div className="flex items-center gap-2 text-sm">
                <GitMerge className="h-4 w-4 text-amber-400" />
                <span data-testid="merge-count">{plan.autoMerge.length}</span>&nbsp;merge into existing (living data wins)
              </div>
              {/* A per-field DIFF, not a bare count — show what each merge ADDS + why it
                  matched. A channel injected onto a TRUSTED contact renders amber with a warning icon. */}
              {plan.autoMerge.length > 0 && (
                <ul className="pl-6 space-y-1" data-testid="merge-details">
                  {plan.autoMerge.map((am, i) => {
                    const prov = mergeProvenance(am.existing, am.incoming);
                    const name = am.existing.peer_name || am.incoming.peer_name || 'this contact';
                    const toTrusted = am.existing.trusted && prov.added.length > 0;
                    return (
                      <li key={am.existing.id || i} className="text-xs" data-testid="merge-row">
                        <span className="text-slate-300">{name}</span>
                        {prov.matchedOn.length > 0 && (
                          <span className="text-slate-500"> · matched on {fmtChannels(prov.matchedOn)}</span>
                        )}
                        {prov.added.length > 0 ? (
                          <span className={toTrusted ? 'text-amber-300' : 'text-slate-400'} data-testid="merge-added">
                            {' · '}
                            {toTrusted && <AlertTriangle className="inline h-3 w-3 mr-1" />}
                            adds {fmtChannels(prov.added)}{toTrusted && ' to a trusted contact'}
                          </span>
                        ) : (
                          <span className="text-slate-600"> · nothing new</span>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>

            {plan.review.length > 0 && (
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-sm">
                  <AlertTriangle className="h-4 w-4 text-amber-400" />
                  <span data-testid="review-count">{plan.review.length}</span>&nbsp;need a closer look
                </div>
                {/* The review card is a DIFF, not a count. (A) routes a
                    trusted-target + net-new-channel merge here (candidates:[target]); the ambiguous
                    (>1 match) case also lands here. Both show matched-on + what WOULD be added. */}
                <div className="pl-6 space-y-2" data-testid="review-details">
                  {plan.review.map((row, i) => {
                    const reason = (row as { reason?: string }).reason;
                    const injection =
                      reason === 'trusted-net-new' ||
                      (row.candidates.length === 1 && row.candidates.some((c) => c.trusted));
                    const name = row.incoming.peer_name || row.incoming.peer_email || 'this contact';
                    return (
                      <div key={i} className="rounded border border-amber-500/30 p-2 text-xs" data-testid="review-row">
                        <div className={injection ? 'text-amber-300 font-medium' : 'text-slate-300'}>
                          {injection ? (
                            <>
                              <AlertTriangle className="inline h-3 w-3 mr-1" />
                              <span className="font-medium">{name}</span> would add new channels to a trusted contact
                            </>
                          ) : (
                            <>
                              <span className="font-medium">{name}</span> could match {row.candidates.length} existing contacts
                            </>
                          )}
                        </div>
                        <ul className="mt-1 space-y-0.5">
                          {row.candidates.map((cand, j) => {
                            const prov = mergeProvenance(cand, row.incoming);
                            return (
                              <li key={cand.id || j} className="text-slate-400">
                                <span className="text-slate-300">{cand.peer_name || cand.peer_email || cand.id}</span>
                                {cand.trusted && <span className="text-amber-400"> (trusted)</span>}
                                {prov.matchedOn.length > 0 && (
                                  <span className="text-slate-500"> · matched on {fmtChannels(prov.matchedOn)}</span>
                                )}
                                {prov.added.length > 0 && (
                                  <span className="text-amber-300" data-testid="review-added"> · would add {fmtChannels(prov.added)}</span>
                                )}
                              </li>
                            );
                          })}
                        </ul>
                        <div className="mt-1 text-slate-500 italic">Kept as a separate contact unless you confirm the merge.</div>
                      </div>
                    );
                  })}
                </div>
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
