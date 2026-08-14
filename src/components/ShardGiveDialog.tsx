"use client";

// ShardGiveDialog — "the tear" (give side).
// Tear off ONE piece of your social-recovery vault and entrust it to a contact,
// delivered over the same client-side encrypted relay channel as the identity card.
// Giving one shard of an M-of-N split is safe by design: a single piece cannot
// reconstruct anything (any THRESHOLD of them can). We enforce one-piece-per-contact.

import React, { useState, useEffect, useCallback } from 'react';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { HeartCrack, Link2, Copy, Check, Clock, ShieldCheck } from 'lucide-react';
import { SimpleQRCode } from '@/components/SimpleQRCode';
import { createRelay } from '@/lib/sync/relay';
import { loadShards, markShardGiven, SHARD_CUSTODY_TYPE } from '@/lib/identity/client-store';

interface ContactLike {
  id: string;
  name: string;
  fingerprint: string;
}

interface ShardGiveDialogProps {
  open: boolean;
  onClose: () => void;
  ownerFingerprint: string;
  ownerName: string;
  contact: ContactLike | null;
  /** Called after a piece is successfully given (to refresh custody state). */
  onGiven?: () => void;
}

type Phase =
  | 'loading'
  | 'ready'        // a piece is available to give
  | 'link'         // link generated, the tear is given
  | 'none'         // this identity has no shards (created pre-feature)
  | 'all-given'    // every piece already handed out
  | 'already-held' // this contact already holds one of your pieces
  | 'error';

export function ShardGiveDialog({
  open, onClose, ownerFingerprint, ownerName, contact, onGiven,
}: ShardGiveDialogProps) {
  const [phase, setPhase] = useState<Phase>('loading');
  const [shardIndex, setShardIndex] = useState<number | null>(null);
  const [shardPayload, setShardPayload] = useState<any>(null);
  const [threshold, setThreshold] = useState(0);
  const [total, setTotal] = useState(0);
  const [remaining, setRemaining] = useState(0);
  const [generating, setGenerating] = useState(false);
  const [link, setLink] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<number | null>(null);
  const [timeLeft, setTimeLeft] = useState('');
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load shard state when the dialog opens.
  useEffect(() => {
    if (!open || !contact) return;
    let cancelled = false;

    (async () => {
      setPhase('loading');
      setLink(null);
      setCopied(false);
      setError(null);
      try {
        const data = await loadShards(ownerFingerprint);
        if (cancelled) return;
        if (!data || !data.shards?.length) { setPhase('none'); return; }

        setThreshold(data.threshold);
        setTotal(data.total);

        const heldByThisContact = data.shards.find(
          s => s.given_to && (s.given_to.contact_id === contact.id || s.given_to.fingerprint === contact.fingerprint),
        );
        if (heldByThisContact) { setPhase('already-held'); return; }

        const ungiven = data.shards.filter(s => !s.given_to);
        setRemaining(ungiven.length);
        if (ungiven.length === 0) { setPhase('all-given'); return; }

        const next = ungiven[0];
        setShardIndex(next.index);
        // Send only the raw shard — never the local custody bookkeeping.
        setShardPayload({
          index: next.index,
          data: next.data,
          identity_fingerprint: next.identity_fingerprint,
          threshold: next.threshold,
        });
        setPhase('ready');
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'Could not read your recovery shards.');
        setPhase('error');
      }
    })();

    return () => { cancelled = true; };
  }, [open, contact, ownerFingerprint]);

  // Countdown for the relay link expiry.
  useEffect(() => {
    if (!expiresAt) return;
    const tick = () => {
      const remainingMs = expiresAt - Date.now();
      if (remainingMs <= 0) { setTimeLeft('Expired'); return; }
      const mins = Math.floor(remainingMs / 60000);
      const secs = Math.floor((remainingMs % 60000) / 1000);
      setTimeLeft(`${mins}:${secs.toString().padStart(2, '0')}`);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [expiresAt]);

  const handleTear = useCallback(async () => {
    if (!contact || shardIndex === null || !shardPayload) return;
    setGenerating(true);
    setError(null);
    try {
      const payload = {
        type: SHARD_CUSTODY_TYPE,
        version: '1.0',
        created_at: new Date().toISOString(),
        from: { fingerprint: ownerFingerprint, name: ownerName },
        threshold,
        total,
        shard: shardPayload,
      };
      const result = await createRelay(JSON.stringify(payload));
      // Record custody only AFTER the encrypted blob is safely posted.
      await markShardGiven(ownerFingerprint, shardIndex, {
        contact_id: contact.id,
        name: contact.name,
        fingerprint: contact.fingerprint,
      });
      setLink(result.url);
      setExpiresAt(new Date(result.expiresAt).getTime());
      setPhase('link');
      onGiven?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create the recovery link.');
    } finally {
      setGenerating(false);
    }
  }, [contact, shardIndex, shardPayload, ownerFingerprint, ownerName, threshold, total, onGiven]);

  const displayLink = link ? link.replace(/^https?:\/\//, '') : null;

  const handleCopy = useCallback(async () => {
    if (!displayLink) return;
    try {
      await navigator.clipboard.writeText(displayLink);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch { /* clipboard blocked — the link is still selectable */ }
  }, [displayLink]);

  return (
    <Dialog open={open} onOpenChange={(isOpen) => { if (!isOpen) onClose(); }}>
      <DialogContent className="sm:max-w-lg bg-gray-950 border-gray-800">
        <DialogHeader>
          <DialogTitle className="text-amber-400 flex items-center gap-2">
            <HeartCrack className="h-5 w-5" />
            Tear off a piece
          </DialogTitle>
          <DialogDescription className="text-gray-400">
            {contact
              ? <>Entrust a piece of your recovery to <span className="text-gray-200">{contact.name}</span>.</>
              : 'Entrust a piece of your recovery to a contact.'}
          </DialogDescription>
        </DialogHeader>

        <div className="py-2">
          {phase === 'loading' && (
            <p className="text-sm text-gray-500 text-center py-8">Reading your recovery shards…</p>
          )}

          {phase === 'none' && (
            <div className="rounded-lg p-4 bg-gray-900 border border-gray-800 text-sm text-gray-400">
              This identity has no recovery shards stored. Shards are minted for identities
              created with social recovery — create a new identity to use the tear.
            </div>
          )}

          {phase === 'already-held' && contact && (
            <div className="rounded-lg p-4 bg-teal-500/6 border border-teal-500/15 text-sm text-gray-300 flex items-start gap-2">
              <ShieldCheck className="h-4 w-4 text-teal-400 flex-shrink-0 mt-0.5" />
              <span>{contact.name} already holds a piece of your recovery. One piece per
              contact keeps any single person below your restore threshold.</span>
            </div>
          )}

          {phase === 'all-given' && (
            <div className="rounded-lg p-4 bg-amber-500/6 border border-amber-500/15 text-sm text-gray-300">
              You've given out all {total} of your pieces. Any {threshold} of your keepers
              can help you restore.
            </div>
          )}

          {phase === 'error' && (
            <div className="rounded-lg p-4 bg-red-500/6 border border-red-500/15 text-sm text-red-300">
              {error || 'Something went wrong.'}
            </div>
          )}

          {phase === 'ready' && contact && (
            <div className="space-y-4">
              <div className="rounded-lg p-4 bg-gray-900 border border-gray-800 text-sm text-gray-400">
                You hold <span className="text-gray-200">{remaining}</span> un-given
                {' '}{remaining === 1 ? 'piece' : 'pieces'} of {total}. Giving one to{' '}
                <span className="text-gray-200">{contact.name}</span> lets any{' '}
                <span className="text-amber-400">{threshold}</span> of your keepers restore you —
                no single piece can, not even theirs.
              </div>
              {error && <p className="text-sm text-red-400">{error}</p>}
              <Button
                onClick={handleTear}
                disabled={generating}
                className="w-full bg-amber-600 hover:bg-amber-700 text-white"
              >
                {generating ? (
                  <><Clock className="h-4 w-4 mr-2 animate-spin" /> Tearing off a piece…</>
                ) : (
                  <><HeartCrack className="h-4 w-4 mr-2" /> Tear off a piece for {contact.name}</>
                )}
              </Button>
            </div>
          )}

          {phase === 'link' && displayLink && contact && (
            <div className="space-y-4">
              <div className="rounded-lg p-4 bg-teal-500/6 border border-teal-500/15">
                <div className="flex items-center gap-2 mb-1">
                  <div className="w-2 h-2 rounded-full bg-teal-400" />
                  <span className="text-xs font-medium text-teal-400">A piece of you is ready for {contact.name}</span>
                </div>
                <p className="text-xs text-gray-500">
                  Send them this link. It's encrypted in your browser — the server never sees the piece.
                </p>
              </div>

              <div className="flex justify-center">
                <div className="bg-white p-3 rounded-lg">
                  <SimpleQRCode value={link || ''} size={180} />
                </div>
              </div>

              <div className="bg-gray-900 border border-gray-800 rounded-lg p-3 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-gray-500 uppercase tracking-wider">Recovery link</span>
                  <div className="flex items-center gap-1 text-xs text-amber-400">
                    <Clock className="h-3 w-3" />
                    <span className="font-mono">{timeLeft}</span>
                  </div>
                </div>
                <div className="bg-gray-950 rounded-md p-3 border border-gray-800">
                  <code className="text-sm text-teal-400 font-mono break-all select-all">{displayLink}</code>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleCopy}
                  className="w-full border-amber-500/30 text-amber-400 hover:bg-amber-500/10"
                >
                  {copied ? <><Check className="h-4 w-4 mr-2" /> Copied</> : <><Copy className="h-4 w-4 mr-2" /> Copy link</>}
                </Button>
              </div>

              <p className="text-xs text-gray-500 text-center">
                Link expires after first use or 15 minutes. {contact.name} now holds 1 of your {total} pieces.
              </p>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
