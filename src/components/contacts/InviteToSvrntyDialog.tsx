'use client';

/**
 * Invite to SVRNTY — asks how to send (link vs QR).
 *
 * ★ TEAM ASK: invitation responses need a special setting (reach / consent /
 * pending-joiner). Cursor ships send chrome only; fleet owns invite→response wire.
 * Until then we reuse the owner's signed share short-link as the invite payload.
 */

import { useEffect, useState, type CSSProperties } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { SimpleQRCode } from '@/components/SimpleQRCode';
import { solarEmber as E } from '@/components/recovery/solar-ember';

export type InviteSendChannel = 'link' | 'qr';

export type InviteToSvrntyDialogProps = {
  open: boolean;
  contactName: string;
  inviteUrl: string | null;
  loading?: boolean;
  error?: string | null;
  onClose: () => void;
  onPrepare?: () => void | Promise<void>;
};

const btn: CSSProperties = {
  fontFamily: E.fontSans,
  fontSize: 13,
  padding: '8px 14px',
  borderRadius: 10,
  cursor: 'pointer',
  border: `1px solid ${E.border}`,
  background: 'transparent',
  color: E.text,
};

export function InviteToSvrntyDialog({
  open,
  contactName,
  inviteUrl,
  loading,
  error,
  onClose,
  onPrepare,
}: InviteToSvrntyDialogProps) {
  const [channel, setChannel] = useState<InviteSendChannel | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!open) {
      setChannel(null);
      setCopied(false);
      return;
    }
    void onPrepare?.();
  }, [open, onPrepare]);

  const copyLink = async () => {
    if (!inviteUrl) return;
    try {
      await navigator.clipboard.writeText(inviteUrl);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(next) => { if (!next) onClose(); }}>
      <DialogContent
        className="sm:max-w-md"
        style={{ fontFamily: E.fontSans, background: E.surfaceSolid, borderColor: E.border }}
      >
        <DialogHeader>
          <DialogTitle style={{ color: E.text, fontFamily: E.fontSans }}>
            Invite {contactName || 'contact'} to SVRNTY
          </DialogTitle>
          <DialogDescription style={{ color: E.muted, fontSize: 13, lineHeight: 1.5 }}>
            Choose how to send the invite. Their response uses a special setting the fleet
            still owns (see PR team asks).
          </DialogDescription>
        </DialogHeader>

        {!channel ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, padding: '8px 0' }}>
            <button
              type="button"
              style={{ ...btn, borderColor: E.borderLit, color: E.accent }}
              onClick={() => setChannel('link')}
            >
              Send as link
            </button>
            <button type="button" style={btn} onClick={() => setChannel('qr')}>
              Show QR code
            </button>
          </div>
        ) : loading ? (
          <p style={{ color: E.muted, fontSize: 13 }}>Preparing invite…</p>
        ) : error ? (
          <p style={{ color: E.danger, fontSize: 13 }}>{error}</p>
        ) : !inviteUrl ? (
          <p style={{ color: E.muted, fontSize: 13 }}>No invite URL yet.</p>
        ) : channel === 'qr' ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
            <SimpleQRCode value={inviteUrl} size={200} />
            <p style={{ margin: 0, fontSize: 11, color: E.dim, textAlign: 'center', wordBreak: 'break-all' }}>
              {inviteUrl}
            </p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <code
              style={{
                display: 'block',
                padding: 12,
                borderRadius: 10,
                border: `1px solid ${E.border}`,
                background: E.inputBg,
                fontSize: 11,
                color: E.text,
                wordBreak: 'break-all',
                fontFamily: E.fontMono,
              }}
            >
              {inviteUrl}
            </code>
            <button
              type="button"
              style={{ ...btn, color: E.accent, borderColor: E.borderLit }}
              onClick={() => void copyLink()}
            >
              {copied ? 'Copied' : 'Copy link'}
            </button>
          </div>
        )}

        <DialogFooter className="gap-2">
          {channel ? (
            <button type="button" style={btn} onClick={() => setChannel(null)}>
              Back
            </button>
          ) : null}
          <button type="button" style={btn} onClick={onClose}>
            Close
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
