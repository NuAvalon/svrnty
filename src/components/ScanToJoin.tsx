'use client';

/**
 * ScanToJoin — camera QR receive-side for the in-page join.
 *
 * Mounted only after the user taps Scan (permission on tap, not on dialog open).
 * Decodes locally (shared QrScanCamera → decodeQrFrame) → parseInviteUrl (INV-4) →
 * parent mounts the SAME <JoinerCeremony>. No second join path.
 *
 * INV-5: the decoded string is never stored in React state, never logged, never
 * shown. Errors are FIXED strings. Stream stops on close / success / error / unmount.
 * Frames stay in RAM — never uploaded or persisted.
 */

import { useCallback } from 'react';
import { inviteFromScannedText } from '@/lib/invite/scanInvite';
import type { ParsedInvite } from '@/lib/invite/parseInviteUrl';
import { QrScanCamera, type QrScanOutcome } from '@/components/scan/QrScanCamera';
import { solarEmber as E } from '@/components/recovery/solar-ember';

type Props = {
  onInvite: (invite: ParsedInvite) => void;
  onClose: () => void;
};

export function ScanToJoin({ onInvite, onClose }: Props) {
  const handleDecoded = useCallback(
    (text: string): QrScanOutcome | void => {
      const result = inviteFromScannedText(text);
      if (result.ok) {
        onInvite(result.invite);
        return { done: true };
      }
      return { error: result.error };
    },
    [onInvite],
  );

  return (
    <div>
      <p
        style={{
          margin: 0,
          fontSize: 11,
          letterSpacing: '0.2em',
          textTransform: 'uppercase',
          color: E.accent,
        }}
      >
        Add a connection
      </p>
      <h2 style={{ margin: '8px 0 0', fontSize: 22, fontWeight: 400, color: E.text }}>
        Scan invite
      </h2>
      <p style={{ margin: '10px 0 0', fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
        Point the camera at the invite QR on their screen.
      </p>

      <QrScanCamera
        onDecoded={handleDecoded}
        videoTestId="scan-invite-video"
        errorTestId="scan-invite-error"
        ariaLabel="Camera preview for scanning an invite QR"
      />

      <button
        type="button"
        data-testid="scan-invite-cancel"
        onClick={onClose}
        style={{
          marginTop: 16,
          width: '100%',
          padding: '12px 14px',
          borderRadius: 8,
          border: `1px solid ${E.border}`,
          background: 'rgba(249,168,37,0.04)',
          color: E.muted,
          cursor: 'pointer',
          fontFamily: E.fontSans,
          fontSize: 12,
          fontWeight: 500,
          letterSpacing: '0.12em',
          textTransform: 'uppercase',
        }}
      >
        Paste instead
      </button>
    </div>
  );
}
