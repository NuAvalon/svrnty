'use client';

/**
 * Reads the owner's "restored from an older backup" marker and shows the notice while it is there. The marker is the only source of truth: this component remembers nothing but the
 * last read, so a tab that is opened again (or a finished export, through `reloadKey`) looks again. Not now is the PAGE's session flag (`dismissed`), never a write to the marker, so the
 * notice comes back on the next load until a new backup has been made. An absent or unreadable marker shows nothing.
 */

import { useEffect, useState } from 'react';
import { shouldShowRestoredNudge, type OwnerRecordRead, type RestoredFromOldBackup } from '@/lib/identity/restored-from-old-backup';
import { OldBackupNotice } from './OldBackupNotice';

export type OldBackupReminderProps = {
  fingerprint: string;
  /** Not now was pressed this session (held by the page, so a tab switch does not bring the notice back). */
  dismissed: boolean;
  onDismiss: () => void;
  onMakeBackup: () => void;
  /** Bumped when an export finishes, so the marker is read again. */
  reloadKey: number;
};

export function OldBackupReminder({ fingerprint, dismissed, onDismiss, onMakeBackup, reloadKey }: OldBackupReminderProps) {
  const [read, setRead] = useState<OwnerRecordRead<RestoredFromOldBackup>>({ state: 'absent' });

  useEffect(() => {
    if (!fingerprint) {
      setRead({ state: 'absent' });
      return;
    }
    let cancelled = false;
    import('@/lib/identity/client-store')
      .then((m) => m.readRestoredFromOldBackup(fingerprint))
      .then((r) => { if (!cancelled) setRead(r); })
      .catch(() => { if (!cancelled) setRead({ state: 'unreadable' }); });
    return () => { cancelled = true; };
  }, [fingerprint, reloadKey]);

  if (!shouldShowRestoredNudge(read, dismissed)) return null;
  return <OldBackupNotice onMakeBackup={onMakeBackup} onNotNow={onDismiss} />;
}
