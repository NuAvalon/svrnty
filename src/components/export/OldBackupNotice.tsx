'use client';

/**
 * The notice on the owner's Identity tab after a restore from an older-format backup (copy ledger row 329b). A presenter only: it renders the reviewed constants and calls what it is
 * handed. Make a new backup opens the existing Full Backup flow and nothing else; Not now hides the notice for this session. Neither button is the default and nothing here closes on its own.
 */

import { solarEmber as E } from '@/components/recovery/solar-ember';
import { cardVerbBtnStyle } from '@/components/ui/CardActionMenu';
import { OLD_BACKUP_MAKE_NEW, OLD_BACKUP_NOT_NOW, OLD_BACKUP_NOTICE } from './old-backup-copy';

export type OldBackupNoticeProps = {
  onMakeBackup: () => void;
  onNotNow: () => void;
};

export function OldBackupNotice({ onMakeBackup, onNotNow }: OldBackupNoticeProps) {
  return (
    <div
      data-testid="old-backup-notice"
      style={{ marginTop: 10, padding: 10, borderRadius: 12, border: `1px solid ${E.border}`, background: E.surface, display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 440, width: '100%' }}
    >
      <p data-testid="old-backup-text" role="status" style={{ margin: 0, fontFamily: E.fontSans, fontSize: 13, lineHeight: 1.45, color: E.text }}>
        {OLD_BACKUP_NOTICE}
      </p>
      <div style={{ display: 'flex', gap: 8 }}>
        <button type="button" data-testid="old-backup-make" onClick={onMakeBackup} style={cardVerbBtnStyle()}>
          {OLD_BACKUP_MAKE_NEW}
        </button>
        <button type="button" data-testid="old-backup-not-now" onClick={onNotNow} style={cardVerbBtnStyle({ muted: true })}>
          {OLD_BACKUP_NOT_NOW}
        </button>
      </div>
    </div>
  );
}
