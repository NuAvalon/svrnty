'use client';

/**
 * Cloud-backup UI shell (queue #1 / M9).
 * Connect a target + last-backup status + restore trigger.
 * Does not pack vaults, talk OAuth, or choose which restore key decrypts what.
 */

import { useSyncExternalStore, type CSSProperties } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import {
  CLOUD_BACKUP_COPY,
  CLOUD_BACKUP_TARGETS,
  clearCloudBackupTarget,
  connectCloudBackupTarget,
  formatBackupStatus,
  getCloudBackupSnapshot,
  isCloudBlobTransportLive,
  subscribeCloudBackup,
  targetDisplayName,
  type CloudBackupTargetId,
} from './cloud-backup-targets';

export type CloudBackupShellProps = {
  surface: 'settings' | 'restore-gate';
  onBackupNow?: () => void;
  onRestore?: () => void;
};

const panel: CSSProperties = {
  marginTop: 16,
  padding: '16px 18px',
  background: E.surface,
  border: `1px solid ${E.border}`,
  borderRadius: 12,
  backdropFilter: 'blur(16px)',
  WebkitBackdropFilter: 'blur(16px)',
  width: '100%',
  textAlign: 'left' as const,
};

const targetBtn = (lit: boolean): CSSProperties => ({
  flex: 1,
  minWidth: 0,
  padding: '10px 8px',
  borderRadius: 10,
  border: `1px solid ${lit ? E.borderLit : E.border}`,
  background: lit ? 'rgba(249, 168, 37, 0.10)' : 'transparent',
  color: lit ? E.accent : E.text,
  fontFamily: E.fontSans,
  fontSize: 12,
  letterSpacing: '0.04em',
  cursor: 'pointer',
});

const actionBtn = (primary: boolean, disabled?: boolean): CSSProperties => ({
  width: '100%',
  padding: '10px 14px',
  borderRadius: 10,
  border: `1px solid ${primary ? E.borderLit : E.border}`,
  background: primary ? 'rgba(249, 168, 37, 0.10)' : 'transparent',
  color: primary ? E.accent : E.text,
  fontFamily: E.fontSans,
  fontSize: 13,
  cursor: disabled ? 'not-allowed' : 'pointer',
  opacity: disabled ? 0.45 : 1,
});

export function CloudBackupShell({ surface, onBackupNow, onRestore }: CloudBackupShellProps) {
  const snap = useSyncExternalStore(
    subscribeCloudBackup,
    getCloudBackupSnapshot,
    getCloudBackupSnapshot,
  );
  const transportLive = isCloudBlobTransportLive();
  const target = snap.target;
  const statusLine = formatBackupStatus(snap.status);

  const select = (id: CloudBackupTargetId) => {
    connectCloudBackupTarget(id);
  };

  return (
    <section
      data-testid="cloud-backup-shell"
      data-surface={surface}
      aria-label={CLOUD_BACKUP_COPY.title}
      style={panel}
    >
      <h3
        style={{
          margin: '0 0 4px',
          fontFamily: E.fontSans,
          fontSize: 13,
          fontWeight: 600,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          color: E.accent,
        }}
      >
        {CLOUD_BACKUP_COPY.title}
      </h3>
      <p
        style={{
          margin: '0 0 14px',
          fontFamily: E.fontSans,
          fontSize: 12,
          lineHeight: 1.45,
          color: E.muted,
        }}
      >
        {surface === 'restore-gate'
          ? CLOUD_BACKUP_COPY.restoreGateHint
          : CLOUD_BACKUP_COPY.intro}
      </p>

      <div
        role="group"
        aria-label="Backup targets"
        style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}
      >
        {CLOUD_BACKUP_TARGETS.map((t) => {
          const lit = target === t.id;
          return (
            <button
              key={t.id}
              type="button"
              data-testid={`cloud-backup-target-${t.id}`}
              aria-pressed={lit}
              onClick={() => select(t.id)}
              style={targetBtn(lit)}
            >
              {t.name}
            </button>
          );
        })}
      </div>

      <p
        data-testid="cloud-backup-connected"
        style={{
          margin: '0 0 8px',
          fontFamily: E.fontSans,
          fontSize: 12,
          color: target ? E.text : E.dim,
        }}
      >
        {target
          ? `${CLOUD_BACKUP_COPY.connectedPrefix}: ${targetDisplayName(target)}`
          : CLOUD_BACKUP_COPY.pickTarget}
      </p>

      {!transportLive && target ? (
        <p
          data-testid="cloud-backup-transport-pending"
          style={{
            margin: '0 0 12px',
            fontFamily: E.fontSans,
            fontSize: 12,
            lineHeight: 1.45,
            color: E.muted,
          }}
        >
          {CLOUD_BACKUP_COPY.transportPending}
        </p>
      ) : null}

      {target ? (
        <button
          type="button"
          data-testid="cloud-backup-clear"
          onClick={() => clearCloudBackupTarget()}
          style={{
            ...actionBtn(false),
            width: 'auto',
            padding: '4px 0 12px',
            border: 'none',
            color: E.dim,
            fontSize: 12,
            textDecoration: 'underline',
            textUnderlineOffset: 2,
          }}
        >
          {CLOUD_BACKUP_COPY.clearTarget}
        </button>
      ) : null}

      <p
        data-testid="cloud-backup-status"
        role="status"
        style={{
          margin: '0 0 12px',
          fontFamily: E.fontSans,
          fontSize: 12,
          lineHeight: 1.45,
          color: E.text,
        }}
      >
        {statusLine}
      </p>

      {surface === 'settings' ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <button
            type="button"
            data-testid="cloud-backup-now"
            onClick={() => onBackupNow?.()}
            disabled={!target}
            style={actionBtn(true, !target)}
          >
            {CLOUD_BACKUP_COPY.backupNow}
          </button>
          {onRestore ? (
            <button
              type="button"
              data-testid="cloud-backup-restore"
              onClick={() => onRestore()}
              style={actionBtn(false)}
            >
              {CLOUD_BACKUP_COPY.restore}
            </button>
          ) : null}
          <p
            style={{
              margin: 0,
              fontFamily: E.fontSans,
              fontSize: 11,
              lineHeight: 1.4,
              color: E.dim,
            }}
          >
            {CLOUD_BACKUP_COPY.restoreHint}
          </p>
        </div>
      ) : (
        <button
          type="button"
          data-testid="cloud-backup-restore"
          onClick={() => onRestore?.()}
          style={actionBtn(true)}
        >
          {CLOUD_BACKUP_COPY.restore}
        </button>
      )}
    </section>
  );
}
