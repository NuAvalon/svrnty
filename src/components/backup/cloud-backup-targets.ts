// Cloud-backup UI state — device-local preference + last-backup status.
// Transport (OAuth / upload / download) is Athena. This module never stores tokens
// and never talks to a cloud adapter until isCloudBlobTransportLive() is true.

export const CLOUD_BACKUP_TARGET_KEY = 'svrnty.cloud-backup.target';
export const CLOUD_BACKUP_STATUS_KEY = 'svrnty.cloud-backup.status';

export type CloudBackupTargetId = 'dropbox' | 'icloud' | 'google-drive';

export type CloudBackupStatus = {
  at: string;
  ok: boolean;
  target: CloudBackupTargetId | null;
  /** Honest: glass can only save a local file until fleet transport is live. */
  kind: 'file';
};

export const CLOUD_BACKUP_TARGETS: { id: CloudBackupTargetId; name: string }[] = [
  { id: 'dropbox', name: 'Dropbox' },
  { id: 'icloud', name: 'iCloud' },
  { id: 'google-drive', name: 'Google Drive' },
];

export const CLOUD_BACKUP_COPY = {
  title: 'Cloud backup',
  intro:
    'Choose where you intend to keep your backup file. This is backup, not multi-device sync.',
  transportPending:
    'Sending the file to this service is not wired yet. Back up now still saves a backup file on this device. Put that file in the service yourself.',
  pickTarget: 'Pick a backup target to connect it.',
  connectedPrefix: 'Backup target',
  clearTarget: 'Clear target',
  statusEmpty: 'No backup on this device yet.',
  statusOkPrefix: 'Last backup',
  statusFailPrefix: 'Last backup failed',
  statusKindFile: 'Saved as a file on this device.',
  backupNow: 'Back up now',
  restore: 'Restore from backup',
  restoreHint:
    'Pick the backup file you kept. Restore uses your password or recovery code — same as the start screen.',
  restoreGateHint:
    'Pick the backup file you kept (Dropbox, iCloud, or Google Drive).',
} as const;

/** Athena OAuth + blob transport. Stay false until the fleet wires it. */
export function isCloudBlobTransportLive(): boolean {
  return false;
}

export function isCloudBackupTargetId(value: unknown): value is CloudBackupTargetId {
  return value === 'dropbox' || value === 'icloud' || value === 'google-drive';
}

export function parseCloudBackupTarget(raw: string | null): CloudBackupTargetId | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as { target?: unknown };
    return isCloudBackupTargetId(parsed.target) ? parsed.target : null;
  } catch {
    return isCloudBackupTargetId(raw) ? raw : null;
  }
}

export function parseCloudBackupStatus(raw: string | null): CloudBackupStatus | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<CloudBackupStatus>;
    if (typeof parsed.at !== 'string' || typeof parsed.ok !== 'boolean') return null;
    if (parsed.kind !== 'file') return null;
    const target = parsed.target === null || parsed.target === undefined
      ? null
      : isCloudBackupTargetId(parsed.target)
        ? parsed.target
        : null;
    if (parsed.target !== null && parsed.target !== undefined && target === null) return null;
    return { at: parsed.at, ok: parsed.ok, target, kind: 'file' };
  } catch {
    return null;
  }
}

export function serializeCloudBackupTarget(target: CloudBackupTargetId): string {
  return JSON.stringify({ target });
}

export function serializeCloudBackupStatus(status: CloudBackupStatus): string {
  return JSON.stringify({
    at: status.at,
    ok: status.ok,
    target: status.target,
    kind: 'file' as const,
  });
}

export function formatBackupWhen(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

export function formatBackupStatus(status: CloudBackupStatus | null): string {
  if (!status) return CLOUD_BACKUP_COPY.statusEmpty;
  const when = formatBackupWhen(status.at);
  if (status.ok) {
    return `${CLOUD_BACKUP_COPY.statusOkPrefix}: ${when}. ${CLOUD_BACKUP_COPY.statusKindFile}`;
  }
  return `${CLOUD_BACKUP_COPY.statusFailPrefix}: ${when}.`;
}

export function targetDisplayName(id: CloudBackupTargetId | null): string {
  if (!id) return '';
  return CLOUD_BACKUP_TARGETS.find((t) => t.id === id)?.name ?? id;
}

type Kv = {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
};

const memory = new Map<string, string>();
const memoryKv: Kv = {
  getItem: (k) => memory.get(k) ?? null,
  setItem: (k, v) => {
    memory.set(k, v);
  },
  removeItem: (k) => {
    memory.delete(k);
  },
};

function storage(): Kv {
  try {
    if (typeof localStorage !== 'undefined') return localStorage;
  } catch {
    /* private mode / SSR */
  }
  return memoryKv;
}

const listeners = new Set<() => void>();

function emit() {
  for (const l of listeners) l();
}

export function subscribeCloudBackup(onStoreChange: () => void): () => void {
  listeners.add(onStoreChange);
  return () => {
    listeners.delete(onStoreChange);
  };
}

export function loadCloudBackupTarget(): CloudBackupTargetId | null {
  return parseCloudBackupTarget(storage().getItem(CLOUD_BACKUP_TARGET_KEY));
}

export function loadCloudBackupStatus(): CloudBackupStatus | null {
  return parseCloudBackupStatus(storage().getItem(CLOUD_BACKUP_STATUS_KEY));
}

let snapshot: {
  target: CloudBackupTargetId | null;
  status: CloudBackupStatus | null;
} = { target: null, status: null };

function statusEqual(a: CloudBackupStatus | null, b: CloudBackupStatus | null): boolean {
  if (a === b) return true;
  if (!a || !b) return false;
  return a.at === b.at && a.ok === b.ok && a.target === b.target && a.kind === b.kind;
}

export function getCloudBackupSnapshot(): {
  target: CloudBackupTargetId | null;
  status: CloudBackupStatus | null;
} {
  const target = loadCloudBackupTarget();
  const status = loadCloudBackupStatus();
  if (snapshot.target === target && statusEqual(snapshot.status, status)) return snapshot;
  snapshot = { target, status };
  return snapshot;
}

export function connectCloudBackupTarget(id: CloudBackupTargetId): void {
  storage().setItem(CLOUD_BACKUP_TARGET_KEY, serializeCloudBackupTarget(id));
  emit();
}

export function clearCloudBackupTarget(): void {
  storage().removeItem(CLOUD_BACKUP_TARGET_KEY);
  emit();
}

export function recordCloudBackupAttempt(input: {
  ok: boolean;
  target: CloudBackupTargetId | null;
  at?: string;
}): void {
  const status: CloudBackupStatus = {
    at: input.at ?? new Date().toISOString(),
    ok: input.ok,
    target: input.target,
    kind: 'file',
  };
  storage().setItem(CLOUD_BACKUP_STATUS_KEY, serializeCloudBackupStatus(status));
  emit();
}

/** Test helper — does not run in the app. */
export function resetCloudBackupStoreForTests(): void {
  memory.clear();
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem(CLOUD_BACKUP_TARGET_KEY);
      localStorage.removeItem(CLOUD_BACKUP_STATUS_KEY);
    }
  } catch {
    /* ignore */
  }
  snapshot = { target: null, status: null };
  emit();
}
