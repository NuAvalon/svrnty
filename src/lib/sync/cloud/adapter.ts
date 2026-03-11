// src/lib/sync/cloud/adapter.ts
// Cloud storage adapter interface.
// Each provider implements this interface. The vault is just a blob —
// the provider never sees plaintext. Dumb storage.

export interface CloudFile {
  id: string;                       // provider-specific file ID
  name: string;
  size: number;
  lastModified: string;
  mimeType?: string;
}

export interface CloudConfig {
  /** OAuth access token (Google Drive, Dropbox) */
  accessToken?: string;
  /** OAuth refresh token */
  refreshToken?: string;
  /** Client ID for OAuth */
  clientId?: string;
  /** Client secret for OAuth */
  clientSecret?: string;
  /** WebDAV server URL */
  webdavUrl?: string;
  /** WebDAV username */
  username?: string;
  /** WebDAV password */
  password?: string;
  /** iCloud container ID */
  containerId?: string;
  /** Folder path within the provider */
  folderPath?: string;
}

export interface CloudAdapter {
  /** Provider name for display */
  readonly name: string;

  /** Provider identifier */
  readonly provider: 'local-file' | 'google-drive' | 'dropbox' | 'icloud' | 'webdav';

  /** Connect to the cloud provider. Call before any operations. */
  connect(config: CloudConfig): Promise<void>;

  /** Disconnect and clean up tokens. */
  disconnect(): Promise<void>;

  /** Whether the adapter is currently connected and ready. */
  isConnected(): boolean;

  /** List .svrnty files in the configured folder. */
  list(): Promise<CloudFile[]>;

  /** Upload a vault blob. Returns the file ID. */
  upload(data: ArrayBuffer, filename: string): Promise<string>;

  /** Download a vault blob by file ID. */
  download(fileId: string): Promise<ArrayBuffer>;

  /** Delete a vault file by ID. */
  delete(fileId: string): Promise<void>;

  /**
   * Get the OAuth authorization URL for providers that need it.
   * Returns null for providers that use direct auth (WebDAV).
   */
  getAuthUrl?(redirectUri: string): string | null;

  /**
   * Exchange an OAuth authorization code for tokens.
   * Returns the tokens to store in config.
   */
  handleAuthCallback?(code: string, redirectUri: string): Promise<{
    accessToken: string;
    refreshToken?: string;
    expiresAt?: string;
  }>;
}

/**
 * Vault filename convention.
 * Uses fingerprint hint so the user can identify which vault is which
 * if they have multiple identities.
 */
export function vaultFilename(fingerprintHint: string): string {
  return `svrnty-vault-${fingerprintHint}.svrnty`;
}
