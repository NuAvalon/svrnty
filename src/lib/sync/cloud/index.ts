// src/lib/sync/cloud/index.ts
// Cloud adapter registry. Import the one you need.

export type { CloudAdapter, CloudConfig, CloudFile } from './adapter';
export { vaultFilename } from './adapter';
export { GoogleDriveAdapter } from './google-drive';
export { DropboxAdapter } from './dropbox';
export { ICloudAdapter } from './icloud';
export { WebDAVAdapter } from './webdav';
export { LocalFileAdapter } from './local-file';

import type { CloudAdapter } from './adapter';
import { GoogleDriveAdapter } from './google-drive';
import { DropboxAdapter } from './dropbox';
import { ICloudAdapter } from './icloud';
import { WebDAVAdapter } from './webdav';
import { LocalFileAdapter } from './local-file';

/**
 * Create a cloud adapter by provider name.
 */
export function createCloudAdapter(provider: string): CloudAdapter {
  switch (provider) {
    case 'local-file': return new LocalFileAdapter();
    case 'google-drive': return new GoogleDriveAdapter();
    case 'dropbox': return new DropboxAdapter();
    case 'icloud': return new ICloudAdapter();
    case 'webdav': return new WebDAVAdapter();
    default: throw new Error(`Unknown cloud provider: ${provider}`);
  }
}

/**
 * Available providers for UI display.
 */
export const CLOUD_PROVIDERS = [
  {
    id: 'local-file',
    name: 'Local File',
    icon: 'download',
    requiresOAuth: false,
    description: 'Export your vault as an encrypted file. No cloud. No network. Just a file on your device.',
  },
  {
    id: 'google-drive',
    name: 'Google Drive',
    icon: 'cloud',
    requiresOAuth: true,
    description: 'Store your vault in Google Drive. Requires a Google account.',
  },
  {
    id: 'dropbox',
    name: 'Dropbox',
    icon: 'cloud',
    requiresOAuth: true,
    description: 'Store your vault in Dropbox. Requires a Dropbox account.',
  },
  {
    id: 'icloud',
    name: 'iCloud',
    icon: 'cloud',
    requiresOAuth: false,
    description: 'Store your vault in iCloud. Requires an Apple ID and Safari or macOS.',
  },
  {
    id: 'webdav',
    name: 'Self-Hosted (WebDAV)',
    icon: 'server',
    requiresOAuth: false,
    description: 'Store your vault on your own server. Nextcloud, Synology, or any WebDAV host.',
  },
] as const;
