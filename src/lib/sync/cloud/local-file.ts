// src/lib/sync/cloud/local-file.ts
// Local file adapter — export/import vault directly to/from the filesystem.
// No cloud, no network, no third party. Just an encrypted file on your device.
//
// Uses the File System Access API where available (Chrome, Edge) for seamless
// save-to-disk / open-from-disk. Falls back to download/upload for other browsers.
//
// The vault is always AES-256-GCM encrypted before touching disk.
// The adapter never sees plaintext — it moves opaque blobs.

import type { CloudAdapter, CloudConfig, CloudFile } from './adapter';

export class LocalFileAdapter implements CloudAdapter {
  readonly name = 'Local File';
  readonly provider = 'local-file' as const;

  private connected = false;
  private fileHandle: any = null; // FileSystemFileHandle (where supported)
  private lastFile: { name: string; size: number; lastModified: string; data: ArrayBuffer } | null = null;

  async connect(_config: CloudConfig): Promise<void> {
    // No auth needed — local file system
    this.connected = true;
  }

  async disconnect(): Promise<void> {
    this.fileHandle = null;
    this.lastFile = null;
    this.connected = false;
  }

  isConnected(): boolean {
    return this.connected;
  }

  async list(): Promise<CloudFile[]> {
    // Local adapter doesn't maintain a directory listing.
    // Return the last known file if we have one.
    if (this.lastFile) {
      return [{
        id: 'local',
        name: this.lastFile.name,
        size: this.lastFile.size,
        lastModified: this.lastFile.lastModified,
      }];
    }
    return [];
  }

  async upload(data: ArrayBuffer, filename: string): Promise<string> {
    this.requireConnected();

    // Try File System Access API first (persistent handle)
    if (hasFileSystemAccess()) {
      try {
        const handle = await (window as any).showSaveFilePicker({
          suggestedName: filename,
          types: [{
            description: 'svrnty Vault',
            accept: { 'application/octet-stream': ['.svrnty'] },
          }],
        });

        const writable = await handle.createWritable();
        await writable.write(data);
        await writable.close();

        this.fileHandle = handle;
        this.lastFile = {
          name: filename,
          size: data.byteLength,
          lastModified: new Date().toISOString(),
          data,
        };

        return 'local';
      } catch (err: any) {
        // User cancelled the picker — fall through to download
        if (err.name === 'AbortError') {
          throw new Error('Export cancelled');
        }
        // API not available or blocked — fall through
      }
    }

    // Fallback: trigger browser download
    downloadBlob(data, filename);

    this.lastFile = {
      name: filename,
      size: data.byteLength,
      lastModified: new Date().toISOString(),
      data,
    };

    return 'local';
  }

  async download(_fileId: string): Promise<ArrayBuffer> {
    this.requireConnected();

    // Try File System Access API (re-read from the saved handle)
    if (this.fileHandle) {
      try {
        const file = await this.fileHandle.getFile();
        const data = await file.arrayBuffer();
        this.lastFile = {
          name: file.name,
          size: file.size,
          lastModified: new Date(file.lastModified).toISOString(),
          data,
        };
        return data;
      } catch {
        // Handle invalidated — fall through to file picker
      }
    }

    // File picker approach
    if (hasFileSystemAccess()) {
      try {
        const [handle] = await (window as any).showOpenFilePicker({
          types: [{
            description: 'svrnty Vault',
            accept: { 'application/octet-stream': ['.svrnty'] },
          }],
          multiple: false,
        });

        const file = await handle.getFile();
        const data = await file.arrayBuffer();
        this.fileHandle = handle;
        this.lastFile = {
          name: file.name,
          size: file.size,
          lastModified: new Date(file.lastModified).toISOString(),
          data,
        };
        return data;
      } catch (err: any) {
        if (err.name === 'AbortError') throw new Error('Import cancelled');
      }
    }

    // Fallback: file input element
    return new Promise((resolve, reject) => {
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = '.svrnty';
      input.onchange = async () => {
        const file = input.files?.[0];
        if (!file) { reject(new Error('No file selected')); return; }
        try {
          const data = await file.arrayBuffer();
          this.lastFile = {
            name: file.name,
            size: file.size,
            lastModified: new Date(file.lastModified).toISOString(),
            data,
          };
          resolve(data);
        } catch (err) {
          reject(err);
        }
      };
      input.click();
    });
  }

  async delete(_fileId: string): Promise<void> {
    // Can't delete files from the local filesystem via browser.
    // Clear our reference instead.
    this.fileHandle = null;
    this.lastFile = null;
  }

  // --- Private ---

  private requireConnected() {
    if (!this.connected) {
      throw new Error('Local file adapter not initialized');
    }
  }
}

// --- Helpers ---

function hasFileSystemAccess(): boolean {
  return typeof window !== 'undefined' && 'showSaveFilePicker' in window;
}

function downloadBlob(data: ArrayBuffer, filename: string) {
  const blob = new Blob([data], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
