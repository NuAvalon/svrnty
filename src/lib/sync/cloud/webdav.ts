// src/lib/sync/cloud/webdav.ts
// WebDAV adapter — stores encrypted vault on any WebDAV server.
// Works with: Nextcloud, Synology, ownCloud, any WebDAV-compatible server.
// This is the self-hosted option. No OAuth, no vendor, just a URL and credentials.
//
// Uses standard WebDAV methods: PROPFIND, GET, PUT, DELETE, MKCOL.
// Basic auth over HTTPS. The vault is encrypted before upload —
// the server admin sees a binary blob, nothing more.

import type { CloudAdapter, CloudConfig, CloudFile } from './adapter';

const VAULT_DIR = '/svrnty/';

export class WebDAVAdapter implements CloudAdapter {
  readonly name = 'WebDAV (Self-Hosted)';
  readonly provider = 'webdav' as const;

  private config: CloudConfig | null = null;
  private connected = false;
  private baseUrl = '';

  async connect(config: CloudConfig): Promise<void> {
    if (!config.webdavUrl) {
      throw new Error('WebDAV requires a server URL');
    }
    if (!config.username || !config.password) {
      throw new Error('WebDAV requires username and password');
    }

    // Normalize URL
    this.baseUrl = config.webdavUrl.replace(/\/+$/, '');

    // Test connection with PROPFIND on root
    const res = await this.request('PROPFIND', '/', null, {
      Depth: '0',
    });

    if (!res.ok && res.status !== 207) {
      throw new Error(`WebDAV connection failed: ${res.status} ${res.statusText}`);
    }

    // Ensure vault directory exists
    await this.ensureDirectory();

    this.config = config;
    this.connected = true;
  }

  async disconnect(): Promise<void> {
    this.config = null;
    this.connected = false;
    this.baseUrl = '';
  }

  isConnected(): boolean {
    return this.connected;
  }

  async list(): Promise<CloudFile[]> {
    this.requireConnected();

    const res = await this.request('PROPFIND', VAULT_DIR, null, {
      Depth: '1',
    });

    if (!res.ok && res.status !== 207) {
      if (res.status === 404) return [];
      throw new Error(`Failed to list files: ${res.status}`);
    }

    const xml = await res.text();
    return this.parsePropfindResponse(xml);
  }

  async upload(data: ArrayBuffer, filename: string): Promise<string> {
    this.requireConnected();

    const path = `${VAULT_DIR}${filename}`;

    const res = await this.request('PUT', path, data, {
      'Content-Type': 'application/octet-stream',
    });

    if (!res.ok) {
      throw new Error(`Failed to upload file: ${res.status}`);
    }

    return path;
  }

  async download(fileId: string): Promise<ArrayBuffer> {
    this.requireConnected();

    const res = await this.request('GET', fileId);

    if (!res.ok) throw new Error(`Failed to download file: ${res.status}`);
    return res.arrayBuffer();
  }

  async delete(fileId: string): Promise<void> {
    this.requireConnected();

    const res = await this.request('DELETE', fileId);

    if (!res.ok && res.status !== 204) {
      throw new Error(`Failed to delete file: ${res.status}`);
    }
  }

  // --- Private ---

  private requireConnected() {
    if (!this.connected || !this.config) {
      throw new Error('Not connected to WebDAV server');
    }
  }

  private authHeader(): string {
    const credentials = `${this.config!.username}:${this.config!.password}`;
    // btoa is available in both browser and Node 16+
    const encoded = typeof btoa === 'function'
      ? btoa(credentials)
      : Buffer.from(credentials).toString('base64');
    return `Basic ${encoded}`;
  }

  private async request(
    method: string,
    path: string,
    body?: ArrayBuffer | null,
    extraHeaders?: Record<string, string>,
  ): Promise<Response> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      Authorization: this.authHeader(),
      ...extraHeaders,
    };

    const init: RequestInit = { method, headers };
    if (body) init.body = body;

    return fetch(url, init);
  }

  private async ensureDirectory(): Promise<void> {
    // Try MKCOL — if directory exists, server returns 405 or 301 (fine)
    const res = await this.request('MKCOL', VAULT_DIR);
    // 201 = created, 405 = already exists, both are fine
    if (!res.ok && res.status !== 405 && res.status !== 301) {
      // Some servers return 409 if parent doesn't exist
      if (res.status === 409) {
        throw new Error('WebDAV: parent directory does not exist. Check your URL.');
      }
    }
  }

  /**
   * Parse a PROPFIND response to extract file metadata.
   * WebDAV responses are XML (multistatus).
   */
  private parsePropfindResponse(xml: string): CloudFile[] {
    const files: CloudFile[] = [];

    // Simple regex-based XML parsing for WebDAV.
    // Avoids DOMParser dependency for Node.js compatibility.
    const responseRegex = /<d:response>([\s\S]*?)<\/d:response>/gi;
    let match;

    while ((match = responseRegex.exec(xml)) !== null) {
      const block = match[1];

      // Extract href
      const hrefMatch = block.match(/<d:href>(.*?)<\/d:href>/i);
      const href = hrefMatch ? decodeURIComponent(hrefMatch[1]) : '';

      // Skip the directory itself
      if (href.endsWith('/')) continue;

      // Only include .svrnty files
      if (!href.endsWith('.svrnty')) continue;

      // Extract properties
      const sizeMatch = block.match(/<d:getcontentlength>(.*?)<\/d:getcontentlength>/i);
      const modifiedMatch = block.match(/<d:getlastmodified>(.*?)<\/d:getlastmodified>/i);
      const typeMatch = block.match(/<d:getcontenttype>(.*?)<\/d:getcontenttype>/i);

      const name = href.split('/').pop() || href;

      files.push({
        id: href, // WebDAV uses the path as the ID
        name,
        size: sizeMatch ? parseInt(sizeMatch[1]) : 0,
        lastModified: modifiedMatch ? new Date(modifiedMatch[1]).toISOString() : '',
        mimeType: typeMatch ? typeMatch[1] : 'application/octet-stream',
      });
    }

    return files;
  }
}
