// src/lib/sync/cloud/dropbox.ts
// Dropbox adapter — stores encrypted vault as a file in Dropbox.
// Uses Dropbox HTTP API v2.
// Requires: OAuth2 app key + secret from Dropbox App Console.
// Scopes: files.content.write, files.content.read

import type { CloudAdapter, CloudConfig, CloudFile } from './adapter';

const API_URL = 'https://api.dropboxapi.com/2';
const CONTENT_URL = 'https://content.dropboxapi.com/2';
const OAUTH_URL = 'https://www.dropbox.com/oauth2/authorize';
const TOKEN_URL = 'https://api.dropboxapi.com/oauth2/token';
const VAULT_FOLDER = '/svrnty';

export class DropboxAdapter implements CloudAdapter {
  readonly name = 'Dropbox';
  readonly provider = 'dropbox' as const;

  private config: CloudConfig | null = null;
  private connected = false;

  async connect(config: CloudConfig): Promise<void> {
    if (!config.accessToken) {
      throw new Error('Dropbox requires an access token. Complete OAuth flow first.');
    }

    // Verify token
    const res = await fetch(`${API_URL}/users/get_current_account`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${config.accessToken}` },
    });

    if (!res.ok) {
      if (res.status === 401 && config.refreshToken && config.clientId && config.clientSecret) {
        const refreshed = await this.refreshAccessToken(config);
        config.accessToken = refreshed.accessToken;
      } else {
        throw new Error(`Dropbox auth failed: ${res.status}`);
      }
    }

    // Ensure vault folder exists
    await this.ensureFolder(config.accessToken!);

    this.config = config;
    this.connected = true;
  }

  async disconnect(): Promise<void> {
    this.config = null;
    this.connected = false;
  }

  isConnected(): boolean {
    return this.connected;
  }

  getAuthUrl(redirectUri: string): string | null {
    if (!this.config?.clientId) return null;

    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      token_access_type: 'offline',
    });

    return `${OAUTH_URL}?${params.toString()}`;
  }

  async handleAuthCallback(code: string, redirectUri: string): Promise<{
    accessToken: string;
    refreshToken?: string;
    expiresAt?: string;
  }> {
    if (!this.config?.clientId || !this.config?.clientSecret) {
      throw new Error('Client ID and secret required for OAuth');
    }

    const res = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        grant_type: 'authorization_code',
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        redirect_uri: redirectUri,
      }),
    });

    if (!res.ok) throw new Error(`Token exchange failed: ${res.status}`);

    const data = await res.json();
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresAt: data.expires_in
        ? new Date(Date.now() + data.expires_in * 1000).toISOString()
        : undefined,
    };
  }

  async list(): Promise<CloudFile[]> {
    this.requireConnected();

    const res = await fetch(`${API_URL}/files/list_folder`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.config!.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        path: VAULT_FOLDER,
        recursive: false,
      }),
    });

    if (!res.ok) {
      // If folder doesn't exist, return empty
      if (res.status === 409) return [];
      throw new Error(`Failed to list files: ${res.status}`);
    }

    const data = await res.json();
    return (data.entries || [])
      .filter((e: any) => e['.tag'] === 'file' && e.name.endsWith('.svrnty'))
      .map((f: any) => ({
        id: f.id,
        name: f.name,
        size: f.size,
        lastModified: f.server_modified,
        mimeType: 'application/octet-stream',
      }));
  }

  async upload(data: ArrayBuffer, filename: string): Promise<string> {
    this.requireConnected();

    const path = `${VAULT_FOLDER}/${filename}`;

    const res = await fetch(`${CONTENT_URL}/files/upload`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.config!.accessToken}`,
        'Content-Type': 'application/octet-stream',
        'Dropbox-API-Arg': JSON.stringify({
          path,
          mode: 'overwrite',
          autorename: false,
          mute: true,
        }),
      },
      body: data,
    });

    if (!res.ok) throw new Error(`Failed to upload file: ${res.status}`);

    const result = await res.json();
    return result.id;
  }

  async download(fileId: string): Promise<ArrayBuffer> {
    this.requireConnected();

    // Dropbox download needs the path, not the ID for the content endpoint.
    // First, get the file metadata to find the path.
    const meta = await this.getFileMetadata(fileId);

    const res = await fetch(`${CONTENT_URL}/files/download`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.config!.accessToken}`,
        'Dropbox-API-Arg': JSON.stringify({ path: meta.path }),
      },
    });

    if (!res.ok) throw new Error(`Failed to download file: ${res.status}`);
    return res.arrayBuffer();
  }

  async delete(fileId: string): Promise<void> {
    this.requireConnected();

    const meta = await this.getFileMetadata(fileId);

    const res = await fetch(`${API_URL}/files/delete_v2`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.config!.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ path: meta.path }),
    });

    if (!res.ok) throw new Error(`Failed to delete file: ${res.status}`);
  }

  // --- Private ---

  private requireConnected() {
    if (!this.connected || !this.config?.accessToken) {
      throw new Error('Not connected to Dropbox');
    }
  }

  private async ensureFolder(token: string): Promise<void> {
    try {
      await fetch(`${API_URL}/files/create_folder_v2`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ path: VAULT_FOLDER, autorename: false }),
      });
    } catch {
      // Folder might already exist — that's fine
    }
  }

  private async getFileMetadata(fileId: string): Promise<{ path: string }> {
    const res = await fetch(`${API_URL}/files/get_metadata`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.config!.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ path: fileId }),
    });

    if (!res.ok) throw new Error(`Failed to get file metadata: ${res.status}`);
    const data = await res.json();
    return { path: data.path_display || data.path_lower };
  }

  private async refreshAccessToken(config: CloudConfig): Promise<{ accessToken: string }> {
    const res = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        refresh_token: config.refreshToken!,
        client_id: config.clientId!,
        client_secret: config.clientSecret!,
        grant_type: 'refresh_token',
      }),
    });

    if (!res.ok) throw new Error(`Token refresh failed: ${res.status}`);
    const data = await res.json();
    return { accessToken: data.access_token };
  }
}
