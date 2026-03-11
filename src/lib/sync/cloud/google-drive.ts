// src/lib/sync/cloud/google-drive.ts
// Google Drive adapter — stores encrypted vault as a file in Drive.
// Uses Google Drive REST API v3.
// Requires: OAuth2 client ID + secret, configured in Google Cloud Console.
// Scopes needed: https://www.googleapis.com/auth/drive.file (app-created files only)

import type { CloudAdapter, CloudConfig, CloudFile } from './adapter';

const DRIVE_API = 'https://www.googleapis.com/drive/v3';
const UPLOAD_API = 'https://www.googleapis.com/upload/drive/v3';
const OAUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const SCOPES = 'https://www.googleapis.com/auth/drive.file';

export class GoogleDriveAdapter implements CloudAdapter {
  readonly name = 'Google Drive';
  readonly provider = 'google-drive' as const;

  private config: CloudConfig | null = null;
  private connected = false;

  async connect(config: CloudConfig): Promise<void> {
    if (!config.accessToken) {
      throw new Error('Google Drive requires an access token. Complete OAuth flow first.');
    }

    // Verify token by listing files
    const res = await fetch(`${DRIVE_API}/files?pageSize=1`, {
      headers: { Authorization: `Bearer ${config.accessToken}` },
    });

    if (!res.ok) {
      if (res.status === 401 && config.refreshToken && config.clientId && config.clientSecret) {
        // Token expired — refresh it
        const refreshed = await this.refreshAccessToken(config);
        config.accessToken = refreshed.accessToken;
      } else {
        throw new Error(`Google Drive auth failed: ${res.status}`);
      }
    }

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
      scope: SCOPES,
      access_type: 'offline',
      prompt: 'consent',
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
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
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

    const query = "name contains '.svrnty' and trashed = false";
    const fields = 'files(id,name,size,modifiedTime,mimeType)';
    const params = new URLSearchParams({ q: query, fields });

    const res = await fetch(`${DRIVE_API}/files?${params}`, {
      headers: { Authorization: `Bearer ${this.config!.accessToken}` },
    });

    if (!res.ok) throw new Error(`Failed to list files: ${res.status}`);

    const data = await res.json();
    return (data.files || []).map((f: any) => ({
      id: f.id,
      name: f.name,
      size: parseInt(f.size || '0'),
      lastModified: f.modifiedTime,
      mimeType: f.mimeType,
    }));
  }

  async upload(data: ArrayBuffer, filename: string): Promise<string> {
    this.requireConnected();

    // Check if file already exists
    const existing = await this.list();
    const match = existing.find(f => f.name === filename);

    if (match) {
      // Update existing file
      const res = await fetch(`${UPLOAD_API}/files/${match.id}?uploadType=media`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${this.config!.accessToken}`,
          'Content-Type': 'application/octet-stream',
        },
        body: data,
      });
      if (!res.ok) throw new Error(`Failed to update file: ${res.status}`);
      return match.id;
    }

    // Create new file — multipart upload with metadata
    const metadata = JSON.stringify({
      name: filename,
      mimeType: 'application/octet-stream',
    });

    const boundary = 'svrnty_boundary_' + Date.now();
    const body = buildMultipartBody(boundary, metadata, data);

    const res = await fetch(`${UPLOAD_API}/files?uploadType=multipart`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.config!.accessToken}`,
        'Content-Type': `multipart/related; boundary=${boundary}`,
      },
      body,
    });

    if (!res.ok) throw new Error(`Failed to upload file: ${res.status}`);

    const result = await res.json();
    return result.id;
  }

  async download(fileId: string): Promise<ArrayBuffer> {
    this.requireConnected();

    const res = await fetch(`${DRIVE_API}/files/${fileId}?alt=media`, {
      headers: { Authorization: `Bearer ${this.config!.accessToken}` },
    });

    if (!res.ok) throw new Error(`Failed to download file: ${res.status}`);
    return res.arrayBuffer();
  }

  async delete(fileId: string): Promise<void> {
    this.requireConnected();

    const res = await fetch(`${DRIVE_API}/files/${fileId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${this.config!.accessToken}` },
    });

    if (!res.ok) throw new Error(`Failed to delete file: ${res.status}`);
  }

  // --- Private ---

  private requireConnected() {
    if (!this.connected || !this.config?.accessToken) {
      throw new Error('Not connected to Google Drive');
    }
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

// --- Helper: build multipart body ---

function buildMultipartBody(boundary: string, metadata: string, fileData: ArrayBuffer): ArrayBuffer {
  const encoder = new TextEncoder();

  const preamble = encoder.encode(
    `--${boundary}\r\n` +
    `Content-Type: application/json; charset=UTF-8\r\n\r\n` +
    `${metadata}\r\n` +
    `--${boundary}\r\n` +
    `Content-Type: application/octet-stream\r\n\r\n`
  );

  const epilogue = encoder.encode(`\r\n--${boundary}--`);

  const result = new Uint8Array(preamble.length + fileData.byteLength + epilogue.length);
  result.set(preamble, 0);
  result.set(new Uint8Array(fileData), preamble.length);
  result.set(epilogue, preamble.length + fileData.byteLength);

  return result.buffer;
}
