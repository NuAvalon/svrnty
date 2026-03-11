// src/lib/sync/cloud/icloud.ts
// iCloud adapter — stores encrypted vault via CloudKit JS / iCloud Drive.
//
// iCloud is the trickiest of the four because Apple doesn't expose
// a straightforward REST API for iCloud Drive. Two approaches:
//
// 1. CloudKit JS — Apple's JavaScript SDK for CloudKit containers.
//    Requires an Apple Developer account and a CloudKit container.
//    The vault is stored as a CKRecord with a CKAsset.
//
// 2. Web-based file picker — not a real API, but could use a
//    "download file / upload file" flow where the user manually
//    manages the file in iCloud Drive.
//
// This implementation uses approach 1 (CloudKit JS).
// Setup: Create a CloudKit container in Apple Developer portal,
//        enable CloudKit JS, get the container ID and API token.

import type { CloudAdapter, CloudConfig, CloudFile } from './adapter';

const CLOUDKIT_CDN = 'https://cdn.apple-cloudkit.com/ck/2/cloudkit.min.js';

export class ICloudAdapter implements CloudAdapter {
  readonly name = 'iCloud';
  readonly provider = 'icloud' as const;

  private config: CloudConfig | null = null;
  private connected = false;
  private container: any = null;
  private database: any = null;

  async connect(config: CloudConfig): Promise<void> {
    if (!config.containerId) {
      throw new Error('iCloud requires a CloudKit container ID. Configure in Apple Developer portal.');
    }

    // Ensure CloudKit JS is loaded (browser only)
    if (typeof window === 'undefined') {
      throw new Error('iCloud adapter requires a browser environment');
    }

    await this.loadCloudKitJS();

    try {
      // Configure CloudKit
      const cloudKit = (window as any).CloudKit;
      if (!cloudKit) throw new Error('CloudKit JS not available');

      cloudKit.configure({
        containers: [{
          containerIdentifier: config.containerId,
          apiTokenAuth: {
            apiToken: config.accessToken,
            persist: true,
          },
          environment: 'production',
        }],
      });

      this.container = cloudKit.getDefaultContainer();
      this.database = this.container.privateCloudDatabase;

      // Check auth status
      const userIdentity = await this.container.setUpAuth();
      if (!userIdentity) {
        // User needs to sign in — CloudKit will show Apple's sign-in UI
        throw new Error('iCloud sign-in required. Please sign in with your Apple ID.');
      }

      this.config = config;
      this.connected = true;
    } catch (err: any) {
      throw new Error(`iCloud connection failed: ${err.message}`);
    }
  }

  async disconnect(): Promise<void> {
    this.container = null;
    this.database = null;
    this.config = null;
    this.connected = false;
  }

  isConnected(): boolean {
    return this.connected;
  }

  async list(): Promise<CloudFile[]> {
    this.requireConnected();

    try {
      const query = {
        recordType: 'SvrntyVault',
        filterBy: [],
        sortBy: [{ fieldName: 'modifiedAt', ascending: false }],
      };

      const response = await this.database.performQuery(query);

      if (!response.records) return [];

      return response.records.map((record: any) => ({
        id: record.recordName,
        name: record.fields.filename?.value || 'vault.svrnty',
        size: record.fields.size?.value || 0,
        lastModified: record.modified?.timestamp
          ? new Date(record.modified.timestamp).toISOString()
          : new Date().toISOString(),
        mimeType: 'application/octet-stream',
      }));
    } catch (err: any) {
      throw new Error(`Failed to list iCloud vaults: ${err.message}`);
    }
  }

  async upload(data: ArrayBuffer, filename: string): Promise<string> {
    this.requireConnected();

    try {
      // Upload the asset (binary data)
      const uploadResponse = await this.database.uploadAsset({
        data: new Uint8Array(data),
      });

      const assetToken = uploadResponse.singleFile.fileChecksum;

      // Check if record exists
      const existing = await this.list();
      const match = existing.find(f => f.name === filename);

      const record: any = {
        recordType: 'SvrntyVault',
        fields: {
          filename: { value: filename },
          vault: { value: { fileChecksum: assetToken } },
          size: { value: data.byteLength },
        },
      };

      if (match) {
        record.recordName = match.id;
        record.recordChangeTag = match.id; // for conflict detection
      }

      const saveResponse = await this.database.saveRecords([record]);

      if (!saveResponse.records || saveResponse.records.length === 0) {
        throw new Error('Save returned no records');
      }

      return saveResponse.records[0].recordName;
    } catch (err: any) {
      throw new Error(`Failed to upload to iCloud: ${err.message}`);
    }
  }

  async download(fileId: string): Promise<ArrayBuffer> {
    this.requireConnected();

    try {
      const response = await this.database.fetchRecords([fileId]);

      if (!response.records || response.records.length === 0) {
        throw new Error('Vault not found in iCloud');
      }

      const record = response.records[0];
      const assetUrl = record.fields.vault?.value?.downloadURL;

      if (!assetUrl) {
        throw new Error('No vault data in iCloud record');
      }

      const res = await fetch(assetUrl);
      if (!res.ok) throw new Error(`Failed to download vault: ${res.status}`);

      return res.arrayBuffer();
    } catch (err: any) {
      throw new Error(`Failed to download from iCloud: ${err.message}`);
    }
  }

  async delete(fileId: string): Promise<void> {
    this.requireConnected();

    try {
      await this.database.deleteRecords([{ recordName: fileId, recordType: 'SvrntyVault' }]);
    } catch (err: any) {
      throw new Error(`Failed to delete from iCloud: ${err.message}`);
    }
  }

  // --- Private ---

  private requireConnected() {
    if (!this.connected || !this.database) {
      throw new Error('Not connected to iCloud');
    }
  }

  private async loadCloudKitJS(): Promise<void> {
    if ((window as any).CloudKit) return;

    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = CLOUDKIT_CDN;
      script.onload = () => resolve();
      script.onerror = () => reject(new Error('Failed to load CloudKit JS'));
      document.head.appendChild(script);
    });
  }
}
