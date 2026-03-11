// src/lib/sync/backup.ts
// Encrypted backup/sync — export trust graph as an encrypted blob.
// Can be saved locally or synced to Google Drive, iCloud, Dropbox.
// Server stores nothing. The blob is encrypted before it leaves.

/**
 * Encrypt a trust graph backup using AES-256-GCM derived from the user's passphrase.
 * Returns a self-contained encrypted blob (salt + iv + ciphertext).
 */
export async function encryptBackup(
  data: object,
  passphrase: string
): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(data));

  // Derive key from passphrase via PBKDF2
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  // Encrypt
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintext
  );

  // Pack: version(1) + salt(16) + iv(12) + ciphertext
  const result = new Uint8Array(1 + 16 + 12 + ciphertext.byteLength);
  result[0] = 1; // version byte
  result.set(salt, 1);
  result.set(iv, 17);
  result.set(new Uint8Array(ciphertext), 29);

  return result.buffer;
}

/**
 * Decrypt a backup blob. Returns the parsed trust graph data.
 */
export async function decryptBackup(
  blob: ArrayBuffer,
  passphrase: string
): Promise<object> {
  const data = new Uint8Array(blob);
  const version = data[0];
  if (version !== 1) throw new Error(`Unknown backup version: ${version}`);

  const salt = data.slice(1, 17);
  const iv = data.slice(17, 29);
  const ciphertext = data.slice(29);

  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );

  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(plaintext));
}

/**
 * Download an encrypted backup as a file (browser).
 */
export function downloadBackup(blob: ArrayBuffer, filename?: string) {
  const name = filename || `svrnty-backup-${new Date().toISOString().slice(0, 10)}.svrnty`;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([blob], { type: 'application/octet-stream' }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

/**
 * Read a backup file from a File input (browser).
 */
export async function readBackupFile(file: File): Promise<ArrayBuffer> {
  return file.arrayBuffer();
}
