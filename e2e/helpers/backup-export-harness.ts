// e2e/helpers/backup-export-harness.ts
// Bundled by esbuild and injected into the page by e2e/restore-error-honesty.spec.ts. It reads the app's own full backup object (exportAll) from the REAL
// IndexedDB after the session key is re-derived from the unlock passphrase, so the spec can build a file in the OLD password format around real data.
import { initSessionKey, exportAll } from '@/lib/identity/client-store';

declare global {
  interface Window { __bk: { all(fingerprint: string, unlockPassphrase: string): Promise<unknown> } }
}

window.__bk = {
  async all(fingerprint, unlockPassphrase) {
    await initSessionKey(unlockPassphrase);
    return exportAll(fingerprint, true);
  },
};
