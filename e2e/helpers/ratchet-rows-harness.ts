// e2e/helpers/ratchet-rows-harness.ts
// Bundled by esbuild and injected into the page by e2e/ratchet-rows-reset.spec.ts. It runs the app's REAL store modules (IndexedDB, the
// encrypted settings rows) against the SAME per-identity notes DB the UI reads, to seed dead-letter records and to observe the reset flag.
// (init mirrors the app's own unlock path.) It never drives the thing under test: the reset itself is the user's click in the UI.
import { initNotesStore } from '@/lib/messaging/store';
import { initSessionKey, loadKey } from '@/lib/identity/client-store';
import { listDeadLetters, putDeadLetter } from '@/lib/messaging/dead-letter-store';
import { clearResetFlagIfSet, hasResetFlag, listResetFlags } from '@/lib/messaging/reset-flag-store';
import type { DeadLetterRow } from '@/lib/sync/dead-letter';

declare global {
  interface Window {
    __rr: {
      init(passphrase: string, ownerFp: string): Promise<void>;
      put(rows: DeadLetterRow[]): Promise<void>;
      list(): Promise<DeadLetterRow[]>;
      hasFlag(peerFp: string): Promise<boolean>;
      flags(): Promise<string[]>;
      clearFlag(peerFp: string): Promise<boolean>;
    };
  }
}

window.__rr = {
  // Exactly how the app opens the notes DB: unlock the vault session with the typed passphrase, read the key record's own passphrase
  // (it is NOT the typed one), and derive the notes key from that. A wrong passphrase here gives a key that cannot read the UI's rows.
  init: async (passphrase, ownerFp) => {
    await initSessionKey(passphrase);
    const key = await loadKey(ownerFp);
    if (!key) throw new Error('harness: no key record for the owner');
    await initNotesStore(key.passphrase, ownerFp);
  },
  put: async (rows) => { for (const r of rows) await putDeadLetter(r); },
  list: () => listDeadLetters(),
  hasFlag: (peerFp) => hasResetFlag(peerFp),
  flags: () => listResetFlags(),
  clearFlag: (peerFp) => clearResetFlagIfSet(peerFp),
};
