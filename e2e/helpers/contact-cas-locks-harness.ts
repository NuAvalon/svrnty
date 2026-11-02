// e2e/helpers/contact-cas-locks-harness.ts
// Bundled by esbuild and injected into TWO pages of one browser context by e2e/contact-cas.spec.ts: the real contact store, plus the real
// per-contact Web Lock (navigator.locks), so "a poll in another tab defers while a safety write holds the contact" runs on real browser
// locks and a real shared IndexedDB.
import { initSessionKey, updateContact, getContact, addContact } from '@/lib/identity/client-store';
import { withSafetyWrite, pollWriteUnlessSafety } from '@/lib/contacts/safety-write';

type Outcome = { ok: true } | { ok: false; name: string; message: string };
const settle = async (p: Promise<unknown>): Promise<Outcome> => {
  try { await p; return { ok: true }; } catch (e) { return { ok: false, name: (e as Error).name, message: (e as Error).message }; }
};
const tagPatch = (t: string) => (f: { metadata?: Record<string, unknown> }) => ({ metadata: { ...f.metadata, tags: [...((f.metadata?.tags as string[] | undefined) ?? []), t] } });

declare global {
  interface Window {
    __casl: {
      init(passphrase: string): Promise<void>;
      add(owner: string, name: string): Promise<string>;
      /** Take the contact's safety lock and hold it for `ms`; resolves once the lock is GRANTED. */
      hold(id: string, ms: number): Promise<void>;
      /** What the poll does: a write that yields to a safety write. */
      poll(id: string, tag: string): Promise<{ deferred: boolean } | { error: string }>;
      /** A safety write: the contact's lock, then the write. */
      safety(id: string, tag: string): Promise<Outcome>;
      tags(id: string): Promise<string[]>;
      lockSupported(): boolean;
    };
  }
}

window.__casl = {
  init: (passphrase) => initSessionKey(passphrase) as unknown as Promise<void>,
  add: async (owner, name) => (await addContact(owner, { name, email: '', public_key: '', fingerprint: '', trust_level: 'unverified' } as never)).id,
  hold: (id, ms) => new Promise<void>((granted) => { void withSafetyWrite(id, async () => { granted(); await new Promise((r) => setTimeout(r, ms)); }); }),
  poll: async (id, t) => {
    try { const r = await pollWriteUnlessSafety(id, () => updateContact(id, tagPatch(t))); return { deferred: r.deferred }; }
    catch (e) { return { error: (e as Error).name + ': ' + (e as Error).message }; }
  },
  safety: (id, t) => settle(withSafetyWrite(id, () => updateContact(id, tagPatch(t)))),
  tags: async (id) => ((await getContact(id))?.metadata?.tags as string[] | undefined) ?? [],
  lockSupported: () => typeof navigator !== 'undefined' && !!navigator.locks,
};
