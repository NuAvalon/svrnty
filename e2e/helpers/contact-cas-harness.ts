// e2e/helpers/contact-cas-harness.ts
// Bundled by esbuild and injected into the page by e2e/contact-cas.spec.ts. It runs the app's REAL contact store (IndexedDB, the encrypted
// contact rows and the book manifest) from inside the page, so concurrent writes race on a real database. Nothing here is a stand-in for the
// thing under test: every write goes through updateContact / addContact exactly as the app calls them.
import { initSessionKey, addContact, updateContact, getContact, getAllContacts, getContactBookIntegrity } from '@/lib/identity/client-store';

type Outcome = { ok: true } | { ok: false; name: string; message: string };
const settle = async (p: Promise<unknown>): Promise<Outcome> => {
  try { await p; return { ok: true }; } catch (e) { return { ok: false, name: (e as Error).name, message: (e as Error).message }; }
};

declare global {
  interface Window {
    __cas: {
      init(passphrase: string): Promise<void>;
      add(owner: string, name: string): Promise<string>;
      tag(id: string, tag: string): Promise<Outcome>;
      bump(id: string): Promise<Outcome>;
      tags(id: string): Promise<string[]>;
      version(id: string): Promise<number>;
      count(owner: string): Promise<number>;
      integrity(owner: string): Promise<'ok' | 'corrupt'>;
      /** Run several operations at the same time, in this page. */
      together(ops: Array<{ kind: 'tag' | 'bump' | 'add'; id?: string; tag?: string; owner?: string; name?: string }>): Promise<Outcome[]>;
    };
  }
}

const tag = (id: string, t: string) =>
  updateContact(id, (f) => ({ metadata: { ...f.metadata, tags: [...((f.metadata?.tags as string[] | undefined) ?? []), t] } }));
const bump = (id: string) => updateContact(id, (f) => ({ version: (f.version ?? 0) + 1 }));
const add = (owner: string, name: string) =>
  addContact(owner, { name, email: '', public_key: '', fingerprint: '', trust_level: 'unverified' } as never);

window.__cas = {
  init: (passphrase) => initSessionKey(passphrase) as unknown as Promise<void>,
  add: async (owner, name) => (await add(owner, name)).id,
  tag: (id, t) => settle(tag(id, t)),
  bump: (id) => settle(bump(id)),
  tags: async (id) => ((await getContact(id))?.metadata?.tags as string[] | undefined) ?? [],
  version: async (id) => (await getContact(id))?.version ?? 0,
  count: async (owner) => (await getAllContacts(owner)).length,
  integrity: (owner) => getContactBookIntegrity(owner),
  together: (ops) => Promise.all(ops.map((o) => settle(o.kind === 'tag' ? tag(o.id!, o.tag!) : o.kind === 'bump' ? bump(o.id!) : add(o.owner!, o.name!)))),
};
