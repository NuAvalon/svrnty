// Test kit: an in-memory contact book (contacts + settings maps, "encryption" = a fresh iv and the JSON body, the manifest = one string over
// (id, version)) behind the CasIO seam, whose commit uses the real compare rule. Shared by the compare-and-swap and safety-write tests.
import { sameStoredRow, type CasIO, type Expect, type PutOp, type StoredRow } from './contact-cas';

export interface Rec { id: string; owner_fingerprint: string; version?: number; n: number; tags: string[]; trust?: string }

/** A tiny store: contacts and settings maps; "encryption" = a fresh iv and the JSON body; the manifest = one string over (id, version). */
export class World {
  contacts = new Map<string, Record<string, unknown>>();
  settings = new Map<string, Record<string, unknown>>();
  ivs = 0;
  commits = 0;
  finalizeCalls: Array<{ existingN: number; nextN: number }> = [];
  finalizeError: Error | null = null;

  seal(r: Rec): Record<string, unknown> {
    const { id, owner_fingerprint, ...body } = r;
    return { id, owner_fingerprint, enc_version: 1, iv: `iv${++this.ivs}`, ciphertext: JSON.stringify(body) };
  }
  open(raw: Record<string, unknown>): Rec {
    return { id: raw.id as string, owner_fingerprint: raw.owner_fingerprint as string, ...JSON.parse(raw.ciphertext as string) };
  }
  manifestOf(recs: Rec[]): Record<string, unknown> {
    const mac = recs.map((c) => `${c.id}:${c.version ?? 0}`).sort().join('|') + `#${recs.length}`;
    return { key: 'contact_manifest:o', value: mac };
  }
  all(): Rec[] { return [...this.contacts.values()].map((r) => this.open(r)); }
  put(r: Rec) { this.contacts.set(r.id, this.seal(r)); this.settings.set('contact_manifest:o', this.manifestOf(this.all())); }
  get(id: string): Rec { return this.open(this.contacts.get(id)!); }
  manifestConsistent(): boolean {
    return sameStoredRow(this.settings.get('contact_manifest:o') ?? null, this.manifestOf(this.all()));
  }

  /** `hooks` belong to THIS writer only: each runs once, between a commit's reads and the commit itself, to force an interleaving. */
  io(hooks: Array<() => Promise<void>> = []): CasIO<Rec> {
    return {
      readRaw: async (id) => this.contacts.get(id) ?? null,
      manifestKey: () => 'contact_manifest:o',
      readManifest: async () => this.settings.get('contact_manifest:o') ?? null,
      decrypt: async (raw) => this.open(raw),
      finalize: async (existing, next) => {
        this.finalizeCalls.push({ existingN: existing.n, nextN: next.n });
        if (this.finalizeError) throw this.finalizeError;
        return next;
      },
      encrypt: async (next) => this.seal(next),
      manifestOp: async (_owner, next) => {
        const recs = this.all().map((c) => (c.id === next.id ? next : c));
        return { store: 'settings', value: this.manifestOf(recs) };
      },
      commit: async (expects: Expect[], ops: PutOp[]) => {
        const hook = hooks.shift();
        if (hook) await hook();
        const cur = (e: Expect): StoredRow => (e.store === 'contacts' ? this.contacts.get(e.key) : this.settings.get(e.key)) ?? null;
        if (!expects.every((e) => sameStoredRow(cur(e), e.expected))) return false;
        for (const op of ops) {
          if ('delete' in op) continue;
          const v = op.value as Record<string, unknown>;
          if (op.store === 'contacts') this.contacts.set(v.id as string, v);
          else this.settings.set(v.key as string, v);
        }
        this.commits++;
        return true;
      },
    };
  }
}

export const rec = (id: string, o: Partial<Rec> = {}): Rec => ({ id, owner_fingerprint: 'o', n: 0, tags: [], version: 0, ...o });
export const addTag = (tag: string) => (e: Rec): Rec => ({ ...e, tags: [...e.tags, tag] });

export function world(...ids: string[]): World {
  const w = new World();
  for (const id of ids) w.put(rec(id));
  return w;
}

