// src/lib/trust/beacon-confirm-glue.ts: the glue between the confirm session and the store. Ports in, nothing imported from the store: the real ports are bound in beacon-confirm-wiring.ts.
// It keeps ONE session at a time. The keys are read from the store when a session starts, and AGAIN at every entry, inside the contact lock, so a key that changed in between is seen by
// the rule that confirms (a match with a changed key refuses). A confirm writes the generation of the key that was compared, inside that same lock, and nowhere else.
// The session ends on a lock of the app or a switch of identity (one hook, registered once at creation), and so does an attempt to open one that is still reading the keys. The hook cannot be removed: create ONE glue per owner.
import { startConfirmSession, joinConfirmFromScan, joinConfirmFromTyped, type ConfirmSession, type EnterResult, type JoinRefusal, type OwnCode, type SessionStatus, type StartRefusal } from './beacon-confirm-session';
import type { SessionKeys } from './beacon-confirm-code';

/** A beacon public key as the store holds it (base64 of 32 bytes) and its generation. */
export interface PublicKeyRead { publicKey: string; generation: number }

export interface GluePorts {
  /** This device's own beacon key, read strictly (never created here); undefined when it cannot be read. */
  readOwn(): Promise<PublicKeyRead | undefined>;
  /** The key this device holds for the contact; undefined when there is none or it cannot be read. */
  readHeld(contactId: string): Promise<PublicKeyRead | undefined>;
  /** Runs `run` under the exclusive lock of the contact; rejects without running it when the lock cannot be taken. */
  withContactLock<T>(contactId: string, run: () => Promise<T>): Promise<T>;
  /** Records the pair as confirmed at this generation. Called only inside withContactLock. */
  writeConfirmed(contactId: string, generation: number): Promise<void>;
  /** Registers a function to run when the app locks or the identity switches. Called once. */
  onLock(fn: () => void): void;
}

export interface GlueOptions { now?: () => number; mono?: () => number; random?: (bytes: number) => Uint8Array }

export type GlueStart = { ok: true; shown: { qr: string; text: string } } | { ok: false; reason: StartRefusal | 'keys-unreadable' | 'interrupted' };
export type GlueJoin = { ok: true } | { ok: false; reason: JoinRefusal | 'keys-unreadable' | 'interrupted' };
export type GlueEnter =
  | Exclude<EnterResult, { kind: 'confirm' }>
  | { kind: 'confirmed'; generation: number }
  | { kind: 'not-saved' }
  | { kind: 'keys-unreadable' }
  | { kind: 'busy' }
  | { kind: 'no-session' };

export interface ConfirmGlue {
  start(contactId: string): Promise<GlueStart>;
  joinFromScan(contactId: string, payload: unknown): Promise<GlueJoin>;
  joinFromTyped(contactId: string, text: unknown): Promise<GlueJoin>;
  ownCode(contactId: string): OwnCode | { ok: false; reason: 'no-session' };
  enter(contactId: string, typed: string): Promise<GlueEnter>;
  drop(): void;
  status(): SessionStatus | 'none';
}

/** Strict base64 of exactly 32 bytes: 44 characters, canonical (re-encoding gives the same string), nothing else. */
function decode32(s: unknown): Uint8Array | null {
  if (typeof s !== 'string' || s.length !== 44 || !/^[A-Za-z0-9+/]{43}=$/.test(s)) return null;
  let bin: string;
  try { bin = atob(s); } catch { return null; }
  if (bin.length !== 32) return null;
  const u = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return btoa(String.fromCharCode(...u)) === s ? u : null;
}

function toKeyView(k: PublicKeyRead | undefined): { pub: Uint8Array; gen: number } | null {
  if (!k || typeof k !== 'object') return null;
  const pub = decode32(k.publicKey);
  return pub && Number.isSafeInteger(k.generation) ? { pub, gen: k.generation } : null;
}

export function createConfirmGlue(ports: GluePorts, opts?: GlueOptions): ConfirmGlue {
  let cur: { contact: string; session: ConfirmSession } | null = null;
  /** Bumped by EVERY drop (a lock, a switch of account, an explicit drop, another start): an attempt that was waiting on the store and finds it changed was interrupted. */
  let epoch = 0;

  const drop = (): void => {
    epoch += 1;
    const c = cur;
    cur = null;
    c?.session.drop();
  };
  ports.onLock(drop);

  /** Both keys, read now. undefined on ANY doubt: a failing read, a missing key, a key that is not strict base64 of 32 bytes. */
  async function readKeys(contactId: string): Promise<SessionKeys | undefined> {
    try {
      const own = toKeyView(await ports.readOwn());
      const held = toKeyView(await ports.readHeld(contactId));
      return own && held ? { own, held } : undefined;
    } catch {
      return undefined;
    }
  }

  async function begin<R extends { ok: boolean }>(contactId: string, open: (keys: SessionKeys) => { result: R; session?: ConfirmSession }): Promise<R | { ok: false; reason: 'keys-unreadable' | 'interrupted' }> {
    drop();
    const startedAt = epoch;   // taken AFTER this attempt's own drop: anything that bumps it from here on interrupts it
    const keys = await readKeys(contactId);
    if (epoch !== startedAt) return { ok: false, reason: 'interrupted' };   // no session is opened after a lock, a switch or a later start
    if (!keys) return { ok: false, reason: 'keys-unreadable' };
    const { result, session } = open(keys);
    if (result.ok && session) cur = { contact: contactId, session };
    return result;
  }

  return {
    async start(contactId) {
      return begin<GlueStart>(contactId, (keys) => {
        const r = startConfirmSession(contactId, keys, opts);
        return r.ok ? { result: { ok: true, shown: r.shown }, session: r.session } : { result: r };
      });
    },
    async joinFromScan(contactId, payload) {
      return begin<GlueJoin>(contactId, (keys) => {
        const r = joinConfirmFromScan(contactId, keys, payload, opts);
        return r.ok ? { result: { ok: true }, session: r.session } : { result: r };
      });
    },
    async joinFromTyped(contactId, text) {
      return begin<GlueJoin>(contactId, (keys) => {
        const r = joinConfirmFromTyped(contactId, keys, text, opts);
        return r.ok ? { result: { ok: true }, session: r.session } : { result: r };
      });
    },
    ownCode(contactId) {
      return cur ? cur.session.ownCode(contactId) : { ok: false, reason: 'no-session' };
    },
    async enter(contactId, typed) {
      const mine = cur;
      if (!mine) return { kind: 'no-session' };
      if (contactId !== mine.contact) return { kind: 'wrong-contact' };
      try {
        return await ports.withContactLock<GlueEnter>(contactId, async () => {
          const keys = await readKeys(contactId);
          if (!keys) { mine.session.drop(); return { kind: 'keys-unreadable' }; }
          const r = mine.session.enter(contactId, typed, keys);
          if (r.kind !== 'confirm') return r;
          try { await ports.writeConfirmed(contactId, r.generation); } catch { return { kind: 'not-saved' }; }
          return { kind: 'confirmed', generation: r.generation };
        });
      } catch {
        return { kind: 'busy' };
      }
    },
    drop,
    status() {
      return cur ? cur.session.status() : 'none';
    },
  };
}
