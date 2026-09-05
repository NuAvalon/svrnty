// src/lib/sync/know-layer-sync.ts
// KNOW-layer PSI overlay — the frontend deps-impl + trigger that wire Apollo's syncMutualTrust
// (mutual-trust-sync.ts crypto #1-3) into the running app. This is #4 of the PSI KNOW-overlay.
//
// LANE / COLLAB-SEAM (Archie #126453): this module APPLIES Apollo's consent-gated PSI result — it
// NEVER computes visibility itself. `disclosed` arrives already consent-gated + fail-closed from
// Apollo's compute (completeTrustSync); we only persist it to disclosed_circle (know) / they_trust
// (trust), intersected with the local book.
//
// §C FIREWALL (Flint F1, NON-NEGOTIABLE): disclosed_circle / they_trust / open_visibility are
// owner-local and MUST NEVER ride the wire. This module's only write is client-store.updateContact
// (local IndexedDB) — it makes NO network call and imports NO publish/serialize path, so it cannot
// leak them. The publish boundary (trust-recipe.stripOwnerLocalForPublish) strips them regardless
// (verified: disclosed-circle-strip.test.ts).
//
// FAIL-CLOSED (Flint D1/D2/D4): getKnownPeers returns the open_visibility SUBSET of the book — the
// consent gate for BOTH roles + the data-minimization boundary. Empty ⇒ no participation ⇒ nothing
// disclosed. applyMutualResult fail-closes on malformed input.
//
// C1 (Flint, CRITICAL): syncMutualTrust defaults `layer` to 'trust' and the responder consent gate
// is guarded by `layer === 'know'` — so an implicit/missing layer SKIPS consent (fail-OPEN). The
// trigger here passes 'know' EXPLICITLY. See runKnowLayerSyncTick.
//
// SEAM-INJECTION (matches consume-mailbox / live-book-poll): the store is injectable (defaults to the
// real client-store) so the deps are unit-testable IndexedDB-free. PSISyncOptions is built by
// buildPsiSyncOptions (scalar-extracted Ed25519 seed, in-memory only) and passed into the trigger.

import { decryptKey, readPrivateKey } from 'openpgp';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  getAllContacts,
  loadKey,
  updateContact,
  type ContactRecord,
} from '@/lib/identity/client-store';
import { extractRawSign, signBind, signPsiAuthWrapped } from '@/lib/identity/raw-sign';
import { contactRecordToEdge } from '@/lib/trust/contact-edge';
import { isDecayed, type TrustEdge } from '@/lib/trust/types';
import {
  syncMutualTrust,
  type OrchestratorDeps,
  type PSISyncOptions,
} from '@/lib/trust/mutual-trust-sync';

// ── Store seam (injectable for tests; defaults to the real IndexedDB client-store) ───────────────

export interface KnowOverlayStore {
  getAllContacts: (ownerFingerprint: string) => Promise<ContactRecord[]>;
  updateContact: (id: string, updates: Partial<ContactRecord>) => Promise<void>;
}

const defaultStore: KnowOverlayStore = { getAllContacts, updateContact };

// ── Helpers ──────────────────────────────────────────────────────────────────────────────────────

/**
 * Project this owner's stored records onto TrustEdges via the ONE canonical projection
 * (contact-edge.ts — the single source of truth). Records without a REAL fingerprint (keyless / gray
 * vCard contacts) are dropped BEFORE projection: they cannot participate in PSI, and contactRecordToEdge
 * falls peer_fingerprint back to c.id, which would otherwise smuggle a UUID into the blinded set. So the
 * raw `fingerprint` field is the minimization guard.
 */
async function ownerEdges(store: KnowOverlayStore, ownerFingerprint: string): Promise<TrustEdge[]> {
  const contacts = await store.getAllContacts(ownerFingerprint);
  return contacts
    .filter((c) => typeof c.fingerprint === 'string' && c.fingerprint.length > 0)
    .map(contactRecordToEdge);
}

/** Staleness-scheduler input: last mutual sync for this edge (null = never synced ⇒ stale ⇒ candidate). */
function lastSyncOf(edge: TrustEdge): string | null {
  return edge.mutual?.last_sync ?? null;
}

// ── The 3 pieces — the OrchestratorDeps Apollo's syncMutualTrust consumes ────────────────────────

/**
 * Build the KNOW-overlay OrchestratorDeps bound to one owner's local book.
 *
 * - getTrustedPeers (TRUST layer, required by the interface + read by the staleness scheduler): the
 *   trusted, non-decayed set — matching TrustGraphManager.getTrustedEdges (`trusted && !isDecayed`).
 * - getKnownPeers   (KNOW layer, #4): the open_visibility SUBSET — the consent gate + minimization
 *   boundary. Empty ⇒ fail-closed.
 * - applyMutualResult: APPLY Apollo's consent-gated `disclosed` to disclosed_circle (know) /
 *   they_trust (trust), intersected with the book. Never computes; never serializes on the wire.
 */
export function buildKnowOverlayDeps(
  ownerFingerprint: string,
  store: KnowOverlayStore = defaultStore,
): OrchestratorDeps {
  return {
    getTrustedPeers: async () => {
      const edges = await ownerEdges(store, ownerFingerprint);
      return edges
        .filter((e) => e.trusted && !isDecayed(e))
        .map((e) => ({ fingerprint: e.peer_fingerprint, lastSync: lastSyncOf(e) }));
    },

    getKnownPeers: async () => {
      const edges = await ownerEdges(store, ownerFingerprint);
      // The open-visible (consented) subset — NOT the whole book. This IS the consent gate (both
      // roles) + minimization boundary. Empty ⇒ fail-closed (sync no-ops, reveals nothing).
      return edges
        .filter((e) => e.open_visibility === true)
        .map((e) => ({ fingerprint: e.peer_fingerprint, lastSync: lastSyncOf(e) }));
    },

    applyMutualResult: async (peerFingerprint, layer, disclosed) => {
      // FAIL-CLOSED validation — on anything malformed we persist NOTHING (never guess a wider set).
      if (layer !== 'know' && layer !== 'trust') {
        throw new Error('applyMutualResult: unknown layer — fail-closed');
      }
      if (typeof peerFingerprint !== 'string' || peerFingerprint.length === 0) {
        throw new Error('applyMutualResult: missing peer fingerprint — fail-closed');
      }
      if (!Array.isArray(disclosed)) {
        throw new Error('applyMutualResult: malformed disclosed set — fail-closed');
      }

      const contacts = await store.getAllContacts(ownerFingerprint);
      const bookFps = new Set(
        contacts
          .filter((c) => typeof c.fingerprint === 'string' && c.fingerprint.length > 0)
          .map((c) => c.fingerprint as string),
      );
      const peer = contacts.find((c) => c.fingerprint === peerFingerprint);
      if (!peer) {
        // Unknown peer — never materialize a disclosure row for a non-contact (caller swallows).
        throw new Error('applyMutualResult: peer not in book — fail-closed');
      }

      // disclosed ∩ book (strings only, de-duplicated). This is the ENTIRE persisted set — never more.
      // We APPLY, we do not compute: no self/peer heuristics, no inference — just Apollo's result ∩ book.
      const inBook = [
        ...new Set(disclosed.filter((fp): fp is string => typeof fp === 'string' && bookFps.has(fp))),
      ];

      // Owner-local write ONLY (IndexedDB). No wire/serialize path is imported or reachable here (§C).
      const field: 'disclosed_circle' | 'they_trust' =
        layer === 'know' ? 'disclosed_circle' : 'they_trust';
      await store.updateContact(peer.id, { [field]: inBook } as Partial<ContactRecord>);
    },
  };
}

// ── Trigger ──────────────────────────────────────────────────────────────────────────────────────

export type SyncMutualTrustFn = typeof syncMutualTrust;

/**
 * One KNOW-layer sync tick.
 *
 * ★★ C1 (Flint, CRITICAL): pass 'know' EXPLICITLY. syncMutualTrust defaults `layer` to 'trust', and
 * respondToTrustSync's consent gate is `if (layer === 'know' && !consentSet.has(...)) continue` — so
 * an implicit/'trust' layer SKIPS the KNOW consent gate entirely (fail-OPEN). Do NOT rely on the
 * default; this literal 'know' is the tested privacy contract.
 */
export async function runKnowLayerSyncTick(
  deps: OrchestratorDeps,
  options: PSISyncOptions,
  syncFn: SyncMutualTrustFn = syncMutualTrust,
): Promise<void> {
  await syncFn(deps, options, 'know');
}

export interface KnowLayerSyncHandle {
  stop: () => void;
}

/** KNOW visibility is not latency-critical (staleness window is 24h); a modest interval avoids
 *  hammering the satellite while still driving the responder path (psiPending) on app-open + periodically. */
const DEFAULT_KNOW_SYNC_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

/** Resolve the owner fingerprint from the unlocked identity shape (same object ContactManagement holds). */
function ownerFingerprintOf(identity: unknown): string | null {
  const id = identity as { identity?: { fingerprint?: string } } | null;
  const fp = id?.identity?.fingerprint;
  return typeof fp === 'string' && fp.length > 0 ? fp : null;
}

/** Same-origin proxy prefix — the browser cannot reach the docker-internal satellite host. */
export const SATELLITE_BROWSER_BASE = '/api/satellite';

export type LoadIdentityKey = (
  fingerprint: string,
) => Promise<{ privateKey: string; passphrase: string } | null>;

function bytesToB64(bytes: Uint8Array): string {
  if (typeof btoa === 'function') {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }
  return Buffer.from(bytes).toString('base64');
}

/**
 * Bind the raw sign pubkey at the satellite (prerequisite for PSI auth).
 * Challenge: GET /bind?fingerprint= → { nonce, epoch } or { bound: true }.
 * Complete: POST /bind { fingerprint, sign_pubkey, nonce, epoch, signature }.
 * Returns false on any misshape / network miss — caller stays fail-closed (no PSI).
 */
export async function runBindCeremony(args: {
  satelliteUrl: string;
  fingerprint: string;
  seed: Uint8Array;
  signPub: Uint8Array;
  fetchImpl?: typeof fetch;
}): Promise<boolean> {
  const fetchImpl = args.fetchImpl ?? fetch;
  const base = args.satelliteUrl.replace(/\/$/, '');
  try {
    const challengeRes = await fetchImpl(
      `${base}/bind?fingerprint=${encodeURIComponent(args.fingerprint)}`,
    );
    if (!challengeRes.ok) return false;
    const challenge = await challengeRes.json();
    if (challenge && challenge.bound === true) return true;
    const nonce = challenge?.nonce;
    const epoch = challenge?.epoch;
    if (typeof nonce !== 'string' && typeof nonce !== 'number') return false;
    if (typeof epoch !== 'string' && typeof epoch !== 'number') return false;
    const signPubHex = bytesToHex(args.signPub);
    const signature = signBind(args.seed, signPubHex, String(nonce), epoch);
    const post = await fetchImpl(`${base}/bind`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fingerprint: args.fingerprint,
        sign_pubkey: signPubHex,
        nonce: String(nonce),
        epoch,
        signature: bytesToB64(signature),
      }),
    });
    return post.ok;
  } catch {
    return false;
  }
}

/**
 * Decrypt the vaulted OpenPGP identity (session must be unlocked), scalar-extract the
 * Ed25519 seed into a closure (in-memory only — never persisted), and return PSI options.
 * Null if locked / missing key / bind did not complete — fail-closed, no sync.
 */
export async function buildPsiSyncOptions(
  identity: unknown,
  deps: {
    loadKey?: LoadIdentityKey;
    satelliteUrl?: string;
    fetchImpl?: typeof fetch;
    skipBind?: boolean;
  } = {},
): Promise<PSISyncOptions | null> {
  const fp = ownerFingerprintOf(identity);
  if (!fp) return null;
  const load = deps.loadKey ?? loadKey;
  const key = await load(fp);
  if (!key?.privateKey || !key.passphrase) return null;

  let decrypted: any;
  try {
    const locked = await readPrivateKey({ armoredKey: key.privateKey });
    decrypted = locked.isDecrypted()
      ? locked
      : await decryptKey({ privateKey: locked, passphrase: key.passphrase });
  } catch {
    return null;
  }

  let seed: Uint8Array;
  let signPub: Uint8Array;
  try {
    ({ seed, signPub } = extractRawSign(decrypted));
  } catch {
    return null;
  }

  const satelliteUrl = (deps.satelliteUrl ?? SATELLITE_BROWSER_BASE).replace(/\/$/, '');
  if (!deps.skipBind) {
    const bound = await runBindCeremony({
      satelliteUrl,
      fingerprint: fp,
      seed,
      signPub,
      fetchImpl: deps.fetchImpl,
    });
    if (!bound) return null;
  }

  return {
    satelliteUrl,
    myFingerprint: fp,
    signFn: (data: Uint8Array) => signPsiAuthWrapped(seed, data),
  };
}

/**
 * Start the app-open + periodic KNOW-layer sync. Mirrors startLiveBookPolling (live-book-poll.ts):
 * immediate first tick, setInterval, FAIL-SOFT (a locked/absent identity or a transient error never
 * throws to React), NON-OVERLAPPING (inFlight guard). Returns a handle whose stop() clears the interval.
 *
 * `options` comes from buildPsiSyncOptions (raw Ed25519 signFn + satellite URL). No options ⇒
 * the caller must not start this loop — fail-closed (no sync ⇒ nothing disclosed).
 */
export function startKnowLayerSync(
  identity: unknown,
  options: PSISyncOptions,
  opts: { intervalMs?: number; store?: KnowOverlayStore; syncFn?: SyncMutualTrustFn } = {},
): KnowLayerSyncHandle {
  const intervalMs = opts.intervalMs ?? DEFAULT_KNOW_SYNC_INTERVAL_MS;
  const syncFn = opts.syncFn ?? syncMutualTrust;
  let stopped = false;
  let inFlight = false;

  const tick = async () => {
    if (stopped || inFlight) return; // never overlap ticks
    const owner = ownerFingerprintOf(identity);
    if (!owner) return; // no unlocked identity — stay inert, retry next tick
    inFlight = true;
    try {
      const deps = buildKnowOverlayDeps(owner, opts.store);
      await runKnowLayerSyncTick(deps, options, syncFn); // 'know' passed explicitly inside (C1)
    } catch (err) {
      // local-only diagnostic; never surfaced to peer/relay. One bad tick must not wedge the loop.
      console.error('[know-layer-sync] tick failed (will retry):', err);
    } finally {
      inFlight = false;
    }
  };

  void tick(); // immediate first sync on app-open
  const timer = setInterval(() => void tick(), intervalMs);

  return {
    stop: () => {
      stopped = true;
      clearInterval(timer);
    },
  };
}
