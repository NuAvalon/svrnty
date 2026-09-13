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
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
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
  completeTrustSync,
  type OrchestratorDeps,
  type PSISyncOptions,
  type PSIKeypair,
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
    .filter((c) => c.metadata?.grow_gate !== true) // Gate arrivals must never enter PSI
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
type SyncMutualTrustResult = Awaited<ReturnType<SyncMutualTrustFn>>;

// ── PSI initiator session persistence (Option A — blinder ON the contact record) ──────────────────
// The PSI initiator starts a session on one tick but the responder answers ASYNC (the satellite is a
// blind mailbox), so completion runs on a LATER tick — which needs the single-use blind scalar (sk_A)
// + the blinded fp ORDER carried across the gap. Per Peter's design the blinder lives ON THE PEER'S
// CONTACT RECORD (not a separate store): the contact body is already AES-GCM encrypted at rest (enc-b),
// so the scalar inherits at-rest protection, and its lifecycle ties to the contact — retract
// (go-private / untrust / delete) drops it for free (forward-revocation).
//
// DENIABILITY (Hypatia disclosure-model design-of-record): NO wall-clock. Expiry uses an ATTEMPT
// COUNTER (a logical clock) — psi_attempts bumps per not-ready completion; past MAX we drop the session
// (≈ the 1h satellite TTL at the 5-min tick). Overwrite-not-append: one in-flight session per peer.
const MAX_PSI_ATTEMPTS = 12; // ≈ 1h at the 5-min KNOW tick — matches the satellite session TTL

const CLEARED_PSI_SESSION: Partial<ContactRecord> = {
  psi_session_id: undefined, psi_sk_A: undefined, psi_pub: undefined,
  psi_fp_order: undefined, psi_layer: undefined, psi_attempts: undefined,
};

/** Persist the sessions initiated this tick onto each peer's contact record (overwrite any prior — one in-flight per peer). */
export async function savePsiInitiated(
  store: KnowOverlayStore,
  ownerFingerprint: string,
  initiated: SyncMutualTrustResult['initiated'],
): Promise<void> {
  if (!initiated || initiated.length === 0) return;
  const byFp = new Map((await store.getAllContacts(ownerFingerprint)).map((c) => [c.fingerprint, c]));
  for (const s of initiated) {
    const contact = byFp.get(s.peerFingerprint);
    if (!contact) continue; // only ever store a session against a real book contact
    await store.updateContact(contact.id, {
      psi_session_id: s.sessionId,
      psi_sk_A: s.keypair.privateKey,
      psi_pub: s.keypair.publicKey,
      psi_fp_order: s.fpOrder,
      psi_layer: 'know',
      psi_attempts: 0,
    } as Partial<ContactRecord>);
  }
}

/**
 * Completion pass — finish any sessions saved on prior ticks (the initiator half that was previously
 * never wired: the tick discarded `initiated` → completeTrustSync had zero callers → no intersection →
 * no trust map). For every contact:
 *  - FORWARD-REVOCATION: a de-consented peer (open_visibility !== true) → drop the in-flight session
 *    AND clear disclosed_circle. They fall out of discovery; nothing corroborates the past.
 *  - READY: completeTrustSync applies the mutual set (deps.applyMutualResult) → clear the session.
 *  - NOT-READY: bump psi_attempts (logical clock); past MAX clear it (expiry — responder never answered).
 * Fail-soft per contact — one bad session never wedges the pass.
 */
export type CompleteTrustSyncFn = typeof completeTrustSync;

export async function runPsiCompletionPass(
  store: KnowOverlayStore,
  ownerFingerprint: string,
  deps: OrchestratorDeps,
  options: PSISyncOptions,
  completeFn: CompleteTrustSyncFn = completeTrustSync,
): Promise<void> {
  const contacts = await store.getAllContacts(ownerFingerprint);
  for (const c of contacts) {
    const consented = contactRecordToEdge(c).open_visibility === true;
    const hasSession = typeof c.psi_session_id === 'string' && c.psi_session_id.length > 0;
    const hasDisclosed = Array.isArray(c.disclosed_circle) && c.disclosed_circle.length > 0;
    try {
      // Forward-revocation: a de-consented peer must not complete or retain a disclosure.
      if (!consented) {
        if (hasSession || hasDisclosed) {
          await store.updateContact(c.id, { ...CLEARED_PSI_SESSION, disclosed_circle: [] } as Partial<ContactRecord>);
        }
        continue;
      }
      if (!hasSession) continue;
      // Fail-closed: an incomplete session record (missing scalar/order) can't complete — drop it,
      // never proceed with a guessed sk_A.
      if (typeof c.psi_sk_A !== 'string' || !Array.isArray(c.psi_fp_order)) {
        await store.updateContact(c.id, CLEARED_PSI_SESSION);
        continue;
      }
      const keypair: PSIKeypair = { privateKey: c.psi_sk_A, publicKey: typeof c.psi_pub === 'string' ? c.psi_pub : '' };
      const layer: 'know' | 'trust' = c.psi_layer === 'trust' ? 'trust' : 'know';
      const result = await completeFn(deps, c.psi_session_id as string, c.fingerprint, keypair, options, c.psi_fp_order as string[], layer);
      if (result && !('error' in result)) {
        await store.updateContact(c.id, CLEARED_PSI_SESSION); // applied → ephemeral delete
      } else {
        const attempts = (typeof c.psi_attempts === 'number' ? c.psi_attempts : 0) + 1;
        await store.updateContact(
          c.id,
          attempts > MAX_PSI_ATTEMPTS ? CLEARED_PSI_SESSION : ({ psi_attempts: attempts } as Partial<ContactRecord>),
        );
      }
    } catch {
      // local-only; never surface. Leave the session for a later tick.
    }
  }
}

/**
 * One KNOW-layer sync tick. Returns syncMutualTrust's result so the caller can persist the
 * newly-initiated blinders (the completion loop lives in startKnowLayerSync, which holds owner+store).
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
): Promise<SyncMutualTrustResult> {
  return syncFn(deps, options, 'know');
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
 *
 * The satellite `/bind` is POST-ONLY (authoritative: satellite_9223f3d3_reconciled.py /
 * satellite_F1.py `@app.post("/bind")`, Flint's svrnty_registration_bind_additive.patch). There is
 * NO GET-challenge route — a GET 405s (the old code GET'd first → 405 → fail-closed → PSI never ran,
 * the Gate-A bind-405). The satellite verifies Ed25519 over `svrnty-bind:{sig_pubkey}:{nonce}:{epoch}`
 * against the REGISTERED identity key, so the client self-generates the nonce (the satellite does not
 * issue/track it). Field names are `sig_pubkey` + `binding_sig` (NOT sign_pubkey/signature).
 * Byte-matches psi_harness.py (proven 200). Returns false on any miss — caller stays fail-closed (no PSI).
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
    const signPubHex = bytesToHex(args.signPub);
    const nonce = bytesToHex(randomBytes(16)); // client self-gen; satellite verifies the sig, not the nonce source
    const epoch = 0;
    const signature = signBind(args.seed, signPubHex, nonce, epoch);
    const post = await fetchImpl(`${base}/bind`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fingerprint: args.fingerprint,
        sig_pubkey: signPubHex,
        nonce,
        epoch,
        binding_sig: bytesToB64(signature),
      }),
    });
    return post.ok;
  } catch {
    return false;
  }
}

/**
 * Enroll the identity at the satellite (prerequisite for bind → PSI auth).
 * The satellite's /bind 404s "Unknown fingerprint" if the identity isn't registered (KB#89329).
 * Mint only registers on slug-claim (SoverentityFrontend) → a minted-but-unslugged identity is never
 * enrolled, so PSI 404s. This co-locates register with bind (same SATELLITE_URL, backend-agnostic),
 * self-healing + idempotent. Sends the satellite's NATIVE register contract — RAW key bytes as base64
 * under {public_key, encryption_pk, pq_kem_pk, pq_sig_pk} (buildCanonicalRegisterPayload), which the
 * satellite b64decodes and re-hashes SHA256(sign‖enc‖kem‖sig) to verify the fingerprint (Athena #137918).
 * NOT buildSatelliteRegisterFields (hex + armored public_key → 400 "Invalid public_key encoding", KB#89639).
 * 409 = already-registered = success. Returns false on network miss / missing public_key — fail-closed.
 */
export async function runRegisterCeremony(args: {
  satelliteUrl: string;
  identity: unknown;
  fetchImpl?: typeof fetch;
}): Promise<boolean> {
  const id = args.identity as {
    identity?: { fingerprint?: string; public_key?: string; publicKey?: string };
  } | null;
  const fp = id?.identity?.fingerprint;
  const publicKey = id?.identity?.public_key || id?.identity?.publicKey || '';
  if (!fp || !publicKey) return false;
  const fetchImpl = args.fetchImpl ?? fetch;
  const base = args.satelliteUrl.replace(/\/$/, '');
  try {
    // Hybrid identities send the satellite's native raw-b64 4-key contract; missing PQ pubs (classical/
    // legacy, or an unparseable armor) fall back to the legacy {fingerprint, public_key} shape unchanged.
    let payload: Record<string, string> = { fingerprint: fp, public_key: publicKey };
    try {
      const { buildCanonicalRegisterPayload } = await import('@/lib/identity/fingerprint');
      const canonical = await buildCanonicalRegisterPayload(
        args.identity as Parameters<typeof buildCanonicalRegisterPayload>[0],
      );
      if (canonical) {
        payload = {
          fingerprint: canonical.fingerprint,
          public_key: canonical.public_key,
          encryption_pk: canonical.encryption_pk,
          pq_kem_pk: canonical.pq_kem_pk,
          pq_sig_pk: canonical.pq_sig_pk,
          crypto_version: canonical.crypto_version,
          ...(canonical.name ? { name: canonical.name } : {}),
        };
      }
    } catch {
      // parse failure → keep the legacy fallback payload
    }
    const res = await fetchImpl(`${base}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (res.ok || res.status === 409) return true; // 2xx, or 409 = already registered
    // Re-registering an EXISTING fingerprint is treated by the satellite as a key-ROTATION attempt →
    // 403 {"detail":"Key rotation requires signature from existing key"} (KB#89344; anti-rotation-hijack
    // guard — the satellite is CORRECT here, do NOT weaken it). For the enroll-before-bind precondition
    // that 403 means the identity is ALREADY registered → proceed to bind (the real enrollment gate: it
    // 404s if not actually registered, so proceeding is self-correcting). Any OTHER 403 (or unreadable
    // body) fail-closes. Without this, every tick after the first re-registers → 403 → the whole PSI sync
    // aborts (no bind, no PSI) → chord stays 0 (Hypatia #138013 / Athena #138021).
    if (res.status === 403) {
      let body = '';
      try { body = (await res.text()).toLowerCase(); } catch { body = ''; }
      return body.includes('rotation') || body.includes('already registered');
    }
    return false;
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
    // Enroll at the satellite BEFORE bind — /bind 404s "Unknown fingerprint" if the identity isn't
    // registered there, and register is otherwise only called on slug-claim (so a PSI-only identity is
    // never enrolled). Same SATELLITE_URL as bind → co-located, self-healing, idempotent (409=ok).
    const registered = await runRegisterCeremony({ satelliteUrl, identity, fetchImpl: deps.fetchImpl });
    if (!registered) return null;
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
      const store = opts.store ?? defaultStore;
      const deps = buildKnowOverlayDeps(owner, store);
      // 1. Complete initiator sessions saved on prior ticks (responder answers async) + forward-revoke
      //    de-consented peers. THIS closes the initiator half that was never wired = the trust map.
      await runPsiCompletionPass(store, owner, deps, options);
      // 2. Respond to pending + initiate new sessions ('know' explicit — C1).
      const result = await runKnowLayerSyncTick(deps, options, syncFn);
      // 3. Persist the newly-initiated blinders so a later tick can complete them.
      await savePsiInitiated(store, owner, result.initiated);
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
