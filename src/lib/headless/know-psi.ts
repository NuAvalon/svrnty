// src/lib/headless/know-psi.ts
//
// KNOW-layer PSI for a HEADLESS agent seat (S53): the adapter that lets an agent run the same
// mutual-contact discovery the browser runs, over its HeadlessStore instead of IndexedDB.
//
// This is an ADAPTER, not a crypto change. The sync core (know-layer-sync.ts) is already seam-injected
// (KnowOverlayStore, PSISyncOptions); this file only supplies a headless store, headless signing options built
// through the SAME bind + anti-swap-pin path the browser uses, and one tick in the browser loop's order.
//
// KNOW ONLY. Nothing here touches the trust layer (Peter's gate #179866): runKnowLayerSyncTick pins layer 'know'.
//
// DEV ONLY, FAIL CLOSED (Flint #197, condition 1). The dogfood runs against the DEV satellite with throwaway seats.
// assertDevOnly refuses any other satellite URL and any other mailbox-key pin; headlessPsiOptions and
// runHeadlessKnowTick both enforce it, and there is no knob to loosen it. A prod run would be a code change that
// goes through review, not a flag.
//
// HEADLESS-ONLY (type-imports HeadlessStore, which pulls node:fs): never import into the browser bundle.

import type { HeadlessStore, HeadlessContact } from './headless-store';
import type { SerializedMintArtifact } from '@/lib/identity/headless-mint';
import type { ContactRecord } from '@/lib/identity/client-store';
import type { PSISyncOptions } from '@/lib/trust/mutual-trust-sync';
import { PINNED_SATELLITE_MAILBOX_FP_DEV, verifySatelliteKey } from '@/lib/crypto/psi-wire-seal';
import {
  buildPsiSyncOptions,
  buildKnowOverlayDeps,
  runPsiCompletionPass,
  runKnowLayerSyncTick,
  savePsiInitiated,
  type KnowOverlayStore,
} from '@/lib/sync/know-layer-sync';

/** What one KNOW tick reports (responded / initiated / errors). */
export type KnowTickResult = Awaited<ReturnType<typeof runKnowLayerSyncTick>>;

/** The ONLY satellite this adapter will talk to. Exact match after trailing-slash normalisation. */
export const DEV_SATELLITE_URL = 'https://dev.svrnty.is/api/satellite';

export class KnowDevOnlyError extends Error {
  constructor(what: string) {
    super(`know-psi: DEV-only adapter refuses ${what}`);
    this.name = 'KnowDevOnlyError';
  }
}

const normUrl = (u: string): string => u.replace(/\/+$/, '');

/**
 * Throw unless this is the dev satellite AND the pinned dev mailbox-key fingerprint. Exact string comparison on the
 * normalised URL (never startsWith / URL host parsing: "https://dev.svrnty.is.evil.test/..." and
 * "https://dev.svrnty.is@evil.test/..." must not pass).
 */
export function assertDevOnly(satelliteUrl: unknown, pinnedFp: unknown): void {
  if (typeof satelliteUrl !== 'string' || normUrl(satelliteUrl) !== DEV_SATELLITE_URL) {
    throw new KnowDevOnlyError('a satellite URL that is not the dev satellite');
  }
  if (typeof pinnedFp !== 'string' || pinnedFp !== PINNED_SATELLITE_MAILBOX_FP_DEV) {
    throw new KnowDevOnlyError('a mailbox-key pin that is not the pinned dev fingerprint');
  }
}

/**
 * KnowOverlayStore over a HeadlessStore. A HeadlessStore holds ONE owner's book, so the owner argument is not
 * a filter (the browser store keys by owner; here the file IS the owner's). updateContact throws on an unknown id
 * (HeadlessStore's own contract); the sync core already treats a thrown store write as "retry next tick".
 */
export function headlessKnowStore(store: HeadlessStore): KnowOverlayStore {
  return {
    getAllContacts: async () => store.listContacts() as unknown as ContactRecord[],
    updateContact: async (id, updates) => {
      store.updateContact(id, updates as Partial<HeadlessContact>);
    },
  };
}

/**
 * PSISyncOptions for a headless seat, from its custody artifact. Goes through buildPsiSyncOptions, so the /bind
 * ceremony, the satellite-key fetch and the anti-swap pin check are the browser's, not a copy. skipBind is never
 * passed: a seat that cannot bind or cannot verify the satellite key gets null (no sync), never an unsealed wire.
 *
 * The signing key stays in-process: the armored key + passphrase are handed to the loader closure and nothing here
 * logs or returns them.
 */
export async function headlessPsiOptions(
  artifact: SerializedMintArtifact,
  deps: { fetchImpl?: typeof fetch } = {},
): Promise<PSISyncOptions | null> {
  const fingerprint = artifact?.public?.durable_id;
  const privateKey = artifact?.private?.classical_private_key;
  const passphrase = artifact?.private?.classical_kpass;
  if (!fingerprint || !privateKey || !passphrase) return null; // fail closed: cannot sign
  return buildPsiSyncOptions(
    { identity: { fingerprint } },
    {
      loadKey: async () => ({ privateKey, passphrase }),
      satelliteUrl: DEV_SATELLITE_URL,
      pinnedFp: PINNED_SATELLITE_MAILBOX_FP_DEV,
      ...(deps.fetchImpl ? { fetchImpl: deps.fetchImpl } : {}),
    },
  );
}

/**
 * One KNOW tick for a headless seat, in startKnowLayerSync's order: complete earlier sessions + forward-revoke,
 * respond + initiate (layer 'know'), persist the newly initiated sessions. Unlike the browser loop it does NOT
 * swallow errors: a dogfood run must see a failing tick. DEV ONLY, fail closed BY CONSTRUCTION: the target (URL and
 * pinned satellite key) is the module's constants, so no caller can name another one. Requires the sealed wire
 * (options.pqWrap) AND that pqWrap's satellite key is the pinned dev key, so options built any other way (some other
 * satellite's key) are refused here too, not only inside headlessPsiOptions (Flint #453).
 */
export async function runHeadlessKnowTick(
  ownerFingerprint: string,
  store: HeadlessStore,
  options: PSISyncOptions,
): Promise<KnowTickResult> {
  return tickCore(ownerFingerprint, store, options, { url: DEV_SATELLITE_URL, pin: PINNED_SATELLITE_MAILBOX_FP_DEV });
}

/**
 * INTERNAL. The guarded tick with its target spelled out, so tests can drive it against a mock satellite whose key
 * cannot equal the real pin. Production code must go through runHeadlessKnowTick, whose target is fixed; a test pins
 * that nothing outside this file and the tests imports tickCore.
 */
export async function tickCore(
  ownerFingerprint: string,
  store: HeadlessStore,
  options: PSISyncOptions,
  target: { url: string; pin: string },
): Promise<KnowTickResult> {
  if (typeof options?.satelliteUrl !== 'string' || normUrl(options.satelliteUrl) !== normUrl(target.url)) {
    throw new KnowDevOnlyError('a satellite URL that is not the dev satellite');
  }
  if (!options.pqWrap) throw new KnowDevOnlyError('an unsealed PSI wire (no pqWrap)');
  const sk = options.pqWrap.satelliteKeys;
  if (!sk || verifySatelliteKey(sk.x25519Pub, sk.mlkem1024Pub, target.pin) === null) {
    throw new KnowDevOnlyError('a satellite key that is not the pinned dev key');
  }
  if (options.myFingerprint !== ownerFingerprint) throw new Error('know-psi: options.myFingerprint is not the owner');

  const kos = headlessKnowStore(store);
  const deps = buildKnowOverlayDeps(ownerFingerprint, kos);
  await runPsiCompletionPass(kos, ownerFingerprint, deps, options);
  const result = await runKnowLayerSyncTick(deps, options);
  await savePsiInitiated(kos, ownerFingerprint, result.initiated);
  return result;
}

/**
 * What a run may publish (Flint #197, condition 3): 8-hex fingerprint prefixes and counts only. No full
 * fingerprints, no blinded values, no keys. One row per contact that has a consent flag, a live session or a
 * disclosed circle.
 */
export interface KnowRunRow {
  peer: string; // 8-hex prefix
  consented: boolean;
  sessionInFlight: boolean;
  disclosed: number;
  disclosedPeers: string[]; // 8-hex prefixes, sorted
}
const p8 = (fp: string): string => fp.slice(0, 8);

export function summarizeKnowState(store: HeadlessStore): KnowRunRow[] {
  return store
    .listContacts()
    .map((c) => {
      const disclosed = Array.isArray(c.disclosed_circle) ? (c.disclosed_circle as unknown[]).filter((x): x is string => typeof x === 'string') : [];
      return {
        peer: p8(c.fingerprint),
        consented: c.open_visibility === true,
        sessionInFlight: typeof c.psi_session_id === 'string' && c.psi_session_id.length > 0,
        disclosed: disclosed.length,
        disclosedPeers: disclosed.map(p8).sort(),
      };
    })
    .filter((r) => r.consented || r.sessionInFlight || r.disclosed > 0)
    .sort((a, b) => a.peer.localeCompare(b.peer));
}
