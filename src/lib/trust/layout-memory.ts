/**
 * Persist Trust Map node positions so neighborhoods feel like *your* map.
 * Pure UI — no trust semantics. Soft-merge with fresh layout on load.
 *
 * When witnessed mutual topology OR glass state (known → verified → trusted)
 * changes, blend softens so density / gravity can rearrange the lattice.
 *
 * Contacts-at-rest v0.1 (A6): the memory moved off localStorage plaintext into a
 * sealed per-owner settings row (atrest:layout, client-store). Positions keyed by
 * fingerprint stay inside the seal; the topology / glass signature strings are NOT
 * stored — one digest detects change instead:
 *   digest = first 16 bytes of SHA-256(TLV("svrnty-layout-digest-v1") ‖ TLV(topology) ‖ TLV(glass)), hex.
 * `loadLayoutMemory` is async: locked → short-circuit empty without touching the
 * store (the map re-reads every second); a corrupt seal THROWS and the caller
 * draws a fresh layout — the map is never blocked.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes } from '@noble/hashes/utils.js';
import { lpStr } from '../crypto/lp-tlv';
import {
  isSessionUnlocked,
  readAtRestLayout,
  writeAtRestLayout,
} from '../identity/client-store';

const PREFIX = 'svrnty.trust-map.layout.v1:'; // legacy localStorage row (left in place post-migration, A7)
const LAYOUT_DIGEST_TAG = 'svrnty-layout-digest-v1';

export type StoredNodePos = { id: string; x: number; y: number };

export type LayoutMemoryPayload = {
  nodes: Map<string, StoredNodePos>;
  /** Sealed-record change digest (svrnty-layout-digest-v1); '' when legacy/unknown. */
  digest: string;
};

function key(ownerFingerprint: string): string {
  return `${PREFIX}${ownerFingerprint.toLowerCase()}`;
}

/**
 * The one stored change-detector (A6): first 16 bytes of
 * SHA-256(LP(tag) ‖ LP(topology) ‖ LP(glass)), hex. Pure + synchronous so the
 * render path can compare every frame without an await.
 */
export function layoutDigest(topology: string, glass: string): string {
  const digest = sha256(concatBytes(lpStr(LAYOUT_DIGEST_TAG), lpStr(topology), lpStr(glass)));
  return bytesToHex(digest.slice(0, 16));
}

/** Stable fingerprint of witnessed mutual chords (order-independent). */
export function mutualTopologySignature(
  bonds: Array<{ a: string; b: string }>,
): string {
  return bonds
    .map((b) => {
      const x = (b.a || '').toLowerCase();
      const y = (b.b || '').toLowerCase();
      return x < y ? `${x}|${y}` : `${y}|${x}`;
    })
    .filter((k) => k !== '|')
    .sort()
    .join(';');
}

/**
 * Owner-local glass fingerprint (known / verified / trusted).
 * Order-independent. Verify is private — this signature never leaves the device.
 */
export function glassStateSignature(
  nodes: Array<{ id: string; state: string; verified?: boolean }>,
): string {
  return nodes
    .map((n) => {
      const id = (n.id || '').toLowerCase();
      const v = n.verified ? 'v' : '';
      return `${id}:${n.state}${v}`;
    })
    .filter((k) => !k.startsWith(':'))
    .sort()
    .join(';');
}

const EMPTY = (): LayoutMemoryPayload => ({ nodes: new Map<string, StoredNodePos>(), digest: '' });

function positionsFrom(list: unknown): Map<string, StoredNodePos> {
  const nodes = new Map<string, StoredNodePos>();
  if (!Array.isArray(list)) return nodes;
  for (const p of list) {
    if (p && typeof p.id === 'string' && Number.isFinite(p.x) && Number.isFinite(p.y)) {
      nodes.set(p.id, p as StoredNodePos);
    }
  }
  return nodes;
}

/** The old plaintext localStorage row (A5 read fallback; A7 leaves it in place). */
function readLegacyLayout(ownerFingerprint: string): { nodes: Map<string, StoredNodePos>; topology: string; glass: string } | null {
  if (typeof localStorage === 'undefined') return null;
  try {
    const raw = localStorage.getItem(key(ownerFingerprint));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as
      | StoredNodePos[]
      | { nodes?: StoredNodePos[]; topology?: string; glass?: string };
    const list = Array.isArray(parsed) ? parsed : parsed?.nodes;
    const topology =
      !Array.isArray(parsed) && typeof parsed?.topology === 'string' ? parsed.topology : '';
    const glass =
      !Array.isArray(parsed) && typeof parsed?.glass === 'string' ? parsed.glass : '';
    return { nodes: positionsFrom(list), topology, glass };
  } catch {
    return null;
  }
}

/**
 * Load the remembered layout. Async + fail-loud-on-corrupt (A4/A6):
 *  - locked → empty, WITHOUT touching the store (the map re-reads every second).
 *  - sealed row present → its nodes + digest; a tag/decrypt/shape failure THROWS
 *    (the caller draws a fresh layout — the map is never blocked on it).
 *  - sealed row absent → the old localStorage row answers once (A5); its
 *    topology+glass strings are folded into the digest, never re-stored.
 */
export async function loadLayoutMemory(ownerFingerprint: string): Promise<LayoutMemoryPayload> {
  if (!ownerFingerprint) return EMPTY();
  if (!isSessionUnlocked()) return EMPTY(); // locked: short-circuit, no decrypt attempt
  const sealed = await readAtRestLayout(ownerFingerprint); // throws AtRestUnreadableError on corrupt
  if (sealed) return { nodes: positionsFrom(sealed.nodes), digest: sealed.digest };
  const legacy = readLegacyLayout(ownerFingerprint);
  if (!legacy) return EMPTY();
  return { nodes: legacy.nodes, digest: layoutDigest(legacy.topology, legacy.glass) };
}

/**
 * Persist positions + the change digest, sealed per owner (A1/A6). Locked →
 * throws AtRestLockedError (A3 — the caller treats a failed save as no memory
 * written, never a plaintext fallback). First unlocked write seals whatever the
 * legacy localStorage row carried (A7) and leaves that row in place.
 */
export async function saveLayoutMemory(
  ownerFingerprint: string,
  nodes: StoredNodePos[],
  topology = '',
  glass = '',
): Promise<void> {
  if (!ownerFingerprint) return;
  const slim = nodes
    .filter((n) => n.id && Number.isFinite(n.x) && Number.isFinite(n.y))
    .map((n) => ({ id: n.id, x: n.x, y: n.y }));
  await writeAtRestLayout(ownerFingerprint, {
    v: 1,
    nodes: slim,
    digest: layoutDigest(topology, glass),
  });
}

/**
 * Blend remembered positions into a fresh layout (0 = fresh, 1 = memory).
 * Topology change (mutual bonds) and glass upgrades (known→trusted) both
 * soften recall so density / gravity can re-pack the hive.
 */
export function applyLayoutMemory<T extends { id: string; x: number; y: number }>(
  nodes: T[],
  memory: Map<string, StoredNodePos>,
  blend = 0.85,
  topologyChanged = false,
  stateChanged = false,
): T[] {
  if (memory.size === 0) return nodes;
  const b = stateChanged
    ? Math.min(blend, 0.14)
    : topologyChanged
      ? Math.min(blend, 0.28)
      : blend;
  return nodes.map((n) => {
    const m = memory.get(n.id);
    if (!m) return n;
    return {
      ...n,
      x: m.x * b + n.x * (1 - b),
      y: m.y * b + n.y * (1 - b),
    };
  });
}
