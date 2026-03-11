// src/lib/sync/merge.ts
// KeePass-style entry-level merge for vault sync.
//
// Strategy:
//   - Each TrustEdge has a unique `id` and timestamps
//   - Compare entries by ID: newer last_interaction wins
//   - Check tombstones before adding "new" entries
//   - Merge tribes by ID similarly
//   - Identity/keys: keep whichever vault was modified more recently
//   - Settings: merge field by field, newer wins
//
// This is NOT a CRDT. It's practical, battle-tested (KeePass does this),
// and good enough for a personal trust vault that one person owns.

import type { TrustGraph, TrustEdge, Tribe } from '../trust/types';
import type { VaultContents, Tombstone, MergeRecord } from './vault';

// --- Types ---

export interface MergeConflict {
  type: 'edge' | 'tribe' | 'identity' | 'settings';
  id: string;
  localValue: any;
  remoteValue: any;
  resolution: 'local' | 'remote';
  reason: string;
}

export interface MergeResult {
  merged: VaultContents;
  conflicts: MergeConflict[];
  stats: {
    edgesAdded: number;
    edgesUpdated: number;
    edgesDeleted: number;
    edgesUnchanged: number;
    tribesAdded: number;
    tribesUpdated: number;
  };
}

// --- Helpers ---

/**
 * Parse a date string, returning 0 for invalid dates.
 */
function toTime(dateStr: string | null | undefined): number {
  if (!dateStr) return 0;
  const t = new Date(dateStr).getTime();
  return isNaN(t) ? 0 : t;
}

/**
 * Get the "freshness" timestamp for a trust edge.
 * Uses the latest of: last_interaction, added_at, trusted_since.
 */
function edgeFreshness(edge: TrustEdge): number {
  return Math.max(
    toTime(edge.last_interaction),
    toTime(edge.added_at),
    toTime(edge.trusted_since),
  );
}

/**
 * Check if an ID has been tombstoned, and if the tombstone is newer
 * than the given timestamp.
 */
function isTombstoned(id: string, tombstones: Tombstone[], entryTime: number): boolean {
  const tomb = tombstones.find(t => t.id === id);
  if (!tomb) return false;
  return toTime(tomb.deletedAt) > entryTime;
}

// --- Merge Logic ---

/**
 * Merge two vaults. `local` is the current device's vault.
 * `remote` is what was pulled from cloud storage.
 *
 * Returns a new merged vault and conflict log.
 */
export function mergeVaults(local: VaultContents, remote: VaultContents): MergeResult {
  const conflicts: MergeConflict[] = [];
  const stats = {
    edgesAdded: 0,
    edgesUpdated: 0,
    edgesDeleted: 0,
    edgesUnchanged: 0,
    tribesAdded: 0,
    tribesUpdated: 0,
  };

  // --- 1. Merge trust graph edges ---
  const localEdgeMap = new Map(local.trustGraph.edges.map(e => [e.id, e]));
  const remoteEdgeMap = new Map(remote.trustGraph.edges.map(e => [e.id, e]));
  const allTombstones = mergeTombstones(local.sync.tombstones, remote.sync.tombstones);
  const mergedEdges: TrustEdge[] = [];

  // Process all IDs from both sides
  const allEdgeIds = new Set([...localEdgeMap.keys(), ...remoteEdgeMap.keys()]);

  for (const id of allEdgeIds) {
    const localEdge = localEdgeMap.get(id);
    const remoteEdge = remoteEdgeMap.get(id);

    if (localEdge && remoteEdge) {
      // Both sides have it — newer wins
      const localTime = edgeFreshness(localEdge);
      const remoteTime = edgeFreshness(remoteEdge);

      if (localTime >= remoteTime) {
        mergedEdges.push(localEdge);
        if (localTime > remoteTime) {
          stats.edgesUpdated++;
          conflicts.push({
            type: 'edge',
            id,
            localValue: localEdge.peer_name,
            remoteValue: remoteEdge.peer_name,
            resolution: 'local',
            reason: `Local is newer (${new Date(localTime).toISOString()} vs ${new Date(remoteTime).toISOString()})`,
          });
        } else {
          stats.edgesUnchanged++;
        }
      } else {
        mergedEdges.push(remoteEdge);
        stats.edgesUpdated++;
        conflicts.push({
          type: 'edge',
          id,
          localValue: localEdge.peer_name,
          remoteValue: remoteEdge.peer_name,
          resolution: 'remote',
          reason: `Remote is newer (${new Date(remoteTime).toISOString()} vs ${new Date(localTime).toISOString()})`,
        });
      }
    } else if (localEdge && !remoteEdge) {
      // Only local has it — check if remote deleted it
      if (isTombstoned(id, remote.sync.tombstones, edgeFreshness(localEdge))) {
        stats.edgesDeleted++;
      } else {
        mergedEdges.push(localEdge);
        stats.edgesUnchanged++;
      }
    } else if (!localEdge && remoteEdge) {
      // Only remote has it — check if local deleted it
      if (isTombstoned(id, local.sync.tombstones, edgeFreshness(remoteEdge))) {
        stats.edgesDeleted++;
      } else {
        mergedEdges.push(remoteEdge);
        stats.edgesAdded++;
      }
    }
  }

  // --- 2. Merge tribes ---
  const localTribeMap = new Map(local.trustGraph.tribes.map(t => [t.id, t]));
  const remoteTribeMap = new Map(remote.trustGraph.tribes.map(t => [t.id, t]));
  const mergedTribes: Tribe[] = [];
  const allTribeIds = new Set([...localTribeMap.keys(), ...remoteTribeMap.keys()]);

  for (const id of allTribeIds) {
    const localTribe = localTribeMap.get(id);
    const remoteTribe = remoteTribeMap.get(id);

    if (localTribe && remoteTribe) {
      // Both have it — merge members (union), keep newer metadata
      const localTime = toTime(localTribe.created_at);
      const remoteTime = toTime(remoteTribe.created_at);
      const base = localTime >= remoteTime ? localTribe : remoteTribe;
      const mergedMembers = [...new Set([...localTribe.members, ...remoteTribe.members])];
      const mergedAudit = mergeAuditChain(localTribe.audit_chain, remoteTribe.audit_chain);

      mergedTribes.push({
        ...base,
        members: mergedMembers,
        audit_chain: mergedAudit,
      });
      stats.tribesUpdated++;
    } else {
      mergedTribes.push((localTribe || remoteTribe)!);
      stats.tribesAdded++;
    }
  }

  // --- 3. Merge identity ---
  // Keep whichever was modified more recently.
  // Identity changes are rare (usually just verification status).
  const localIdentityTime = toTime(local.identity.verification?.verified_at) || toTime(local.identity.created_at);
  const remoteIdentityTime = toTime(remote.identity.verification?.verified_at) || toTime(remote.identity.created_at);
  const mergedIdentity = localIdentityTime >= remoteIdentityTime ? local.identity : remote.identity;
  const mergedKeys = localIdentityTime >= remoteIdentityTime ? local.keys : remote.keys;

  if (localIdentityTime !== remoteIdentityTime) {
    conflicts.push({
      type: 'identity',
      id: 'identity',
      localValue: local.identity.verification?.status,
      remoteValue: remote.identity.verification?.status,
      resolution: localIdentityTime >= remoteIdentityTime ? 'local' : 'remote',
      reason: 'Kept newer identity state',
    });
  }

  // --- 4. Merge settings ---
  const mergedSettings = mergeSettings(local.settings, remote.settings);

  // --- 5. Build merged trust graph ---
  const mergedGraph: TrustGraph = {
    version: local.trustGraph.version,
    owner_fingerprint: local.trustGraph.owner_fingerprint,
    edges: mergedEdges,
    tribes: mergedTribes,
    settings: {
      default_decay_days: mergedSettings.defaultDecayDays,
    },
    stats: {
      total_contacts: mergedEdges.length,
      trusted_count: mergedEdges.filter(e => e.trusted).length,
      known_count: mergedEdges.filter(e => !e.trusted).length,
      decayed_count: 0, // will be recalculated on load
      last_modified: new Date().toISOString(),
    },
  };

  // --- 6. Build merge record ---
  const mergeRecord: MergeRecord = {
    timestamp: new Date().toISOString(),
    deviceId: local.sync.deviceId,
    entriesAdded: stats.edgesAdded,
    entriesUpdated: stats.edgesUpdated,
    entriesDeleted: stats.edgesDeleted,
  };

  // --- 7. Assemble merged vault ---
  const merged: VaultContents = {
    identity: mergedIdentity,
    keys: mergedKeys,
    trustGraph: mergedGraph,
    settings: mergedSettings,
    recovery: local.recovery ?? remote.recovery,
    sync: {
      deviceId: local.sync.deviceId,
      lastModified: new Date().toISOString(),
      tombstones: allTombstones,
      mergeHistory: [...(local.sync.mergeHistory || []), mergeRecord],
    },
  };

  return { merged, conflicts, stats };
}

// --- Helper: merge tombstones ---

function mergeTombstones(local: Tombstone[], remote: Tombstone[]): Tombstone[] {
  const map = new Map<string, Tombstone>();

  for (const t of [...local, ...remote]) {
    const existing = map.get(t.id);
    if (!existing || toTime(t.deletedAt) > toTime(existing.deletedAt)) {
      map.set(t.id, t);
    }
  }

  // Prune tombstones older than 90 days — they've served their purpose
  const cutoff = Date.now() - 90 * 24 * 60 * 60 * 1000;
  return Array.from(map.values()).filter(t => toTime(t.deletedAt) > cutoff);
}

// --- Helper: merge audit chains ---

function mergeAuditChain(local: any[], remote: any[]): any[] {
  const seen = new Set<string>();
  const merged: any[] = [];

  for (const entry of [...local, ...remote]) {
    const key = `${entry.introduced}-${entry.introduced_by}-${entry.timestamp}`;
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(entry);
    }
  }

  return merged.sort((a, b) => toTime(a.timestamp) - toTime(b.timestamp));
}

// --- Helper: merge settings ---

function mergeSettings(
  local: VaultContents['settings'],
  remote: VaultContents['settings']
): VaultContents['settings'] {
  // For settings, local wins by default (user's current device preference)
  // except for cloud sync config which should come from the most recent
  return {
    defaultDecayDays: local.defaultDecayDays,
    safeWord: local.safeWord || remote.safeWord,
    cloudSync: local.cloudSync ?? remote.cloudSync,
  };
}

// --- Convenience: add a tombstone ---

export function createTombstone(id: string, deviceId: string): Tombstone {
  return {
    id,
    deletedAt: new Date().toISOString(),
    deletedBy: deviceId,
  };
}
