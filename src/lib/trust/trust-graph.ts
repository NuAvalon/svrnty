// src/lib/trust/trust-graph.ts
// Local-first encrypted trust graph. Replaces ContactManager.
// Storage: ~/.soverentity/<fingerprint>.trust.enc (PGP-encrypted JSON)

import { readFile, writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { createMessage, encrypt, readMessage, decrypt, readKey, readPrivateKey, decryptKey } from 'openpgp';
import { randomUUID } from 'crypto';
import type {
  TrustEdge,
  TrustGraph,
  TrustLevel,
  TrustEvent,
  Tribe,
  IntroductionRecord,
  LegacyContact,
} from './types';
import { TRUST_LABELS } from './types';
import { migrateContacts } from './migration';

export interface TrustGraphManagerOptions {
  storageDir?: string;
  ownerFingerprint: string;
  ownerPublicKey: string;
  ownerPrivateKey: string;
  ownerPassphrase: string;
}

export class TrustGraphManager {
  private storageDir: string;
  private ownerFingerprint: string;
  private ownerPublicKey: string;
  private ownerPrivateKey: string;
  private ownerPassphrase: string;
  private initialized: Promise<void>;

  constructor(options: TrustGraphManagerOptions) {
    this.storageDir = options.storageDir || join(homedir(), '.soverentity');
    this.ownerFingerprint = options.ownerFingerprint;
    this.ownerPublicKey = options.ownerPublicKey;
    this.ownerPrivateKey = options.ownerPrivateKey;
    this.ownerPassphrase = options.ownerPassphrase;
    this.initialized = this.initialize();
  }

  private async initialize(): Promise<void> {
    await mkdir(this.storageDir, { recursive: true });
  }

  // --- File paths ---

  private graphPath(): string {
    return join(this.storageDir, `${this.ownerFingerprint}.trust.enc`);
  }

  // --- Encrypted storage ---

  private async loadGraph(): Promise<TrustGraph> {
    await this.initialized;
    try {
      const encryptedData = await readFile(this.graphPath(), 'utf8');
      const message = await readMessage({ armoredMessage: encryptedData });
      const privateKeyObj = await readPrivateKey({ armoredKey: this.ownerPrivateKey });
      const decryptedKey = await decryptKey({
        privateKey: privateKeyObj,
        passphrase: this.ownerPassphrase,
      });
      const { data: decrypted } = await decrypt({
        message,
        decryptionKeys: decryptedKey,
      });
      return JSON.parse(decrypted.toString());
    } catch (error: any) {
      if (error.code === 'ENOENT') {
        return this.emptyGraph();
      }
      throw error;
    }
  }

  private async saveGraph(graph: TrustGraph): Promise<void> {
    await this.initialized;
    graph.stats = this.computeStats(graph);
    const message = await createMessage({
      text: JSON.stringify(graph, null, 2),
    });
    const publicKey = await readKey({ armoredKey: this.ownerPublicKey });
    const encrypted = await encrypt({ message, encryptionKeys: publicKey });
    await writeFile(this.graphPath(), encrypted as string);
  }

  private emptyGraph(): TrustGraph {
    return {
      version: '1.0.0',
      owner_fingerprint: this.ownerFingerprint,
      edges: [],
      tribes: [],
      stats: {
        total_contacts: 0,
        by_level: { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 },
        last_modified: new Date().toISOString(),
      },
    };
  }

  private computeStats(graph: TrustGraph): TrustGraph['stats'] {
    const byLevel: Record<number, number> = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 };
    for (const edge of graph.edges) {
      byLevel[edge.trust_level] = (byLevel[edge.trust_level] || 0) + 1;
    }
    return {
      total_contacts: graph.edges.length,
      by_level: byLevel,
      last_modified: new Date().toISOString(),
    };
  }

  // --- Edge CRUD ---

  async addEdge(params: {
    peer_fingerprint: string;
    peer_name: string;
    peer_email: string;
    peer_public_key: string;
    trust_level?: TrustLevel;
    connection_channels?: string[];
    notes?: string;
    tags?: string[];
    peer_pq_sig_public_key?: string;
    peer_pq_kem_public_key?: string;
  }): Promise<TrustEdge> {
    const graph = await this.loadGraph();

    if (graph.edges.some(e => e.peer_fingerprint === params.peer_fingerprint)) {
      throw new Error('Edge already exists for this fingerprint');
    }

    const level = params.trust_level ?? 1;
    const now = new Date().toISOString();

    const edge: TrustEdge = {
      id: randomUUID(),
      peer_fingerprint: params.peer_fingerprint,
      peer_name: params.peer_name,
      peer_email: params.peer_email,
      peer_public_key: params.peer_public_key,
      trust_level: level,
      trust_since: now,
      trust_history: [{
        timestamp: now,
        from_level: 0,
        to_level: level,
        reason: 'Initial contact added',
        initiated_by: 'self',
      }],
      verification: {
        method: 'none',
        verified_at: null,
      },
      mutual: {
        their_level_for_me: null,
        last_sync: null,
        reciprocal: false,
      },
      tags: params.tags || [],
      notes: params.notes || '',
      connection_channels: params.connection_channels || [],
      added_at: now,
      peer_pq_sig_public_key: params.peer_pq_sig_public_key,
      peer_pq_kem_public_key: params.peer_pq_kem_public_key,
    };

    graph.edges.push(edge);
    await this.saveGraph(graph);
    return edge;
  }

  async getEdge(fingerprint: string): Promise<TrustEdge | null> {
    const graph = await this.loadGraph();
    return graph.edges.find(e => e.peer_fingerprint === fingerprint) || null;
  }

  async getEdgeById(id: string): Promise<TrustEdge | null> {
    const graph = await this.loadGraph();
    return graph.edges.find(e => e.id === id) || null;
  }

  async getAllEdges(): Promise<TrustEdge[]> {
    const graph = await this.loadGraph();
    return graph.edges;
  }

  async getEdgesByLevel(level: TrustLevel): Promise<TrustEdge[]> {
    const graph = await this.loadGraph();
    return graph.edges.filter(e => e.trust_level === level);
  }

  async getEdgesAtOrAbove(level: TrustLevel): Promise<TrustEdge[]> {
    const graph = await this.loadGraph();
    return graph.edges.filter(e => e.trust_level >= level);
  }

  async updateEdge(
    fingerprint: string,
    updates: Partial<Pick<TrustEdge, 'peer_name' | 'peer_email' | 'tags' | 'notes' | 'connection_channels' | 'agent_fingerprint'>>
  ): Promise<TrustEdge> {
    const graph = await this.loadGraph();
    const idx = graph.edges.findIndex(e => e.peer_fingerprint === fingerprint);
    if (idx === -1) throw new Error('Edge not found');

    graph.edges[idx] = { ...graph.edges[idx], ...updates };
    await this.saveGraph(graph);
    return graph.edges[idx];
  }

  async removeEdge(fingerprint: string, reason: string): Promise<void> {
    const graph = await this.loadGraph();
    const idx = graph.edges.findIndex(e => e.peer_fingerprint === fingerprint);
    if (idx === -1) throw new Error('Edge not found');

    // Record the break in history before removing
    const edge = graph.edges[idx];
    edge.trust_history.push({
      timestamp: new Date().toISOString(),
      from_level: edge.trust_level,
      to_level: 0,
      reason: `Trust break: ${reason}`,
      initiated_by: 'self',
    });

    // Remove from tribes
    for (const tribe of graph.tribes) {
      tribe.members = tribe.members.filter(m => m !== fingerprint);
      delete tribe.member_overrides[fingerprint];
    }

    graph.edges.splice(idx, 1);
    await this.saveGraph(graph);
  }

  async searchEdges(query: string): Promise<TrustEdge[]> {
    const graph = await this.loadGraph();
    const q = query.toLowerCase();
    return graph.edges.filter(e =>
      e.peer_name.toLowerCase().includes(q) ||
      e.peer_email.toLowerCase().includes(q) ||
      e.peer_fingerprint.toLowerCase().includes(q) ||
      e.tags.some(t => t.toLowerCase().includes(q))
    );
  }

  // --- Trust Level Management ---

  /**
   * Change trust level with mandatory reason. Records audit trail.
   * L3->L4 is always manual (enforced by caller, not here — this is the data layer).
   */
  async setTrustLevel(
    fingerprint: string,
    newLevel: TrustLevel,
    reason: string,
    initiatedBy: TrustEvent['initiated_by'] = 'self'
  ): Promise<TrustEdge> {
    const graph = await this.loadGraph();
    const idx = graph.edges.findIndex(e => e.peer_fingerprint === fingerprint);
    if (idx === -1) throw new Error('Edge not found');

    const edge = graph.edges[idx];
    const oldLevel = edge.trust_level;

    if (oldLevel === newLevel) return edge;

    edge.trust_history.push({
      timestamp: new Date().toISOString(),
      from_level: oldLevel,
      to_level: newLevel,
      reason,
      initiated_by: initiatedBy,
    });

    edge.trust_level = newLevel;
    edge.trust_since = new Date().toISOString();

    await this.saveGraph(graph);
    return edge;
  }

  /**
   * Record verification. Upgrades L1 -> L2 if currently at L1.
   */
  async verify(
    fingerprint: string,
    method: TrustEdge['verification']['method'],
    vouchers?: string[]
  ): Promise<TrustEdge> {
    const graph = await this.loadGraph();
    const idx = graph.edges.findIndex(e => e.peer_fingerprint === fingerprint);
    if (idx === -1) throw new Error('Edge not found');

    const edge = graph.edges[idx];
    edge.verification = {
      method,
      verified_at: new Date().toISOString(),
      vouchers,
    };

    // Auto-upgrade L1 -> L2 on verification
    if (edge.trust_level === 1) {
      edge.trust_history.push({
        timestamp: new Date().toISOString(),
        from_level: 1,
        to_level: 2,
        reason: `Verified via ${method}`,
        initiated_by: 'self',
      });
      edge.trust_level = 2;
      edge.trust_since = new Date().toISOString();
    }

    await this.saveGraph(graph);
    return edge;
  }

  /**
   * Update mutual state from a sync signal.
   */
  async updateMutualState(
    fingerprint: string,
    theirLevel: TrustLevel
  ): Promise<TrustEdge> {
    const graph = await this.loadGraph();
    const idx = graph.edges.findIndex(e => e.peer_fingerprint === fingerprint);
    if (idx === -1) throw new Error('Edge not found');

    const edge = graph.edges[idx];
    edge.mutual = {
      their_level_for_me: theirLevel,
      last_sync: new Date().toISOString(),
      reciprocal: edge.trust_level === theirLevel,
    };

    await this.saveGraph(graph);
    return edge;
  }

  // --- Tribes ---

  async createTribe(params: {
    name: string;
    members?: string[];
    trust_level?: TrustLevel;
    notes?: string;
  }): Promise<Tribe> {
    const graph = await this.loadGraph();

    const tribe: Tribe = {
      id: randomUUID(),
      name: params.name,
      members: params.members || [],
      trust_level: params.trust_level ?? 2,
      member_overrides: {},
      audit_chain: [],
      created_at: new Date().toISOString(),
      notes: params.notes || '',
    };

    graph.tribes.push(tribe);
    await this.saveGraph(graph);
    return tribe;
  }

  async addToTribe(
    tribeId: string,
    memberFingerprint: string,
    introducedBy: string,
    context: string
  ): Promise<Tribe> {
    const graph = await this.loadGraph();
    const tribe = graph.tribes.find(t => t.id === tribeId);
    if (!tribe) throw new Error('Tribe not found');

    if (tribe.members.includes(memberFingerprint)) {
      throw new Error('Already a member');
    }

    // Verify the member exists in our graph
    if (!graph.edges.some(e => e.peer_fingerprint === memberFingerprint)) {
      throw new Error('Must be a known contact before adding to tribe');
    }

    tribe.members.push(memberFingerprint);
    tribe.audit_chain.push({
      introduced: memberFingerprint,
      introduced_by: introducedBy,
      timestamp: new Date().toISOString(),
      context,
    });

    await this.saveGraph(graph);
    return tribe;
  }

  async removeFromTribe(tribeId: string, memberFingerprint: string): Promise<Tribe> {
    const graph = await this.loadGraph();
    const tribe = graph.tribes.find(t => t.id === tribeId);
    if (!tribe) throw new Error('Tribe not found');

    tribe.members = tribe.members.filter(m => m !== memberFingerprint);
    delete tribe.member_overrides[memberFingerprint];

    await this.saveGraph(graph);
    return tribe;
  }

  /**
   * Set individual trust override within a tribe.
   * Individual always overrides group.
   */
  async setTribeOverride(
    tribeId: string,
    memberFingerprint: string,
    level: TrustLevel
  ): Promise<Tribe> {
    const graph = await this.loadGraph();
    const tribe = graph.tribes.find(t => t.id === tribeId);
    if (!tribe) throw new Error('Tribe not found');

    tribe.member_overrides[memberFingerprint] = level;
    await this.saveGraph(graph);
    return tribe;
  }

  /**
   * Get effective trust level for a tribe member.
   * Individual override > group level.
   */
  getEffectiveTrustLevel(tribe: Tribe, memberFingerprint: string): TrustLevel {
    if (memberFingerprint in tribe.member_overrides) {
      return tribe.member_overrides[memberFingerprint];
    }
    return tribe.trust_level;
  }

  async getAllTribes(): Promise<Tribe[]> {
    const graph = await this.loadGraph();
    return graph.tribes;
  }

  async getTribe(tribeId: string): Promise<Tribe | null> {
    const graph = await this.loadGraph();
    return graph.tribes.find(t => t.id === tribeId) || null;
  }

  /**
   * Trace the introduction chain for a tribe member.
   */
  async traceIntroductionChain(
    tribeId: string,
    memberFingerprint: string
  ): Promise<IntroductionRecord[]> {
    const graph = await this.loadGraph();
    const tribe = graph.tribes.find(t => t.id === tribeId);
    if (!tribe) return [];

    // Walk the chain: who introduced this member, who introduced that person, etc.
    const chain: IntroductionRecord[] = [];
    let current = memberFingerprint;
    const visited = new Set<string>();

    while (!visited.has(current)) {
      visited.add(current);
      const record = tribe.audit_chain.find(r => r.introduced === current);
      if (!record) break;
      chain.push(record);
      current = record.introduced_by;
    }

    return chain;
  }

  // --- Graph Stats ---

  async getStats(): Promise<TrustGraph['stats']> {
    const graph = await this.loadGraph();
    return graph.stats;
  }

  async getFullGraph(): Promise<TrustGraph> {
    return this.loadGraph();
  }

  // --- Migration ---

  /**
   * Import legacy contacts into the trust graph.
   * Merges with existing edges (skips duplicates by fingerprint).
   */
  async importLegacyContacts(contacts: LegacyContact[]): Promise<{
    imported: number;
    skipped: number;
  }> {
    const graph = await this.loadGraph();
    const migrated = migrateContacts(contacts);

    let imported = 0;
    let skipped = 0;

    for (const edge of migrated) {
      if (graph.edges.some(e => e.peer_fingerprint === edge.peer_fingerprint)) {
        skipped++;
      } else {
        graph.edges.push(edge);
        imported++;
      }
    }

    if (imported > 0) {
      await this.saveGraph(graph);
    }

    return { imported, skipped };
  }

  // --- Export (privacy-filtered) ---

  /**
   * Export edges visible to a peer at a given trust level.
   * L1: name, fingerprint, public key only.
   * L4: full graph topology (no private notes).
   */
  async exportForPeer(peerLevel: TrustLevel): Promise<Partial<TrustEdge>[]> {
    const graph = await this.loadGraph();

    if (peerLevel <= 0) return [];

    return graph.edges.map(edge => {
      const base: Partial<TrustEdge> = {
        peer_fingerprint: edge.peer_fingerprint,
        peer_name: edge.peer_name,
        peer_public_key: edge.peer_public_key,
      };

      if (peerLevel >= 2) {
        base.verification = {
          method: edge.verification.method,
          verified_at: edge.verification.verified_at,
        };
      }

      if (peerLevel >= 3) {
        base.connection_channels = edge.connection_channels;
      }

      if (peerLevel >= 4) {
        base.trust_level = edge.trust_level;
        base.trust_since = edge.trust_since;
      }

      // Never export: notes, trust_history (private)
      return base;
    });
  }
}
