// src/lib/trust/trust-graph.ts
// Local-first encrypted trust graph.
// Binary trust: known or trusted. Trust decays without interaction.
// Storage: ~/.soverentity/<fingerprint>.trust.enc (PGP-encrypted JSON)

import { readFile, writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';
import { createMessage, encrypt, readMessage, decrypt, readKey, readPrivateKey, decryptKey } from 'openpgp';
import { randomUUID } from 'crypto';
import type {
  TrustEdge,
  TrustGraph,
  TrustEvent,
  Tribe,
  IntroductionRecord,
  LegacyContact,
} from './types';
import { isDecayed, migrateTrustLevel } from './types';

const DEFAULT_DECAY_DAYS = 730; // 2 years

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
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
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
      version: '2.0.0',
      owner_fingerprint: this.ownerFingerprint,
      edges: [],
      tribes: [],
      settings: {
        default_decay_days: DEFAULT_DECAY_DAYS,
      },
      stats: {
        total_contacts: 0,
        trusted_count: 0,
        known_count: 0,
        decayed_count: 0,
        last_modified: new Date().toISOString(),
      },
    };
  }

  private computeStats(graph: TrustGraph): TrustGraph['stats'] {
    let trusted = 0;
    let known = 0;
    let decayed = 0;

    for (const edge of graph.edges) {
      if (edge.trusted) {
        if (isDecayed(edge)) {
          decayed++;
        } else {
          trusted++;
        }
      } else {
        known++;
      }
    }

    return {
      total_contacts: graph.edges.length,
      trusted_count: trusted,
      known_count: known,
      decayed_count: decayed,
      last_modified: new Date().toISOString(),
    };
  }

  // --- Edge CRUD ---

  async addEdge(params: {
    peer_fingerprint: string;
    peer_name: string;
    peer_email: string;
    peer_public_key: string;
    trusted?: boolean;
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

    const now = new Date().toISOString();
    const trusted = params.trusted ?? false;

    const edge: TrustEdge = {
      id: randomUUID(),
      peer_fingerprint: params.peer_fingerprint,
      peer_name: params.peer_name,
      peer_email: params.peer_email,
      peer_public_key: params.peer_public_key,
      trusted,
      trusted_since: trusted ? now : null,
      last_interaction: now,
      decay_days: graph.settings.default_decay_days,
      trust_history: [{
        timestamp: now,
        action: trusted ? 'trust' : 'reverify' as const,
        reason: trusted ? 'Initial contact — trusted' : 'Contact added',
        initiated_by: 'self',
      }],
      verification: {
        method: 'none',
        verified_at: null,
      },
      mutual: {
        they_trust_me: null,
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

  async getTrustedEdges(): Promise<TrustEdge[]> {
    const graph = await this.loadGraph();
    return graph.edges.filter(e => e.trusted && !isDecayed(e));
  }

  async getKnownEdges(): Promise<TrustEdge[]> {
    const graph = await this.loadGraph();
    return graph.edges.filter(e => !e.trusted);
  }

  async getDecayedEdges(): Promise<TrustEdge[]> {
    const graph = await this.loadGraph();
    return graph.edges.filter(e => e.trusted && isDecayed(e));
  }

  async updateEdge(
    fingerprint: string,
    updates: Partial<Pick<TrustEdge, 'peer_name' | 'peer_email' | 'tags' | 'notes' | 'connection_channels' | 'agent_fingerprint' | 'contact_info' | 'decay_days'>>
  ): Promise<TrustEdge> {
    const graph = await this.loadGraph();
    const idx = graph.edges.findIndex(e => e.peer_fingerprint === fingerprint);
    if (idx === -1) throw new Error('Edge not found');

    graph.edges[idx] = { ...graph.edges[idx], ...updates };
    await this.saveGraph(graph);
    return graph.edges[idx];
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

  // --- Trust Operations ---

  /**
   * Vouch for someone — grant trust. Resets the decay clock.
   */
  async vouch(fingerprint: string, reason: string): Promise<TrustEdge> {
    const graph = await this.loadGraph();
    const idx = graph.edges.findIndex(e => e.peer_fingerprint === fingerprint);
    if (idx === -1) throw new Error('Edge not found');

    const edge = graph.edges[idx];
    const now = new Date().toISOString();

    edge.trusted = true;
    edge.trusted_since = edge.trusted_since || now;
    edge.last_interaction = now;

    edge.trust_history.push({
      timestamp: now,
      action: 'trust',
      reason,
      initiated_by: 'self',
    });

    await this.saveGraph(graph);
    return edge;
  }

  /**
   * Break trust. Visible to both sides on next sync.
   * The person drops from trusted to known. They'll notice.
   */
  async breakTrust(fingerprint: string, reason: string): Promise<TrustEdge> {
    const graph = await this.loadGraph();
    const idx = graph.edges.findIndex(e => e.peer_fingerprint === fingerprint);
    if (idx === -1) throw new Error('Edge not found');

    const edge = graph.edges[idx];
    const now = new Date().toISOString();

    edge.trusted = false;
    edge.trusted_since = null;

    edge.trust_history.push({
      timestamp: now,
      action: 'break',
      reason,
      initiated_by: 'self',
    });

    // Remove from tribes
    for (const tribe of graph.tribes) {
      tribe.members = tribe.members.filter(m => m !== fingerprint);
    }

    await this.saveGraph(graph);
    return edge;
  }

  /**
   * Process decay for all edges. Call periodically (e.g., on app open).
   * Returns edges that just decayed.
   */
  async processDecay(): Promise<TrustEdge[]> {
    const graph = await this.loadGraph();
    const decayed: TrustEdge[] = [];
    const now = new Date().toISOString();

    for (const edge of graph.edges) {
      if (edge.trusted && isDecayed(edge)) {
        // Check if we already recorded this decay
        const lastEvent = edge.trust_history[edge.trust_history.length - 1];
        if (lastEvent?.action !== 'decay') {
          edge.trusted = false;
          edge.trusted_since = null;
          edge.trust_history.push({
            timestamp: now,
            action: 'decay',
            reason: `No interaction for ${edge.decay_days} days`,
            initiated_by: 'system',
          });
          decayed.push(edge);
        }
      }
    }

    if (decayed.length > 0) {
      await this.saveGraph(graph);
    }

    return decayed;
  }

  /**
   * Reverify — any meaningful interaction resets the decay clock.
   * Can also restore trust after decay.
   */
  async reverify(fingerprint: string, restoreTrust: boolean = false): Promise<TrustEdge> {
    const graph = await this.loadGraph();
    const idx = graph.edges.findIndex(e => e.peer_fingerprint === fingerprint);
    if (idx === -1) throw new Error('Edge not found');

    const edge = graph.edges[idx];
    const now = new Date().toISOString();

    edge.last_interaction = now;

    if (restoreTrust && !edge.trusted) {
      edge.trusted = true;
      edge.trusted_since = now;
      edge.trust_history.push({
        timestamp: now,
        action: 'reverify',
        reason: 'Trust restored after reverification',
        initiated_by: 'self',
      });
    }

    await this.saveGraph(graph);
    return edge;
  }

  /**
   * Record verification method (email, QR, in-person, mutual vouch).
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
    edge.last_interaction = new Date().toISOString();

    await this.saveGraph(graph);
    return edge;
  }

  /**
   * Update mutual state from a sync signal.
   */
  async updateMutualState(
    fingerprint: string,
    theyTrustMe: boolean
  ): Promise<TrustEdge> {
    const graph = await this.loadGraph();
    const idx = graph.edges.findIndex(e => e.peer_fingerprint === fingerprint);
    if (idx === -1) throw new Error('Edge not found');

    const edge = graph.edges[idx];
    edge.mutual = {
      they_trust_me: theyTrustMe,
      last_sync: new Date().toISOString(),
      reciprocal: edge.trusted && theyTrustMe,
    };
    edge.last_interaction = new Date().toISOString();

    await this.saveGraph(graph);
    return edge;
  }

  /**
   * Remove a contact entirely (not just break trust — remove from graph).
   */
  async removeEdge(fingerprint: string, reason: string): Promise<void> {
    const graph = await this.loadGraph();
    const idx = graph.edges.findIndex(e => e.peer_fingerprint === fingerprint);
    if (idx === -1) throw new Error('Edge not found');

    // Remove from tribes
    for (const tribe of graph.tribes) {
      tribe.members = tribe.members.filter(m => m !== fingerprint);
    }

    graph.edges.splice(idx, 1);
    await this.saveGraph(graph);
  }

  // --- Tribes ---

  async createTribe(params: {
    name: string;
    members?: string[];
    notes?: string;
  }): Promise<Tribe> {
    const graph = await this.loadGraph();

    const tribe: Tribe = {
      id: randomUUID(),
      name: params.name,
      members: params.members || [],
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

    // Must be a known contact
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
    await this.saveGraph(graph);
    return tribe;
  }

  async getAllTribes(): Promise<Tribe[]> {
    const graph = await this.loadGraph();
    return graph.tribes;
  }

  async getTribe(tribeId: string): Promise<Tribe | null> {
    const graph = await this.loadGraph();
    return graph.tribes.find(t => t.id === tribeId) || null;
  }

  async traceIntroductionChain(
    tribeId: string,
    memberFingerprint: string
  ): Promise<IntroductionRecord[]> {
    const graph = await this.loadGraph();
    const tribe = graph.tribes.find(t => t.id === tribeId);
    if (!tribe) return [];

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

  // --- Settings ---

  async setDefaultDecayDays(days: number): Promise<void> {
    const graph = await this.loadGraph();
    graph.settings.default_decay_days = days;
    await this.saveGraph(graph);
  }

  // --- Stats ---

  async getStats(): Promise<TrustGraph['stats']> {
    const graph = await this.loadGraph();
    return this.computeStats(graph);
  }

  async getFullGraph(): Promise<TrustGraph> {
    return this.loadGraph();
  }

  // --- Export (privacy-filtered) ---

  /**
   * Export edges visible to a peer.
   * Known contacts see: name, fingerprint, public key.
   * Trusted contacts see: + verification, channels, contact info.
   * Never exported: notes, trust_history.
   */
  async exportForPeer(peerIsTrusted: boolean): Promise<Partial<TrustEdge>[]> {
    const graph = await this.loadGraph();

    if (!peerIsTrusted) {
      // Known peers get minimal info
      return graph.edges
        .filter(e => e.trusted && !isDecayed(e))
        .map(edge => ({
          peer_fingerprint: edge.peer_fingerprint,
          peer_name: edge.peer_name,
          peer_public_key: edge.peer_public_key,
        }));
    }

    // Trusted peers get more
    return graph.edges
      .filter(e => e.trusted && !isDecayed(e))
      .map(edge => ({
        peer_fingerprint: edge.peer_fingerprint,
        peer_name: edge.peer_name,
        peer_public_key: edge.peer_public_key,
        verification: {
          method: edge.verification.method,
          verified_at: edge.verification.verified_at,
        },
        connection_channels: edge.connection_channels,
      }));
  }

  // --- Migration ---

  /**
   * Import legacy contacts (flat or 5-level) into binary trust graph.
   */
  async importLegacyContacts(contacts: LegacyContact[]): Promise<{
    imported: number;
    skipped: number;
  }> {
    const graph = await this.loadGraph();
    const now = new Date().toISOString();
    let imported = 0;
    let skipped = 0;

    for (const contact of contacts) {
      if (graph.edges.some(e => e.peer_fingerprint === contact.fingerprint)) {
        skipped++;
        continue;
      }

      const trusted = migrateTrustLevel(contact.trust_level);

      const edge: TrustEdge = {
        id: contact.id || randomUUID(),
        peer_fingerprint: contact.fingerprint,
        peer_name: contact.name,
        peer_email: contact.email,
        peer_public_key: contact.public_key,
        trusted,
        trusted_since: trusted ? (contact.verified_at || contact.added_at) : null,
        last_interaction: contact.verified_at || contact.added_at,
        decay_days: graph.settings.default_decay_days,
        trust_history: [{
          timestamp: contact.added_at,
          action: trusted ? 'trust' as const : 'reverify' as const,
          reason: `Migrated from legacy (${contact.trust_level})`,
          initiated_by: 'self' as const,
        }],
        verification: {
          method: contact.verified_at ? 'email' : 'none',
          verified_at: contact.verified_at || null,
        },
        mutual: {
          they_trust_me: null,
          last_sync: null,
          reciprocal: false,
        },
        tags: contact.metadata?.tags || [],
        notes: contact.metadata?.notes || '',
        connection_channels: contact.metadata?.connection_method ? [contact.metadata.connection_method] : [],
        added_at: contact.added_at,
      };

      graph.edges.push(edge);
      imported++;
    }

    if (imported > 0) {
      await this.saveGraph(graph);
    }

    return { imported, skipped };
  }
}
