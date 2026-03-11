// src/lib/trust/types.ts
// TrustEdge data model — replaces flat Contact with graduated trust levels.
// Spec: autobots/specs/soverentity_trust_protocol.md (Archie, v2)

// --- Trust Levels ---

export type TrustLevel = 0 | 1 | 2 | 3 | 4;

export const TRUST_LABELS: Record<TrustLevel, string> = {
  0: 'stranger',
  1: 'known',
  2: 'verified',
  3: 'trusted',
  4: 'inner_circle',
};

// --- Core Types ---

export interface TrustEdge {
  id: string;
  // Who
  peer_fingerprint: string;
  peer_name: string;                    // display name YOU gave them
  peer_email: string;
  peer_public_key: string;
  // Contact details (encrypted, never shared without consent)
  contact_info?: {
    phone?: string;                     // phone number
    emails?: string[];                  // additional emails beyond peer_email
    handles?: Record<string, string>;   // 'signal' -> '@handle', 'telegram' -> '@handle', etc.
    urls?: string[];                    // personal sites, profiles
  };
  // Trust
  trust_level: TrustLevel;
  trust_since: string;                  // ISO timestamp of current level
  trust_history: TrustEvent[];          // full audit trail
  // Verification
  verification: {
    method: 'none' | 'email' | 'qr' | 'mutual_vouch' | 'in_person';
    verified_at: string | null;
    vouchers?: string[];                // fingerprints of L3+ who vouched
    verified_claims?: VerifiedClaim[];  // what has been proved
  };
  // Mutual state
  mutual: {
    their_level_for_me: TrustLevel | null;  // what THEY set (if they share it)
    last_sync: string | null;               // last mutual state exchange
    reciprocal: boolean;                    // are we at same level?
  };
  // Metadata
  tags: string[];
  notes: string;                        // private notes (never shared)
  connection_channels: string[];        // 'signal', 'email', 'telegram', etc.
  added_at: string;
  // Cairn bridge
  agent_fingerprint?: string;           // their cairn agent's key (if they use cairn)
  // Post-quantum public keys (if peer has them)
  peer_pq_sig_public_key?: string;      // ML-DSA-65, base64
  peer_pq_kem_public_key?: string;      // ML-KEM-768, base64
}

export interface VerifiedClaim {
  type: 'email' | 'phone' | 'domain' | 'handle';
  value: string;
  verified_at: string;
  method: string;                       // 'otp', 'dns-txt', 'mutual_vouch'
}

export interface TrustEvent {
  timestamp: string;
  from_level: TrustLevel;
  to_level: TrustLevel;
  reason: string;
  initiated_by: 'self' | 'peer' | 'signal';
}

// --- Trust Graph ---

export interface TrustGraph {
  version: string;
  owner_fingerprint: string;
  edges: TrustEdge[];
  tribes: Tribe[];
  stats: {
    total_contacts: number;
    by_level: Record<number, number>;
    last_modified: string;
  };
}

// --- Signals ---

export type TrustSignal =
  | { type: 'vouch';       subject: string; level: TrustLevel; }
  | { type: 'concern';     subject: string; detail: string; }
  | { type: 'break';       subject: string; severity: 'soft' | 'hard'; }
  | { type: 'upgrade';     subject: string; from: TrustLevel; to: TrustLevel; }
  | { type: 'sync';        my_level: TrustLevel; }
  | { type: 'introduce';   subject: string; pub_key: string; name: string; }
  | { type: 'key_rotation'; old_fingerprint: string; new_fingerprint: string; }
  | { type: 'recovery_request'; shard_holders: string[]; };

export interface SignedSignal {
  payload: TrustSignal;
  from: string;              // sender fingerprint
  to: string;                // recipient fingerprint
  timestamp: string;
  signature: string;         // ED25519 signature of payload+to+timestamp
  pq_signature?: string;     // ML-DSA-65 signature (v0.2.0+)
}

// --- Groups / Tribes ---

export interface Tribe {
  id: string;
  name: string;
  members: string[];                    // member fingerprints
  trust_level: TrustLevel;             // your trust of the GROUP
  member_overrides: Record<string, TrustLevel>;  // individual overrides
  audit_chain: IntroductionRecord[];   // who introduced whom
  created_at: string;
  notes: string;
}

export interface IntroductionRecord {
  introduced: string;          // fingerprint of who was introduced
  introduced_by: string;       // fingerprint of who did the introducing
  timestamp: string;
  context: string;             // "met at conference", "online collab", etc.
}

// --- Privacy Filters ---

export const PRIVACY_FILTERS: Record<TrustLevel, string[]> = {
  0: [],
  1: ['name', 'fingerprint', 'public_key'],
  2: ['name', 'fingerprint', 'public_key', 'verification_status', 'mutual_count'],
  3: ['name', 'fingerprint', 'public_key', 'verification_status', 'mutual_contacts', 'connection_channels'],
  4: ['name', 'fingerprint', 'public_key', 'verification_status', 'mutual_contacts', 'connection_channels', 'graph_topology'],
};

// --- Migration ---

/** Legacy Contact type (pre-TrustEdge) */
export interface LegacyContact {
  id: string;
  name: string;
  email: string;
  fingerprint: string;
  public_key: string;
  trust_level: 'unverified' | 'verified' | 'trusted';
  added_at: string;
  verified_at?: string;
  metadata?: {
    notes?: string;
    tags?: string[];
    connection_method?: 'manual' | 'qr' | 'burner_link' | 'mutual';
    mutual_contacts?: string[];
  };
}

export const LEGACY_TRUST_MAP: Record<string, TrustLevel> = {
  'unverified': 1,
  'verified': 2,
  'trusted': 3,
};
