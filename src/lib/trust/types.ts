// src/lib/trust/types.ts
// Trust is binary: you know someone, or you trust them.
// Known = contact exists. Trusted = vouched.
// Trust decays over time without interaction. Default: 2 years.
// No levels. No tiers. No popularity contest.

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
    phones?: string[];
    emails?: string[];
    handles?: Record<string, string>;
    urls?: string[];
    verified_claims?: VerifiedClaim[];
    /** Local classical book — round-trip through vCard, never a living-wire field. */
    org?: string;
    title?: string;
    nickname?: string;
    bday?: string;
    adr?: string;
    extras?: Array<{ label: string; value: string }>;
  };
  // Trust — binary
  trusted: boolean;                     // vouched or not
  trusted_since: string | null;         // when trust was last granted (null = never trusted)
  last_interaction: string;             // last meaningful contact — decay clock starts here
  decay_days: number;                   // customizable per-edge, default from graph settings
  trust_history: TrustEvent[];          // full audit trail
  // Verification (legacy / channel claims — not a public "verified" badge)
  verification: {
    method: 'none' | 'email' | 'qr' | 'mutual_vouch' | 'in_person' | 'other_channel';
    verified_at: string | null;
    vouchers?: string[];                // fingerprints of people who vouched
  };
  /**
   * Owner-local: you confirmed this key is the person you mean.
   * Prerequisite for Trust on this device. NEVER publish / PSI-sync.
   */
  owner_verify?: {
    owner_verified_at: string;
    method: 'in_person' | 'other_channel';
  };
  // Mutual state
  mutual: {
    they_trust_me: boolean | null;      // do THEY trust me? (null = unknown)
    last_sync: string | null;           // last mutual state exchange
    reciprocal: boolean;                // do we both trust each other?
  };
  // Metadata
  tags: string[];
  notes: string;                        // private notes (never shared)
  connection_channels: string[];        // 'signal', 'email', 'telegram', etc.
  added_at: string;
  /** Owner-local mute (CUR-5). Never publish — strip on wire like tags. */
  blocked?: boolean;
  /**
   * Owner-local: you received a Distress packet about them (witnessed receipt).
   * Paints the vivre. NEVER publish.
   */
  distress_inbound?: boolean;
  /**
   * Fingerprints in YOUR book that this peer disclosed to you
   * (fleet `visible()` ∩ book). Absent until the fleet fills it — glass never infers.
   */
  disclosed_circle?: string[];
  /**
   * People in your book this peer also trusts (fleet PSI). Not transitive trust.
   * Drawn as a peer chord only when both sides are open-visibility mutuals
   * (see witnessedPeerTrustChords) — never inferred from owner tags.
   */
  they_trust?: string[];
  /**
   * Owner-local intent toward this peer: open visibility for trusted contacts.
   * Not a wire field. Combined with reciprocal trust + they_trust, this is
   * how a witnessed peer bond becomes visible on the glass.
   * how Sally↔Joe becomes visible on the glass.
   */
  open_visibility?: boolean;
  // Cairn bridge
  agent_fingerprint?: string;           // their cairn agent's key (if they use cairn)
  // Post-quantum public keys
  peer_pq_sig_public_key?: string;      // ML-DSA-87, base64
  peer_pq_kem_public_key?: string;      // ML-KEM-1024, base64
}

export interface VerifiedClaim {
  type: 'email' | 'phone' | 'domain' | 'handle';
  value: string;
  verified_at: string;
  method: string;                       // 'otp', 'dns-txt', 'mutual_vouch'
}

export interface TrustEvent {
  timestamp: string;
  action: 'trust' | 'break' | 'decay' | 'reverify';
  reason: string;
  initiated_by: 'self' | 'peer' | 'system';  // system = decay
}

// --- Trust Decay ---

/**
 * Check if trust has decayed (no interaction within decay_days).
 * Returns true if the edge is trusted but past its decay window.
 */
export function isDecayed(edge: TrustEdge): boolean {
  if (!edge.trusted) return false;
  const lastContact = new Date(edge.last_interaction).getTime();
  const now = Date.now();
  const decayMs = edge.decay_days * 24 * 60 * 60 * 1000;
  return (now - lastContact) > decayMs;
}

/**
 * Days remaining until trust decays. Negative = already decayed.
 */
export function daysUntilDecay(edge: TrustEdge): number {
  if (!edge.trusted) return 0;
  const lastContact = new Date(edge.last_interaction).getTime();
  const now = Date.now();
  const decayMs = edge.decay_days * 24 * 60 * 60 * 1000;
  const remaining = (lastContact + decayMs - now) / (24 * 60 * 60 * 1000);
  return Math.round(remaining);
}

// --- Trust Graph ---

export interface TrustGraph {
  version: string;
  owner_fingerprint: string;
  edges: TrustEdge[];
  tribes: Tribe[];
  settings: {
    default_decay_days: number;         // 730 = 2 years
  };
  stats: {
    total_contacts: number;
    trusted_count: number;
    known_count: number;
    decayed_count: number;
    last_modified: string;
  };
}

// --- Signals ---

export type TrustSignal =
  | { type: 'vouch';       subject: string; }
  | { type: 'concern';     subject: string; detail: string; }
  | { type: 'break';       subject: string; reason?: string; }
  | { type: 'introduce';   subject: string; pub_key: string; name: string; }
  | { type: 'sync';        trusted: boolean; }
  | { type: 'key_rotation'; old_fingerprint: string; new_fingerprint: string; }
  | { type: 'recovery_request'; shard_holders: string[]; };

export interface SignedSignal {
  payload: TrustSignal;
  from: string;              // sender fingerprint
  to: string;                // recipient fingerprint
  timestamp: string;
  signature: string;         // ED25519 signature of payload+to+timestamp
  pq_signature?: string;     // ML-DSA-87 signature (v0.2.0+)
}

// --- Groups / Tribes ---

export interface Tribe {
  id: string;
  name: string;
  members: string[];                    // member fingerprints
  audit_chain: IntroductionRecord[];    // who introduced whom
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
// Simple: known contacts get name/fingerprint/key.
// Trusted contacts get what you choose to share.
// Notes and history are never exported.

export const PRIVACY_FILTERS = {
  known: ['peer_name', 'peer_fingerprint', 'peer_public_key'],
  trusted: ['peer_name', 'peer_fingerprint', 'peer_public_key', 'connection_channels', 'contact_info'],
} as const;

// --- Migration from v1 (5-level system) ---

/** Legacy 5-level TrustLevel */
export type LegacyTrustLevel = 0 | 1 | 2 | 3 | 4;

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

/**
 * Map old 5-level or string trust to binary.
 * L0-L1 / 'unverified' = known (not trusted)
 * L2+ / 'verified'+ = trusted
 */
export function migrateTrustLevel(level: LegacyTrustLevel | string): boolean {
  if (typeof level === 'number') return level >= 2;
  return level === 'verified' || level === 'trusted';
}
