// src/lib/connect/add-logic.ts
//
// Connect-UX add-logic seam (CURSOR_QUEUE.md #3 — one-step grow-link).
//
// The render layer NEVER implements crypto / gate / trust plumbing — it calls
// this interface. Apollo wires the real grow-link resolve + add logic
// post-flip; this module is the typed contract the UI is built and tested
// against NOW.
//
// What is real today vs. what is a stub:
//   • parseConnectLink — REAL + TOTAL (never throws, never echoes the fragment).
//   • resolve        — REAL for fragment-bearing /c/{code}#{key} links (the
//                      shipped invite shape: blind-relay GET + AES-GCM decrypt
//                      via resolveRelay + the classifyImportedCard anti-spoof
//                      gate). FRAGMENT-LESS bare-code links are the post-flip
//                      newcomer-card format Apollo owns — they refuse
//                      'unwired', honestly, never a fake success.
//   • landInGate     — REAL (enqueueGateArrival — the existing holding room).
//   • promoteToKnown — REAL (admitGateArrival — the existing consent tap).
//
// INVARIANTS this interface exists to hold (queue §"TRUST-MODEL INVARIANTS"):
//   1. Gate-not-Known on arrival — resolve+land NEVER writes a contact.
//   2. Adding is LOCAL + one-sided — land/promote touch only the owner store.
//   3. No mutual-edge fabrication — nothing here asserts mutuality.
//   4. The link carries the newcomer's consent-to-be-added — an invitation,
//      not a capture. resolve only reads what the link author published.
//   5. Trust-level on promote is the user's explicit choice — promote is only
//      ever called from an explicit tap; never chained from resolve.

import {
  enqueueGateArrival,
  getContactByFingerprint,
  getGateArrival,
  type ContactRecord,
  type GateArrival,
} from '@/lib/identity/client-store';
import { resolveRelay } from '@/lib/sync/relay';
import { classifyImportedCard } from '@/lib/identity/identity-card-sign';
import {
  admitGateArrival,
  clampArrivalName,
  type AdmitOptions,
} from '@/lib/trust/grow-gate';

/** Entity attestation class carried on a shareable card. 'unknown' = not-yet-attested
 *  (an honest absence — never a guess, never a 'verified' claim). */
export type ConnectEntityType = 'agent' | 'human' | 'organization' | 'unknown';

/** The newcomer card a resolved connect link yields — the data shape the
 *  post-flip resolver is bound to (name/handle + identity pubkey + mailbox
 *  pointer, per the queue spec). Everything here is UNTRUSTED card data:
 *  render escaped + bounded, never innerHTML. */
export interface ConnectLinkCard {
  /** canonical 64-hex — derives from the keys the card presents (anti-spoof). */
  fingerprint: string;
  displayName: string;
  entityType: ConnectEntityType;
  publicKeyArmored: string;
  pqKemPublicKey?: string;
  pqSigPublicKey?: string;
  /** Opaque relay/mailbox hint. The UI carries, never parses. */
  mailboxPointer?: unknown;
  /** The /c/{code} this card resolved from (gate provenance). */
  inviteNonce: string;
}

export interface ConnectLinkParse {
  code: string;
  /** Present on today's invite links; absent on the post-flip bare-code format. */
  keyFragment?: string;
}

export type ConnectResolveRefusal =
  | 'bad-link' // input doesn't carry a plausible /c/{code}
  | 'resolve-failed' // transport refused / link expired / blob malformed
  | 'unverified-card' // fingerprint doesn't derive from presented keys (anti-spoof)
  | 'not-a-card' // resolved fine, but the payload isn't a shareable card (e.g. a shard)
  | 'unwired'; // fragment-less link — post-flip format, not yet wired (Apollo)

export type ConnectResolveResult =
  | { ok: true; card: ConnectLinkCard }
  | { ok: false; refusal: ConnectResolveRefusal; detail?: string };

export type GateLanding =
  | { kind: 'landed'; arrival: GateArrival } // newcomer now waits in the owner's Gate (pending)
  | { kind: 'already-gate'; arrival: GateArrival } // same fingerprint already waiting — idempotent
  | { kind: 'already-known' } // already a contact — nothing to land
  | { kind: 'refused' }; // unbindable input (no owner / no fingerprint) — nothing written

export interface ConnectAddLogic {
  /**
   * TOTAL parse (never throws, never logs): accepts a full
   * `svrnty.is/c/{code}[#{key}]` link (any accepted host, with or without a
   * scheme) or the bare code itself. Fragment is OPTIONAL — its absence is a
   * resolve-time refusal ('unwired'), not a parse failure.
   */
  parseConnectLink(input: unknown): ConnectLinkParse | null;
  /** Resolve the link to the newcomer's shareable card (one GET + classify). */
  resolve(link: ConnectLinkParse): Promise<ConnectResolveResult>;
  /**
   * Land the resolved newcomer in the owner's Gate (pending). Writes the
   * holding-room record ONLY — never a contact, never a wire message.
   * Idempotent on fingerprint.
   */
  landInGate(ownerFp: string, card: ConnectLinkCard): Promise<GateLanding>;
  /**
   * The single consent action: Gate → Known. Called ONLY from an explicit
   * owner tap (invariant 5) — never implicitly from resolve/land.
   */
  promoteToKnown(
    ownerFp: string,
    arrival: GateArrival,
    opts?: AdmitOptions,
  ): Promise<ContactRecord>;
}

// ---------------------------------------------------------------------------
// parse — the untrusted-input edge. Mirrors parseInviteUrl's host discipline:
// accepted hosts = the app host + the known svrnty hosts; path must be exactly
// /c/<code>; code is URL-safe + bounded. DIFFERS deliberately on the fragment:
// a connect link may carry no key (the post-flip bare-code format), so the
// fragment is captured-if-present, not required.
// ---------------------------------------------------------------------------

const KNOWN_HOSTS = new Set(['svrnty.is', 'www.svrnty.is', 'dev.svrnty.is']);
const CODE_RE = /^[A-Za-z0-9_-]{1,64}$/;
// Bare-code input: the same alphabet as a path segment, no scheme, no '/'.
const BARE_CODE_RE = /^[A-Za-z0-9_-]{1,64}$/;

function hostAllowed(hostname: string): boolean {
  if (KNOWN_HOSTS.has(hostname)) return true;
  try {
    if (typeof window !== 'undefined' && window.location && window.location.hostname === hostname) {
      return true;
    }
  } catch {
    /* non-browser context — known-host allowlist only */
  }
  return false;
}

function parseConnectLinkImpl(input: unknown): ConnectLinkParse | null {
  if (typeof input !== 'string') return null;
  const raw = input.trim();
  if (!raw) return null;
  // Bare code — no URL machinery, no fragment.
  if (BARE_CODE_RE.test(raw) && !raw.includes('/') && !raw.includes('#')) {
    return { code: raw };
  }
  try {
    const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw);
    const url = new URL(hasScheme ? raw : `https://${raw}`);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    if (!hostAllowed(url.hostname)) return null;
    const m = url.pathname.match(/^\/c\/([^/]+)\/?$/);
    if (!m) return null;
    const code = decodeURIComponent(m[1]);
    if (!CODE_RE.test(code)) return null;
    const keyFragment = url.hash.startsWith('#') ? url.hash.slice(1) : '';
    // Fragment present → bound it exactly like the invite path (len cap, no
    // whitespace). We never echo it back out of this module.
    if (keyFragment && (keyFragment.length > 1024 || /\s/.test(keyFragment))) {
      return null;
    }
    return keyFragment ? { code, keyFragment } : { code };
  } catch {
    return null; // TOTAL — never throw on untrusted input
  }
}

// ---------------------------------------------------------------------------
// default implementation — thin composition over existing vetted plumbing.
// Every dependency is injectable so each rule has a test that can fail.
// ---------------------------------------------------------------------------

export interface ConnectDeps {
  resolveRelay: typeof resolveRelay;
  classifyImportedCard: typeof classifyImportedCard;
  enqueueGateArrival: typeof enqueueGateArrival;
  getContactByFingerprint: typeof getContactByFingerprint;
  getGateArrival: typeof getGateArrival;
  admitGateArrival: typeof admitGateArrival;
}

const ENTITY_TYPES: ReadonlySet<string> = new Set(['agent', 'human', 'organization']);

function normalizeEntityType(raw: unknown): ConnectEntityType {
  return typeof raw === 'string' && ENTITY_TYPES.has(raw)
    ? (raw as ConnectEntityType)
    : 'unknown'; // not-yet-attested — an honest absence, never a guess
}

export function createConnectAddLogic(deps: Partial<ConnectDeps> = {}): ConnectAddLogic {
  const d: ConnectDeps = {
    resolveRelay,
    classifyImportedCard,
    enqueueGateArrival,
    getContactByFingerprint,
    getGateArrival,
    admitGateArrival,
    ...deps,
  };

  return {
    parseConnectLink: parseConnectLinkImpl,

    async resolve(link) {
      if (!link?.code || !CODE_RE.test(link.code)) {
        return { ok: false, refusal: 'bad-link' };
      }
      // Fragment-less links are the post-flip newcomer-card format — Apollo
      // owns that wire. Refuse honestly; never fake a card.
      if (!link.keyFragment) {
        return { ok: false, refusal: 'unwired' };
      }
      let decrypted: string;
      try {
        decrypted = await d.resolveRelay(link.code, link.keyFragment);
      } catch (err) {
        return {
          ok: false,
          refusal: 'resolve-failed',
          detail: String((err as Error)?.message ?? err).slice(0, 200),
        };
      }
      let parsed;
      try {
        parsed = JSON.parse(decrypted);
      } catch {
        return { ok: false, refusal: 'resolve-failed', detail: 'unreadable-card' };
      }
      // A link that resolves to a non-card payload (e.g. a recovery shard) is
      // honest, not a verification failure — it belongs on its own route.
      // Shape-based: a shareable card carries a fingerprint or a public key
      // (flat or under .identity); a shard/other payload carries neither there.
      const cardShape = parsed?.identity || parsed;
      const looksCard =
        cardShape &&
        typeof cardShape === 'object' &&
        (typeof cardShape.fingerprint === 'string' ||
          typeof cardShape.peer_fingerprint === 'string' ||
          typeof cardShape.public_key === 'string' ||
          typeof cardShape.publicKey === 'string');
      if (!looksCard) {
        return { ok: false, refusal: 'not-a-card' };
      }
      // The anti-spoof gate (unchanged): fingerprint must derive from the keys
      // the card presents, else the card is refused outright.
      const disp = await d.classifyImportedCard(parsed);
      if (!disp.importClassical) {
        return { ok: false, refusal: 'unverified-card' };
      }
      const p = parsed?.identity || parsed;
      const fingerprint = String(p.fingerprint || p.peer_fingerprint || '');
      if (!fingerprint) return { ok: false, refusal: 'unverified-card' };
      const card: ConnectLinkCard = {
        fingerprint,
        displayName: clampArrivalName(p.display_name || p.name || p.peer_name || ''),
        entityType: normalizeEntityType(p.entity_type ?? p.entityType),
        publicKeyArmored: String(p.public_key || p.publicKey || ''),
        inviteNonce: link.code,
        ...(disp.pq
          ? {
              pqKemPublicKey: disp.pq.pq_kem_public_key,
              pqSigPublicKey: disp.pq.pq_sig_public_key,
            }
          : {}),
        ...(disp.deviceMailbox ? { mailboxPointer: disp.deviceMailbox } : {}),
      };
      return { ok: true, card };
    },

    async landInGate(ownerFp, card) {
      if (!ownerFp || !card?.fingerprint) return { kind: 'refused' };
      const existing = await d.getContactByFingerprint(ownerFp, card.fingerprint);
      if (existing) return { kind: 'already-known' };
      const waiting = await d.getGateArrival(ownerFp, card.fingerprint);
      if (waiting) return { kind: 'already-gate', arrival: waiting };
      const arrival: GateArrival = {
        fingerprint: card.fingerprint,
        displayName: clampArrivalName(card.displayName) || 'Unknown',
        publicKeyArmored: card.publicKeyArmored,
        epoch: 0,
        inviteNonce: card.inviteNonce,
        mintChannel: 'remote', // a link is remote arrival by definition
        arrivedAt: new Date().toISOString(),
        direction: 'scanned_giver', // the newcomer's card, resolved and gated
        ...(card.pqKemPublicKey ? { pqKemPublicKey: card.pqKemPublicKey } : {}),
        ...(card.pqSigPublicKey ? { pqSigPublicKey: card.pqSigPublicKey } : {}),
      };
      await d.enqueueGateArrival(ownerFp, arrival);
      return { kind: 'landed', arrival };
    },

    async promoteToKnown(ownerFp, arrival, opts) {
      return d.admitGateArrival(ownerFp, arrival, opts);
    },
  };
}
