/**
 * Grow Gate — glass holding room for Grow arrivals.
 *
 * Arrive (solicited TOFU) → Gate. Admit → Known star. Verify = private key-check.
 * Trust is mutual and is NOT granted here.
 *
 * Giver-side: the return-channel still verifies the joiner-response (fleet crypto unchanged)
 * and consumes the issued-code slot. The joiner is NOT addContact'd until Admit.
 * Joiner-side: remote confirm enqueues the giver here; in-person confirm admits+verifies locally.
 *
 * Identity forge/restore "Gate" (SoverentityFrontend) is a different machine.
 */

import {
  addContact,
  enqueueGateArrival,
  getContactByFingerprint,
  getGateArrival,
  issuedCodeChannel,
  markAcceptedInMap,
  recordAcceptedJoiner,
  removeGateArrival,
  type ContactRecord,
  type GateArrival,
  type GrowMintChannel,
  type IssuedCodeMap,
} from '@/lib/identity/client-store';
import { emitContactChange } from '@/lib/contacts/contact-events';
import { ownerVerifyPersistPatch } from '@/lib/trust/trust-recipe';
import type { PendingJoiner } from '@/lib/trust/joiner-response';

export type { GateArrival, GrowMintChannel };

export const GATE_COPY = {
  title: 'Gate',
  waiting: 'Waiting at the Gate',
  empty: 'No one waiting. Remote joiners land here until you admit them.',
  admit: 'Admit as Known',
  dismiss: 'Dismiss',
  inPerson: 'In person',
  remote: 'Remote',
  inPersonHint:
    'Single-use. Mint this when they are in front of you. After they join, generate a new code.',
  remoteHint: 'They wait at the Gate until you admit them as Known. Verify stays yours.',
  joinPresence: 'Were you with them?',
  joinTogether: 'We were together',
  joinRemote: 'I joined remotely',
  joinTogetherHint:
    'This records that you checked the key together. It does not prove who they are in the world.',
  joinRemoteHint: 'They wait at your Gate. Known comes when you admit them.',
  latticeRemote: 'They wait at your Gate — not a star yet. Open Grow to admit them.',
  latticeTogether: 'They are a star you Know. You marked this key on this device.',
  spentInPerson: 'This in-person code was used. Generate a new one for the next person.',
  regen: 'Generate a new code',
  groupLabel: 'Group (optional)',
  notesLabel: 'Note (optional)',
  verifyNone: 'Don’t mark verify yet',
  provenance: 'Joined from',
} as const;

/** Clamp an attacker-typed display name for Gate / admit (defense-in-depth, not XSS). */
export function clampArrivalName(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  let out = '';
  for (const ch of raw) {
    const c = ch.codePointAt(0) ?? 0;
    if (c >= 0x20 && c !== 0x7f && (c < 0x80 || c > 0x9f)) out += ch;
  }
  return out.trim().slice(0, 80);
}

export function parseTagList(raw: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const part of String(raw || '').split(/[,;\n]/)) {
    const t = part.trim().slice(0, 32);
    if (!t || seen.has(t.toLowerCase())) continue;
    seen.add(t.toLowerCase());
    out.push(t);
    if (out.length >= 12) break;
  }
  return out;
}

/** Belt-and-suspenders: a contact accidentally flagged grow_gate is not a Galaxy star. */
export function isGrowGateRecord(c: { metadata?: { grow_gate?: unknown } } | null | undefined): boolean {
  return c?.metadata?.grow_gate === true;
}

export function starsOnly<T extends { metadata?: { grow_gate?: unknown } }>(contacts: T[]): T[] {
  return contacts.filter((c) => !isGrowGateRecord(c));
}

export type AdmitOptions = {
  name?: string;
  tags?: string[];
  notes?: string;
  verify?: 'in_person' | 'other_channel' | null;
};

export function buildAdmitRecord(
  arrival: GateArrival,
  opts: AdmitOptions = {},
): Omit<ContactRecord, 'id' | 'added_at' | 'owner_fingerprint'> {
  const name = clampArrivalName(opts.name ?? arrival.displayName) || clampArrivalName(arrival.displayName) || 'Unknown';
  const tags = (opts.tags || []).map((t) => t.trim()).filter(Boolean).slice(0, 12);
  const notes = String(opts.notes || '').slice(0, 2000);
  const localMeta: Record<string, unknown> = {
    tags,
    notes,
    grow_invite_nonce: arrival.inviteNonce,
    grow_mint_channel: arrival.mintChannel,
  };
  const verifyPatch = opts.verify ? ownerVerifyPersistPatch(localMeta, opts.verify) : null;
  const rec: Omit<ContactRecord, 'id' | 'added_at' | 'owner_fingerprint'> = {
    name,
    fingerprint: arrival.fingerprint,
    public_key: arrival.publicKeyArmored,
    trust_level: 'known',
    email: '',
    epoch: arrival.epoch,
    version: 0,
    tags,
    notes,
    metadata: verifyPatch?.metadata ?? localMeta,
  };
  if (arrival.pqKemPublicKey) rec.pq_kem_public_key = arrival.pqKemPublicKey;
  if (arrival.pqSigPublicKey) rec.pq_sig_public_key = arrival.pqSigPublicKey;
  if (verifyPatch) rec.owner_verify = verifyPatch.owner_verify;
  return rec;
}

export async function admitGateArrival(
  ownerFp: string,
  arrival: GateArrival,
  opts: AdmitOptions = {},
): Promise<ContactRecord> {
  const existing = await getContactByFingerprint(ownerFp, arrival.fingerprint);
  let record: ContactRecord;
  if (existing) {
    record = existing;
  } else {
    record = await addContact(ownerFp, buildAdmitRecord(arrival, opts));
  }
  await removeGateArrival(ownerFp, arrival.fingerprint);
  emitContactChange({ ids: [record.id], reason: 'ui-edit' });
  return record;
}

export async function dismissGateArrival(ownerFp: string, peerFp: string): Promise<void> {
  await removeGateArrival(ownerFp, peerFp);
  emitContactChange({ ids: [], reason: 'ui-edit' });
}

function pqToB64(u8?: Uint8Array): string | undefined {
  if (!u8 || u8.length === 0) return undefined;
  let binary = '';
  for (let i = 0; i < u8.length; i++) binary += String.fromCharCode(u8[i]);
  if (typeof btoa === 'function') return btoa(binary);
  return Buffer.from(u8).toString('base64');
}

export function arrivalFromPendingJoiner(
  pj: PendingJoiner,
  mintChannel: GrowMintChannel,
): GateArrival {
  const arrival: GateArrival = {
    fingerprint: pj.fingerprint,
    displayName: clampArrivalName(pj.displayName),
    publicKeyArmored: pj.publicKeyArmored,
    epoch: pj.epoch,
    inviteNonce: pj.inviteNonce,
    mintChannel,
    arrivedAt: pj.ts || new Date().toISOString(),
    direction: 'inbound_joiner',
  };
  const sig = pqToB64(pj.pqSigningPublicKey);
  if (sig) arrival.pqSigPublicKey = sig;
  return arrival;
}

/**
 * Giver consume: persist at the Gate, consume the code slot, do NOT addContact.
 * Injected store in tests; production passes the real IndexedDB helpers.
 */
export async function acceptJoinerAtGate(
  ownerFp: string,
  pj: PendingJoiner,
  codes: IssuedCodeMap,
  store: {
    getContactByFingerprint: typeof getContactByFingerprint;
    getGateArrival: typeof getGateArrival;
    enqueueGateArrival: typeof enqueueGateArrival;
    recordAcceptedJoiner: typeof recordAcceptedJoiner;
  } = {
    getContactByFingerprint,
    getGateArrival,
    enqueueGateArrival,
    recordAcceptedJoiner,
  },
): Promise<{ ignited: boolean } | null> {
  const existing = await store.getContactByFingerprint(ownerFp, pj.fingerprint);
  if (existing) {
    markAcceptedInMap(codes, ownerFp, pj.inviteNonce, pj.fingerprint);
    await store.recordAcceptedJoiner(ownerFp, pj.inviteNonce, pj.fingerprint);
    return null;
  }
  const waiting = await store.getGateArrival(ownerFp, pj.fingerprint);
  if (waiting) {
    markAcceptedInMap(codes, ownerFp, pj.inviteNonce, pj.fingerprint);
    await store.recordAcceptedJoiner(ownerFp, pj.inviteNonce, pj.fingerprint);
    return null;
  }
  const mintChannel = issuedCodeChannel(codes, ownerFp, pj.inviteNonce);
  const arrival = arrivalFromPendingJoiner(pj, mintChannel);
  await store.enqueueGateArrival(ownerFp, arrival);
  markAcceptedInMap(codes, ownerFp, pj.inviteNonce, pj.fingerprint);
  await store.recordAcceptedJoiner(ownerFp, pj.inviteNonce, pj.fingerprint);
  emitContactChange({ ids: [], reason: 'live-apply' });
  return { ignited: true };
}

export function joinerPersistPlan(
  presence: 'in_person' | 'remote' | null,
  alreadyInBook: boolean,
): 'already-known' | 'admit-verified' | 'enqueue-gate' | 'need-presence' {
  if (alreadyInBook) return 'already-known';
  if (presence === 'in_person') return 'admit-verified';
  if (presence === 'remote') return 'enqueue-gate';
  return 'need-presence';
}
