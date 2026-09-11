/**
 * Owner card methods + lenses — local-only disclosure faces.
 *
 * One identity (one fingerprint, one QR/link). A lens is an assortment of
 * YOUR methods with a preferred channel — "business email" vs "festival Instagram".
 * Extra methods are NOT on the signed identity-exchange card yet (fleet schema).
 * Glass stores intent here; share still carries signed name+key+email.
 */

import { loadLocalMethods } from '@/components/identity/local-methods';
import { SVRNTY_DOMAIN } from '@/lib/config/domain';

export type OwnerMethodKind =
  | 'email'
  | 'phone'
  | 'signal'
  | 'telegram'
  | 'instagram'
  | 'whatsapp'
  | 'site'
  | 'url'
  | 'custom';

/** Typed custom fields — additive, no signed-card schema change. */
export type OwnerCustomValueType = 'text' | 'url' | 'date' | 'phone' | 'email';

export const OWNER_CUSTOM_VALUE_TYPES: Array<{ type: OwnerCustomValueType; label: string }> = [
  { type: 'text', label: 'Text' },
  { type: 'url', label: 'Link' },
  { type: 'date', label: 'Date' },
  { type: 'phone', label: 'Phone' },
  { type: 'email', label: 'Email' },
];

export type OwnerMethod = {
  id: string;
  kind: OwnerMethodKind;
  value: string;
  label?: string;
  /** For kind === 'custom' — how the value is entered. */
  valueType?: OwnerCustomValueType;
  /**
   * Relay host this method intends to be reached through (local intent).
   * Default is the deployment domain. Routing.update (fleet) is not wired —
   * glass records the host; it does not move delivery.
   */
  relay?: string;
};

/** Soft size bound (Athena storage fact): avatars referenced, never inlined. */
export const OWNER_CARD_SOFT_CAP_BYTES = 16 * 1024;

export type OwnerLens = {
  id: string;
  name: string;
  methodIds: string[];
  preferredMethodId?: string;
};

export type OwnerCardBag = {
  methods: OwnerMethod[];
  lenses: OwnerLens[];
  defaultLensId?: string;
};

export const OWNER_METHOD_KINDS: Array<{ kind: OwnerMethodKind; label: string }> = [
  { kind: 'email', label: 'Email' },
  { kind: 'phone', label: 'Phone' },
  { kind: 'signal', label: 'Signal' },
  { kind: 'telegram', label: 'Telegram' },
  { kind: 'instagram', label: 'Instagram' },
  { kind: 'whatsapp', label: 'WhatsApp' },
  { kind: 'site', label: 'Site' },
  { kind: 'url', label: 'Link' },
  { kind: 'custom', label: 'Custom' },
];

const bagKey = (fingerprint: string) =>
  `svrnty.owner-card.${fingerprint.replace(/[^0-9a-fA-F]/g, '').toLowerCase()}`;

function nid(prefix: string) {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}`;
}

export function emptyOwnerCard(): OwnerCardBag {
  const everyone: OwnerLens = { id: 'lens-everyone', name: 'Everyone', methodIds: [] };
  return { methods: [], lenses: [everyone], defaultLensId: everyone.id };
}

/** Merge identity email + legacy signal/site bag into the owner card. */
export function hydrateOwnerCard(
  fingerprint: string,
  email?: string,
): OwnerCardBag {
  const stored = loadOwnerCardRaw(fingerprint);
  const legacy = loadLocalMethods(fingerprint);
  let bag = stored || emptyOwnerCard();

  const ensure = (kind: OwnerMethodKind, value: string | undefined, id: string) => {
    const v = (value || '').trim();
    if (!v) return;
    const existing = bag.methods.find((m) => m.id === id || (m.kind === kind && m.value === v));
    if (existing) {
      existing.value = v;
      return;
    }
    bag.methods.push({ id, kind, value: v });
  };

  ensure('email', email, 'm-email');
  ensure('signal', legacy.signal, 'm-signal');
  ensure('site', legacy.site, 'm-site');

  if (!bag.lenses.length) {
    bag.lenses = [{ id: 'lens-everyone', name: 'Everyone', methodIds: bag.methods.map((m) => m.id) }];
    bag.defaultLensId = bag.lenses[0].id;
  }
  const everyone = bag.lenses.find((l) => l.id === bag.defaultLensId) || bag.lenses[0];
  if (everyone) {
    const have = new Set(everyone.methodIds);
    for (const m of bag.methods) {
      if (!have.has(m.id)) everyone.methodIds.push(m.id);
    }
    if (!everyone.preferredMethodId && everyone.methodIds.length) {
      everyone.preferredMethodId = everyone.methodIds[0];
    }
  }
  return bag;
}

function storage(): {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
} | null {
  try {
    const ls = (globalThis as { localStorage?: Storage }).localStorage;
    return ls ?? null;
  } catch {
    return null;
  }
}

function loadOwnerCardRaw(fingerprint: string): OwnerCardBag | null {
  const ls = storage();
  if (!ls) return null;
  try {
    const raw = ls.getItem(bagKey(fingerprint));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as OwnerCardBag;
    if (!Array.isArray(parsed.methods) || !Array.isArray(parsed.lenses)) return null;
    return parsed;
  } catch {
    return null;
  }
}

export type SaveOwnerCardResult =
  | { ok: true; bag: OwnerCardBag; bytes: number }
  | { ok: false; reason: 'over-cap' | 'inlined-binary'; bag: OwnerCardBag; bytes: number };

export function ownerCardBytes(bag: OwnerCardBag): number {
  return new TextEncoder().encode(JSON.stringify(bag)).length;
}

/** Reject data:/javascript: values — avatars must be references, never inlined. */
export function ownerCardHasInlinedBinary(bag: OwnerCardBag): boolean {
  const bad = (s?: string) => !!s && /^\s*(data|javascript):/i.test(s);
  return bag.methods.some((m) => bad(m.value) || bad(m.relay));
}

export function saveOwnerCard(fingerprint: string, bag: OwnerCardBag): SaveOwnerCardResult {
  const bytes = ownerCardBytes(bag);
  if (ownerCardHasInlinedBinary(bag)) {
    return { ok: false, reason: 'inlined-binary', bag, bytes };
  }
  if (bytes > OWNER_CARD_SOFT_CAP_BYTES) {
    return { ok: false, reason: 'over-cap', bag, bytes };
  }
  const ls = storage();
  if (!ls) return { ok: true, bag, bytes };
  ls.setItem(bagKey(fingerprint), JSON.stringify(bag));
  return { ok: true, bag, bytes };
}

export function addOwnerMethod(
  bag: OwnerCardBag,
  kind: OwnerMethodKind,
  value = '',
  label?: string,
  extra?: Pick<OwnerMethod, 'valueType' | 'relay'>,
): OwnerCardBag {
  const method: OwnerMethod = {
    id: nid('m'),
    kind,
    value,
    label,
    valueType: kind === 'custom' ? extra?.valueType || 'text' : extra?.valueType,
    relay: extra?.relay,
  };
  const methods = [...bag.methods, method];
  const lenses = bag.lenses.map((l) =>
    l.id === bag.defaultLensId ? { ...l, methodIds: [...l.methodIds, method.id] } : l,
  );
  return { ...bag, methods, lenses };
}

export function removeOwnerMethod(bag: OwnerCardBag, id: string): OwnerCardBag {
  return {
    ...bag,
    methods: bag.methods.filter((m) => m.id !== id),
    lenses: bag.lenses.map((l) => ({
      ...l,
      methodIds: l.methodIds.filter((x) => x !== id),
      preferredMethodId: l.preferredMethodId === id ? undefined : l.preferredMethodId,
    })),
  };
}

export function updateOwnerMethod(
  bag: OwnerCardBag,
  id: string,
  patch: Partial<OwnerMethod>,
): OwnerCardBag {
  return {
    ...bag,
    methods: bag.methods.map((m) => (m.id === id ? { ...m, ...patch, id } : m)),
  };
}

export function addOwnerLens(bag: OwnerCardBag, name: string): OwnerCardBag {
  const lens: OwnerLens = { id: nid('lens'), name: name.trim() || 'New lens', methodIds: [] };
  return { ...bag, lenses: [...bag.lenses, lens] };
}

export function removeOwnerLens(bag: OwnerCardBag, id: string): OwnerCardBag {
  if (bag.lenses.length <= 1) return bag;
  const lenses = bag.lenses.filter((l) => l.id !== id);
  const defaultLensId = bag.defaultLensId === id ? lenses[0]?.id : bag.defaultLensId;
  return { ...bag, lenses, defaultLensId };
}

export function setDefaultLens(bag: OwnerCardBag, lensId: string): OwnerCardBag {
  if (!bag.lenses.some((l) => l.id === lensId)) return bag;
  return { ...bag, defaultLensId: lensId };
}

/** Deployment default relay host — never claimed as the only possible relay. */
export function defaultMethodRelay(): string {
  return SVRNTY_DOMAIN;
}

export function methodRelayHost(method: OwnerMethod): string {
  return (method.relay || '').trim() || defaultMethodRelay();
}

export function patchOwnerLens(
  bag: OwnerCardBag,
  id: string,
  patch: Partial<OwnerLens>,
): OwnerCardBag {
  return {
    ...bag,
    lenses: bag.lenses.map((l) => (l.id === id ? { ...l, ...patch, id } : l)),
  };
}

export function toggleLensMethod(bag: OwnerCardBag, lensId: string, methodId: string): OwnerCardBag {
  return {
    ...bag,
    lenses: bag.lenses.map((l) => {
      if (l.id !== lensId) return l;
      const on = l.methodIds.includes(methodId);
      const methodIds = on ? l.methodIds.filter((x) => x !== methodId) : [...l.methodIds, methodId];
      const preferredMethodId =
        l.preferredMethodId && methodIds.includes(l.preferredMethodId)
          ? l.preferredMethodId
          : methodIds[0];
      return { ...l, methodIds, preferredMethodId };
    }),
  };
}

export function setLensPreferred(bag: OwnerCardBag, lensId: string, methodId: string): OwnerCardBag {
  return {
    ...bag,
    lenses: bag.lenses.map((l) => {
      if (l.id !== lensId) return l;
      if (!l.methodIds.includes(methodId)) return l;
      return { ...l, preferredMethodId: methodId };
    }),
  };
}

export function methodsForLens(bag: OwnerCardBag, lensId?: string): OwnerMethod[] {
  const lens = bag.lenses.find((l) => l.id === lensId) || bag.lenses.find((l) => l.id === bag.defaultLensId);
  if (!lens) return [];
  const byId = new Map(bag.methods.map((m) => [m.id, m]));
  return lens.methodIds.map((id) => byId.get(id)).filter((m): m is OwnerMethod => !!m && !!m.value.trim());
}

export function preferredMethod(bag: OwnerCardBag, lensId?: string): OwnerMethod | undefined {
  const lens = bag.lenses.find((l) => l.id === lensId) || bag.lenses.find((l) => l.id === bag.defaultLensId);
  if (!lens?.preferredMethodId) return methodsForLens(bag, lens?.id)[0];
  return bag.methods.find((m) => m.id === lens.preferredMethodId);
}

/** Match a lens by group name (owner-authored) — local intent, not a roster. */
export function lensForGroupName(bag: OwnerCardBag, groupName?: string | null): OwnerLens | undefined {
  const want = (groupName || '').trim().toLowerCase();
  if (!want) return bag.lenses.find((l) => l.id === bag.defaultLensId);
  return (
    bag.lenses.find((l) => l.name.trim().toLowerCase() === want) ||
    bag.lenses.find((l) => l.id === bag.defaultLensId)
  );
}

export function methodKindLabel(kind: OwnerMethodKind): string {
  return OWNER_METHOD_KINDS.find((k) => k.kind === kind)?.label || kind;
}
