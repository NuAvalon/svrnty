/**
 * Owner card methods + lenses — local-only disclosure faces.
 *
 * One identity (one fingerprint, one QR/link, one seal). A lens is a PROFILE
 * you author for a face: display name, handle, note, and which of YOUR methods
 * that face shows — "work email as Peter" vs "festival Instagram as Archie".
 * Extra methods / per-lens names are NOT on the signed identity-exchange card
 * yet (fleet schema). Glass stores intent here; Grow/share still carry the
 * signed name+key. The card you SEE is the face; the key does not change.
 */

import { loadLocalMethods } from '@/components/identity/local-methods';

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

export type OwnerMethod = {
  id: string;
  kind: OwnerMethodKind;
  value: string;
  label?: string;
};

/** How you appear on one face. All optional — empty falls back to the signed identity. */
export type OwnerLensProfile = {
  displayName?: string;
  handle?: string;
  note?: string;
};

export type OwnerLens = {
  id: string;
  name: string;
  methodIds: string[];
  preferredMethodId?: string;
  profile?: OwnerLensProfile;
};

/** Resolved card face for render — never a second key. */
export type OwnerLensFace = {
  lensId: string;
  lensName: string;
  isDefault: boolean;
  displayName: string;
  handle?: string;
  note?: string;
  methods: OwnerMethod[];
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

function loadOwnerCardRaw(fingerprint: string): OwnerCardBag | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = localStorage.getItem(bagKey(fingerprint));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as OwnerCardBag;
    if (!Array.isArray(parsed.methods) || !Array.isArray(parsed.lenses)) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function saveOwnerCard(fingerprint: string, bag: OwnerCardBag): OwnerCardBag {
  if (typeof window === 'undefined') return bag;
  localStorage.setItem(bagKey(fingerprint), JSON.stringify(bag));
  return bag;
}

export function addOwnerMethod(
  bag: OwnerCardBag,
  kind: OwnerMethodKind,
  value = '',
  label?: string,
): OwnerCardBag {
  const method: OwnerMethod = { id: nid('m'), kind, value, label };
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

export function patchLensProfile(
  bag: OwnerCardBag,
  id: string,
  patch: Partial<OwnerLensProfile>,
): OwnerCardBag {
  return {
    ...bag,
    lenses: bag.lenses.map((l) => {
      if (l.id !== id) return l;
      const merged = { ...(l.profile || {}), ...patch };
      const profile: OwnerLensProfile = {};
      const displayName = (merged.displayName || '').trim();
      const handle = (merged.handle || '').trim();
      const note = (merged.note || '').trim();
      if (displayName) profile.displayName = displayName;
      if (handle) profile.handle = handle;
      if (note) profile.note = note;
      return { ...l, profile: Object.keys(profile).length ? profile : undefined };
    }),
  };
}

export function ownerLensFace(
  bag: OwnerCardBag,
  lensId: string | undefined,
  fallback: { displayName?: string; handle?: string } = {},
): OwnerLensFace {
  const lens =
    bag.lenses.find((l) => l.id === lensId) ||
    bag.lenses.find((l) => l.id === bag.defaultLensId) ||
    bag.lenses[0];
  const displayName =
    (lens?.profile?.displayName || '').trim() || (fallback.displayName || '').trim();
  const handle = (lens?.profile?.handle || '').trim() || (fallback.handle || '').trim() || undefined;
  const note = (lens?.profile?.note || '').trim() || undefined;
  return {
    lensId: lens?.id || '',
    lensName: lens?.name || 'Everyone',
    isDefault: !!lens && lens.id === bag.defaultLensId,
    displayName,
    handle,
    note,
    methods: lens ? methodsForLens(bag, lens.id) : [],
  };
}

export type CardFaceMethod = {
  id?: string;
  kind: OwnerMethodKind | string;
  label: string;
  value?: string;
};

/**
 * Methods to paint on YOUR card for a face.
 * Default lens keeps the classic email / Signal / site rows (even empty) so
 * Revise still has a home. Named lenses show only what that profile includes.
 */
export function cardMethodsForFace(
  bag: OwnerCardBag,
  face: OwnerLensFace,
  fallback: { email?: string; signal?: string; site?: string } = {},
): CardFaceMethod[] {
  const fromLens: CardFaceMethod[] = face.methods.map((m) => ({
    id: m.id,
    kind: m.kind,
    label: m.kind === 'custom' ? m.label || 'Custom' : methodKindLabel(m.kind),
    value: m.value,
  }));
  if (!face.isDefault) return fromLens;

  const haveKind = new Set(fromLens.map((m) => m.kind));
  const classic: Array<{ kind: 'email' | 'signal' | 'site'; value?: string }> = [
    { kind: 'email', value: fallback.email },
    { kind: 'signal', value: fallback.signal },
    { kind: 'site', value: fallback.site },
  ];
  const extras: CardFaceMethod[] = [];
  for (const row of classic) {
    if (haveKind.has(row.kind)) continue;
    extras.push({
      kind: row.kind,
      label: methodKindLabel(row.kind),
      value: row.value,
    });
  }
  const order = ['email', 'signal', 'site'];
  return [...extras, ...fromLens].sort((a, b) => {
    const ai = order.indexOf(String(a.kind));
    const bi = order.indexOf(String(b.kind));
    return (ai === -1 ? 50 : ai) - (bi === -1 ? 50 : bi);
  });
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
