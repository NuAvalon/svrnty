'use client';

/**
 * Add fields to YOUR identity card + author lenses (disclosure faces).
 * Local intent only — extra methods are not on the signed exchange card yet.
 */

import { useEffect, useState, type CSSProperties } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import {
  OWNER_CUSTOM_VALUE_TYPES,
  OWNER_METHOD_KINDS,
  addOwnerLens,
  addOwnerMethod,
  hydrateOwnerCard,
  methodKindLabel,
  methodRelayHost,
  methodsForLens,
  patchOwnerLens,
  removeOwnerLens,
  removeOwnerMethod,
  saveOwnerCard,
  setDefaultLens,
  setLensPreferred,
  toggleLensMethod,
  updateOwnerMethod,
  type OwnerCardBag,
  type OwnerCustomValueType,
  type OwnerMethodKind,
} from '@/components/identity/owner-card';
import { saveLocalMethods } from '@/components/identity/local-methods';
import { OwnerCardPreview } from '@/components/identity/OwnerCardPreview';
import { requestMethodRelayMove } from '@/lib/contacts/method-relay';

export function OwnerCardStudio({
  fingerprint,
  name,
  email,
  onEmailChange,
  onBagChange,
}: {
  fingerprint: string;
  name?: string;
  email?: string;
  onEmailChange?: (email: string) => void;
  onBagChange?: (bag: OwnerCardBag) => void;
}) {
  const [bag, setBag] = useState<OwnerCardBag>(() => hydrateOwnerCard(fingerprint, email));
  const [addKind, setAddKind] = useState<OwnerMethodKind>('phone');
  const [addCustomType, setAddCustomType] = useState<OwnerCustomValueType>('text');
  const [newLensName, setNewLensName] = useState('');
  const [activeLensId, setActiveLensId] = useState(bag.defaultLensId || bag.lenses[0]?.id);
  const [saveHint, setSaveHint] = useState<string | null>(null);
  const [relayDraft, setRelayDraft] = useState<Record<string, string>>({});
  const [relayHint, setRelayHint] = useState<Record<string, string>>({});

  useEffect(() => {
    const next = hydrateOwnerCard(fingerprint, email);
    setBag(next);
    setActiveLensId(next.defaultLensId || next.lenses[0]?.id);
  }, [fingerprint, email]);

  const persist = (next: OwnerCardBag): boolean => {
    const saved = saveOwnerCard(fingerprint, next);
    if (!saved.ok) {
      setSaveHint(
        saved.reason === 'inlined-binary'
          ? 'Paste a link, not an inlined file — avatars stay as references.'
          : 'This card is at the size limit. Remove a field to add another.',
      );
      return false;
    }
    setSaveHint(null);
    setBag(next);
    const emailM = next.methods.find((m) => m.id === 'm-email' || m.kind === 'email');
    const signalM = next.methods.find((m) => m.id === 'm-signal' || m.kind === 'signal');
    const siteM = next.methods.find((m) => m.id === 'm-site' || m.kind === 'site');
    saveLocalMethods(fingerprint, {
      signal: signalM?.value,
      site: siteM?.value,
    });
    if (emailM && onEmailChange && emailM.value !== (email || '')) onEmailChange(emailM.value);
    onBagChange?.(next);
    return true;
  };

  const lens = bag.lenses.find((l) => l.id === activeLensId) || bag.lenses[0];

  return (
    <div
      data-testid="owner-card-studio"
      style={{
        width: '100%',
        maxWidth: 440,
        margin: '0 auto',
        display: 'flex',
        flexDirection: 'column',
        gap: 14,
      }}
    >
      <div>
        <p
          style={{
            margin: 0,
            fontSize: 11,
            letterSpacing: '0.16em',
            textTransform: 'uppercase',
            color: E.accent,
            fontFamily: E.fontSans,
          }}
        >
          Methods on your card
        </p>
        <p style={{ margin: '6px 0 0', fontSize: 12, color: E.dim, fontFamily: E.fontSans, lineHeight: 1.45 }}>
          Add channels the way you would a vCard. A lens below picks which ones a person gets.
        </p>
      </div>

      {bag.methods.map((m) => (
        <div key={m.id} style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {m.kind === 'custom' ? (
              <input
                value={m.label || ''}
                placeholder="Label"
                onChange={(e) => persist(updateOwnerMethod(bag, m.id, { label: e.target.value }))}
                style={inp(88)}
              />
            ) : (
              <span style={{ width: 88, fontSize: 11, color: E.dim, fontFamily: E.fontSans, flexShrink: 0 }}>
                {methodKindLabel(m.kind)}
              </span>
            )}
            {m.kind === 'custom' ? (
              <select
                value={m.valueType || 'text'}
                aria-label="Custom field type"
                onChange={(e) =>
                  persist(
                    updateOwnerMethod(bag, m.id, { valueType: e.target.value as OwnerCustomValueType }),
                  )
                }
                style={{ ...inp(0), width: 92 }}
              >
                {OWNER_CUSTOM_VALUE_TYPES.map((t) => (
                  <option key={t.type} value={t.type}>
                    {t.label}
                  </option>
                ))}
              </select>
            ) : null}
            <input
              value={m.value}
              placeholder={methodKindLabel(m.kind)}
              onChange={(e) => persist(updateOwnerMethod(bag, m.id, { value: e.target.value }))}
              style={{ ...inp(0), flex: 1 }}
            />
            <button
              type="button"
              onClick={() => persist(removeOwnerMethod(bag, m.id))}
              style={ghostBtn}
            >
              Remove
            </button>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', paddingLeft: 88 }}>
            <span style={{ fontSize: 10, color: E.dim, fontFamily: E.fontSans, flexShrink: 0 }}>
              Relay
            </span>
            <input
              data-testid={`owner-method-relay-${m.id}`}
              value={relayDraft[m.id] ?? methodRelayHost(m)}
              placeholder="svrnty.is"
              aria-label={`Relay for ${m.kind === 'custom' ? m.label || 'custom' : methodKindLabel(m.kind)}`}
              onChange={(e) => setRelayDraft((d) => ({ ...d, [m.id]: e.target.value }))}
              style={{ ...inp(0), flex: 1, fontSize: 12 }}
            />
            <button
              type="button"
              data-testid={`owner-method-switch-relay-${m.id}`}
              onClick={() => {
                void (async () => {
                  const raw = relayDraft[m.id] ?? methodRelayHost(m);
                  const { result, bag: next } = await requestMethodRelayMove(bag, m.id, raw);
                  if (!result.ok) {
                    setRelayHint((h) => ({
                      ...h,
                      [m.id]: 'Use an https host — javascript and data URLs are refused.',
                    }));
                    return;
                  }
                  persist(next);
                  setRelayDraft((d) => ({ ...d, [m.id]: result.host }));
                  setRelayHint((h) => ({
                    ...h,
                    [m.id]: result.delivered
                      ? `Recorded ${result.host}.`
                      : `Saved ${result.host} on this device. Delivery still uses the current relay until routing.update is wired.`,
                  }));
                })();
              }}
              style={{
                ...ghostBtn,
                border: `1px solid ${E.border}`,
                padding: '4px 8px',
              }}
            >
              Use this relay
            </button>
          </div>
          {relayHint[m.id] ? (
            <p style={{ margin: 0, paddingLeft: 88, fontSize: 10, color: E.dim, fontFamily: E.fontSans }}>
              {relayHint[m.id]}
            </p>
          ) : null}
        </div>
      ))}

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <select
          value={addKind}
          onChange={(e) => setAddKind(e.target.value as OwnerMethodKind)}
          style={{ ...inp(0), width: 120 }}
        >
          {OWNER_METHOD_KINDS.map((k) => (
            <option key={k.kind} value={k.kind}>
              {k.label}
            </option>
          ))}
        </select>
        {addKind === 'custom' ? (
          <select
            value={addCustomType}
            onChange={(e) => setAddCustomType(e.target.value as OwnerCustomValueType)}
            aria-label="Type for new custom field"
            style={{ ...inp(0), width: 100 }}
          >
            {OWNER_CUSTOM_VALUE_TYPES.map((t) => (
              <option key={t.type} value={t.type}>
                {t.label}
              </option>
            ))}
          </select>
        ) : null}
        <button
          type="button"
          data-testid="owner-card-add-field"
          onClick={() =>
            persist(
              addOwnerMethod(bag, addKind, '', addKind === 'custom' ? '' : undefined, {
                valueType: addKind === 'custom' ? addCustomType : undefined,
              }),
            )
          }
          style={{
            ...ghostBtn,
            border: `1px solid ${E.borderLit}`,
            color: E.accent,
            padding: '6px 12px',
          }}
        >
          Add field
        </button>
      </div>
      {saveHint ? (
        <p data-testid="owner-card-save-hint" style={{ margin: 0, fontSize: 11, color: E.danger, fontFamily: E.fontSans }}>
          {saveHint}
        </p>
      ) : null}

      <div style={{ height: 1, background: E.border, margin: '4px 0' }} />

      <div>
        <p
          style={{
            margin: 0,
            fontSize: 11,
            letterSpacing: '0.16em',
            textTransform: 'uppercase',
            color: E.accent,
            fontFamily: E.fontSans,
          }}
        >
          Lenses
        </p>
        <p style={{ margin: '6px 0 10px', fontSize: 12, color: E.dim, fontFamily: E.fontSans, lineHeight: 1.45 }}>
          Same you, same QR. Business gets work email; festival friends get Instagram. The star is
          the preferred way to reach you on that face.
        </p>
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
        {bag.lenses.map((l) => (
          <button
            key={l.id}
            type="button"
            onClick={() => setActiveLensId(l.id)}
            style={{
              fontSize: 11,
              fontFamily: E.fontSans,
              padding: '6px 10px',
              borderRadius: 8,
              cursor: 'pointer',
              border: `1px solid ${l.id === lens?.id ? E.borderLit : E.border}`,
              background:
                l.id === lens?.id ? 'color-mix(in srgb, var(--se-accent) 14%, transparent)' : 'transparent',
              color: E.accent,
            }}
          >
            {l.name}
            {l.id === bag.defaultLensId ? ' · default' : ''}
          </button>
        ))}
      </div>

      {lens ? (
        <div
          style={{
            padding: 12,
            borderRadius: 12,
            border: `1px solid ${E.border}`,
            background: E.inputBg,
            display: 'flex',
            flexDirection: 'column',
            gap: 8,
          }}
        >
          <input
            value={lens.name}
            onChange={(e) => persist(patchOwnerLens(bag, lens.id, { name: e.target.value }))}
            style={inp(0)}
            aria-label="Lens name"
          />
          {bag.methods.length === 0 ? (
            <p style={{ margin: 0, fontSize: 12, color: E.dim }}>Add a method above first.</p>
          ) : (
            bag.methods.map((m) => {
              const on = lens.methodIds.includes(m.id);
              const pref = lens.preferredMethodId === m.id;
              return (
                <label
                  key={m.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    fontSize: 12,
                    color: E.muted,
                    fontFamily: E.fontSans,
                    cursor: 'pointer',
                  }}
                >
                  <input
                    type="checkbox"
                    checked={on}
                    onChange={() => persist(toggleLensMethod(bag, lens.id, m.id))}
                  />
                  <span style={{ flex: 1 }}>
                    {m.kind === 'custom' ? m.label || 'Custom' : methodKindLabel(m.kind)}
                    {m.value ? ` · ${m.value}` : ''}
                  </span>
                  <button
                    type="button"
                    aria-label={pref ? 'Preferred' : 'Make preferred'}
                    disabled={!on}
                    onClick={() => persist(setLensPreferred(bag, lens.id, m.id))}
                    style={{
                      ...ghostBtn,
                      color: pref ? E.accent : E.dim,
                      opacity: on ? 1 : 0.35,
                    }}
                  >
                    {pref ? '★ preferred' : '☆ prefer'}
                  </button>
                </label>
              );
            })
          )}
          <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
            <button
              type="button"
              data-testid="owner-card-use-default-lens"
              onClick={() => persist(setDefaultLens(bag, lens.id))}
              style={ghostBtn}
            >
              Use as share default
            </button>
            {bag.lenses.length > 1 ? (
              <button
                type="button"
                onClick={() => {
                  const next = removeOwnerLens(bag, lens.id);
                  persist(next);
                  setActiveLensId(next.defaultLensId || next.lenses[0]?.id || '');
                }}
                style={ghostBtn}
              >
                Remove lens
              </button>
            ) : null}
          </div>
        </div>
      ) : null}

      <div style={{ display: 'flex', gap: 8 }}>
        <input
          value={newLensName}
          onChange={(e) => setNewLensName(e.target.value)}
          placeholder="New lens name — Business, Festival…"
          style={{ ...inp(0), flex: 1 }}
        />
        <button
          type="button"
          data-testid="owner-card-add-lens"
          onClick={() => {
            const name = newLensName.trim();
            if (!name) return;
            const next = addOwnerLens(bag, name);
            persist(next);
            setActiveLensId(next.lenses[next.lenses.length - 1]?.id);
            setNewLensName('');
          }}
          style={{
            ...ghostBtn,
            border: `1px solid ${E.borderLit}`,
            color: E.accent,
            padding: '6px 12px',
          }}
        >
          Add lens
        </button>
      </div>

      <p style={{ margin: 0, fontSize: 11, color: E.dim, fontFamily: E.fontSans, lineHeight: 1.45 }}>
        The share link is still you — one key. A lens is the default face you intend to hand them.
        Extra methods stay on this device until the living card schema carries them.
      </p>

      <OwnerCardPreview
        name={name || ''}
        fingerprint={fingerprint}
        methods={methodsForLens(bag, lens?.id).length ? methodsForLens(bag, lens?.id) : bag.methods}
        preferredId={lens?.preferredMethodId}
        caption="Preview of this face — not a send receipt. The signed invite still carries your identity key."
      />
    </div>
  );
}

const ghostBtn: CSSProperties = {
  border: 'none',
  background: 'transparent',
  color: E.dim,
  cursor: 'pointer',
  fontSize: 11,
  fontFamily: E.fontSans,
};

function inp(width: number): CSSProperties {
  return {
    width: width || undefined,
    fontSize: 13,
    fontFamily: E.fontSans,
    color: E.text,
    background: E.inputBg,
    border: `1px solid ${E.border}`,
    borderRadius: 8,
    padding: '6px 8px',
  };
}
