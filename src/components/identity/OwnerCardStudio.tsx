'use client';

/**
 * Add fields to YOUR identity card + author lenses (disclosure faces).
 * Local intent only — extra methods are not on the signed exchange card yet.
 */

import { useEffect, useState, type CSSProperties } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import {
  OWNER_METHOD_KINDS,
  addOwnerLens,
  addOwnerMethod,
  hydrateOwnerCard,
  methodKindLabel,
  patchOwnerLens,
  removeOwnerLens,
  removeOwnerMethod,
  saveOwnerCard,
  setLensPreferred,
  toggleLensMethod,
  updateOwnerMethod,
  type OwnerCardBag,
  type OwnerMethodKind,
} from '@/components/identity/owner-card';
import { saveLocalMethods } from '@/components/identity/local-methods';

export function OwnerCardStudio({
  fingerprint,
  email,
  onEmailChange,
  onBagChange,
}: {
  fingerprint: string;
  email?: string;
  onEmailChange?: (email: string) => void;
  onBagChange?: (bag: OwnerCardBag) => void;
}) {
  const [bag, setBag] = useState<OwnerCardBag>(() => hydrateOwnerCard(fingerprint, email));
  const [addKind, setAddKind] = useState<OwnerMethodKind>('phone');
  const [newLensName, setNewLensName] = useState('');
  const [activeLensId, setActiveLensId] = useState(bag.defaultLensId || bag.lenses[0]?.id);

  useEffect(() => {
    const next = hydrateOwnerCard(fingerprint, email);
    setBag(next);
    setActiveLensId(next.defaultLensId || next.lenses[0]?.id);
  }, [fingerprint, email]);

  const persist = (next: OwnerCardBag) => {
    setBag(next);
    saveOwnerCard(fingerprint, next);
    const emailM = next.methods.find((m) => m.id === 'm-email' || m.kind === 'email');
    const signalM = next.methods.find((m) => m.id === 'm-signal' || m.kind === 'signal');
    const siteM = next.methods.find((m) => m.id === 'm-site' || m.kind === 'site');
    saveLocalMethods(fingerprint, {
      signal: signalM?.value,
      site: siteM?.value,
    });
    if (emailM && onEmailChange && emailM.value !== (email || '')) onEmailChange(emailM.value);
    onBagChange?.(next);
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
        <div key={m.id} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
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
      ))}

      <div style={{ display: 'flex', gap: 8 }}>
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
        <button
          type="button"
          data-testid="owner-card-add-field"
          onClick={() => persist(addOwnerMethod(bag, addKind, ''))}
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
              onClick={() => persist({ ...bag, defaultLensId: lens.id })}
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
                  setActiveLensId(next.defaultLensId);
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
