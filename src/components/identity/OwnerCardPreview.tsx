'use client';

/**
 * Compose-preview of YOUR card (name + selected methods). Recognition aid only —
 * the seal is recomputed from the fingerprint (never a transmitted field).
 */

import { IdentitySeal } from '@/components/identity/IdentitySeal';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { methodKindLabel, methodRelayHost, type OwnerMethod } from '@/components/identity/owner-card';

export type OwnerCardPreviewProps = {
  name: string;
  fingerprint: string;
  methods: OwnerMethod[];
  preferredId?: string;
  caption?: string;
};

export function OwnerCardPreview({
  name,
  fingerprint,
  methods,
  preferredId,
  caption,
}: OwnerCardPreviewProps) {
  const shown = methods.filter((m) => m.value.trim());
  return (
    <div
      data-testid="owner-card-preview"
      style={{
        borderRadius: 16,
        border: `1px solid ${E.borderLit}`,
        background: E.surfaceSolid,
        padding: '16px 14px',
        textAlign: 'center',
      }}
    >
      {fingerprint ? (
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 10 }}>
          <IdentitySeal fingerprint={fingerprint} size={64} />
        </div>
      ) : null}
      <p style={{ margin: 0, fontSize: 17, fontWeight: 600, color: E.text, fontFamily: E.fontSans }}>
        {name.trim() || 'Unnamed'}
      </p>
      {fingerprint ? (
        <p
          style={{
            margin: '6px 0 0',
            fontSize: 10,
            color: E.dim,
            fontFamily: E.fontMono,
            wordBreak: 'break-all',
          }}
        >
          {fingerprint.match(/.{1,4}/g)?.join(' ') || fingerprint}
        </p>
      ) : null}
      <div style={{ textAlign: 'left', marginTop: 10 }}>
        {shown.length === 0 ? (
          <p style={{ margin: 0, fontSize: 12, color: E.muted, fontFamily: E.fontSans }}>
            Add a method to preview it on this face.
          </p>
        ) : (
          shown.map((m) => {
            const label = m.kind === 'custom' ? m.label || 'Custom' : methodKindLabel(m.kind);
            const pref = preferredId === m.id;
            return (
              <div key={m.id} data-testid="owner-card-preview-method" style={{ marginTop: 8 }}>
                <p
                  style={{
                    margin: 0,
                    fontSize: 10,
                    letterSpacing: '0.12em',
                    textTransform: 'uppercase',
                    color: E.dim,
                    fontFamily: E.fontSans,
                  }}
                >
                  {pref ? `${label} · preferred` : label}
                </p>
                <p
                  style={{
                    margin: '3px 0 0',
                    fontSize: 13,
                    color: E.text,
                    fontFamily: E.fontSans,
                    wordBreak: 'break-word',
                  }}
                >
                  {m.value}
                </p>
                <p style={{ margin: '2px 0 0', fontSize: 10, color: E.dim, fontFamily: E.fontSans }}>
                  Relay {methodRelayHost(m)}
                </p>
              </div>
            );
          })
        )}
      </div>
      {caption ? (
        <p style={{ margin: '12px 0 0', fontSize: 11, color: E.dim, fontFamily: E.fontSans, lineHeight: 1.4 }}>
          {caption}
        </p>
      ) : null}
    </div>
  );
}
