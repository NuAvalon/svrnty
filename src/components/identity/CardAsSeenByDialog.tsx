'use client';

/**
 * Preview what YOUR living card would show a peer (or a group) —
 * disclosure by their trust with you, not a delivery receipt.
 *
 * Known → seal + name + fingerprint (methods stay private).
 * Trusted → living methods you keep on the card.
 * Group with mixed trust → show both tiers honestly.
 */

import type { ReactNode } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { IdentitySeal } from '@/components/identity/IdentitySeal';
import { solarEmber as E } from '@/components/recovery/solar-ember';

export type OwnerCardMethodView = {
  label: string;
  value: string;
  preferred?: boolean;
};

export type OwnerCardSnapshot = {
  name: string;
  fingerprint: string;
  email?: string;
  signal?: string;
  site?: string;
  handle?: string;
  /** Default-lens methods (local faces — not the signed exchange card). */
  methods?: OwnerCardMethodView[];
  /** Named lenses for group-matched faces. */
  lenses?: Array<{ id: string; name: string; methods: OwnerCardMethodView[] }>;
};

export type CardAsSeenAudience =
  | { kind: 'peer'; name: string; fingerprint: string; trusted: boolean }
  | { kind: 'group'; name: string; memberCount: number; trustedCount: number; knownCount: number };

export type CardAsSeenByDialogProps = {
  open: boolean;
  onClose: () => void;
  owner: OwnerCardSnapshot;
  audience: CardAsSeenAudience | null;
};

function Field({ label, value }: { label: string; value?: string }) {
  if (!value?.trim()) return null;
  return (
    <div style={{ marginTop: 10 }}>
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
        {label}
      </p>
      <p
        style={{
          margin: '4px 0 0',
          fontSize: 14,
          color: E.text,
          fontFamily: E.fontSans,
          wordBreak: 'break-word',
        }}
      >
        {value}
      </p>
    </div>
  );
}

function methodsForAudience(
  owner: OwnerCardSnapshot,
  audience: CardAsSeenAudience | null,
): OwnerCardMethodView[] {
  if (audience?.kind === 'group' && owner.lenses?.length) {
    const want = audience.name.trim().toLowerCase();
    const named = owner.lenses.find((l) => l.name.trim().toLowerCase() === want);
    if (named) return named.methods;
  }
  return owner.methods || [];
}

function CardFace({
  owner,
  showMethods,
  caption,
  methods,
}: {
  owner: OwnerCardSnapshot;
  showMethods: boolean;
  caption: ReactNode;
  methods?: OwnerCardMethodView[];
}) {
  const methodsToShow = methods && methods.length ? methods : owner.methods || [];

  return (
    <div
      style={{
        borderRadius: 16,
        border: `1px solid ${E.borderLit}`,
        background: E.surfaceSolid,
        padding: '18px 16px',
        textAlign: 'center',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 12 }}>
        <IdentitySeal fingerprint={owner.fingerprint} size={72} />
      </div>
      <p style={{ margin: 0, fontSize: 18, fontWeight: 600, color: E.text, fontFamily: E.fontSans }}>
        {owner.name || 'Unnamed'}
      </p>
      {owner.handle ? (
        <p style={{ margin: '4px 0 0', fontSize: 13, color: E.accent, fontFamily: E.fontSans }}>
          {owner.handle.startsWith('@') ? owner.handle : `@${owner.handle}`}
        </p>
      ) : null}
      <p
        style={{
          margin: '8px 0 0',
          fontSize: 11,
          color: E.dim,
          fontFamily: E.fontMono,
          wordBreak: 'break-all',
        }}
      >
        {owner.fingerprint.match(/.{1,4}/g)?.join(' ') || owner.fingerprint}
      </p>
      {showMethods ? (
        <div style={{ textAlign: 'left', marginTop: 8 }}>
          {methodsToShow.length > 0 ? (
            methodsToShow.map((m, i) => (
              <Field
                key={`${m.label}-${i}`}
                label={m.preferred ? `${m.label} · preferred` : m.label}
                value={m.value}
              />
            ))
          ) : (
            <>
              <Field label="Email" value={owner.email} />
              <Field label="Signal" value={owner.signal} />
              <Field label="Site" value={owner.site} />
              {!owner.email && !owner.signal && !owner.site ? (
                <p style={{ margin: '10px 0 0', fontSize: 12, color: E.muted, fontFamily: E.fontSans }}>
                  No living methods on your card yet.
                </p>
              ) : null}
            </>
          )}
        </div>
      ) : (
        <p style={{ margin: '12px 0 0', fontSize: 12, color: E.muted, fontFamily: E.fontSans, lineHeight: 1.45 }}>
          Methods stay private at Known — only seal + name + fingerprint.
        </p>
      )}
      <p style={{ margin: '14px 0 0', fontSize: 11, color: E.dim, fontFamily: E.fontSans, lineHeight: 1.4 }}>
        {caption}
      </p>
    </div>
  );
}

export function CardAsSeenByDialog({ open, onClose, owner, audience }: CardAsSeenByDialogProps) {
  const title =
    audience?.kind === 'group'
      ? `Your card · group “${audience.name}”`
      : audience
        ? `Your card · as ${audience.name} sees it`
        : 'Your card · as they see it';

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
    >
      <DialogContent
        className="gap-0 overflow-hidden p-0 sm:rounded-2xl [&>button]:z-20"
        style={{
          width: 'min(26rem, calc(100vw - 1rem))',
          maxWidth: 'calc(100vw - 1rem)',
          maxHeight: 'min(92dvh, 40rem)',
          display: 'flex',
          flexDirection: 'column',
          background: E.surfaceSolid,
          border: `1px solid ${E.border}`,
          color: E.text,
          fontFamily: E.fontSans,
        }}
      >
        <DialogHeader
          className="shrink-0 space-y-1 px-4 pb-2 pt-4 pr-12 text-left"
          style={{ borderBottom: `1px solid ${E.border}` }}
        >
          <DialogTitle style={{ color: E.text, fontFamily: E.fontSans, fontSize: 16 }}>
            {title}
          </DialogTitle>
          <DialogDescription style={{ color: E.muted, fontSize: 12, lineHeight: 1.45 }}>
            Preview of fields you disclose at their trust with you — not a send receipt, and not
            location. Reachability only.
          </DialogDescription>
        </DialogHeader>

        <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {!audience ? (
            <p style={{ margin: 0, fontSize: 13, color: E.muted }}>Select a contact or group first.</p>
          ) : audience.kind === 'peer' ? (
            <CardFace
              owner={owner}
              showMethods={audience.trusted}
              methods={methodsForAudience(owner, audience)}
              caption={
                audience.trusted
                  ? 'Trusted with you — living methods on the card are visible.'
                  : 'Known (not trusted) — seal identity only.'
              }
            />
          ) : (
            <>
              {audience.trustedCount > 0 ? (
                <div>
                  <p
                    style={{
                      margin: '0 0 8px',
                      fontSize: 10,
                      letterSpacing: '0.12em',
                      textTransform: 'uppercase',
                      color: E.accent,
                      fontFamily: E.fontSans,
                    }}
                  >
                    Trusted members ({audience.trustedCount})
                  </p>
                  <CardFace
                    owner={owner}
                    showMethods
                    methods={methodsForAudience(owner, audience)}
                    caption="Trusted members of this group see living methods."
                  />
                </div>
              ) : null}
              {audience.knownCount > 0 ? (
                <div>
                  <p
                    style={{
                      margin: '0 0 8px',
                      fontSize: 10,
                      letterSpacing: '0.12em',
                      textTransform: 'uppercase',
                      color: E.dim,
                      fontFamily: E.fontSans,
                    }}
                  >
                    Known members ({audience.knownCount})
                  </p>
                  <CardFace
                    owner={owner}
                    showMethods={false}
                    caption="Known-only members see seal + name — not methods."
                  />
                </div>
              ) : null}
              <p style={{ margin: 0, fontSize: 11, color: E.dim, lineHeight: 1.45 }}>
                Co-members of “{audience.name}” are not a trust edge — same hull, no inferred bond.
              </p>
            </>
          )}
        </div>

        <div className="shrink-0 px-4 py-3" style={{ borderTop: `1px solid ${E.border}` }}>
          <Button type="button" variant="outline" className="w-full" onClick={onClose} style={{ fontFamily: E.fontSans }}>
            Close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
