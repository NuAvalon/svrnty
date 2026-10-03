'use client';

/**
 * Gate-pending card chrome for one-step Connect-UX.
 * Render-glass only: displays what the add-logic stub (or, later, Apollo) returned.
 * Seal is recomputed from fingerprint (I-6) — never a transmitted picture.
 */

import { IdentitySeal } from '@/components/identity/IdentitySeal';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { formatFingerprintForVerify } from '@/lib/trust/trust-recipe';
import {
  resolveUrlHref,
  sanitizeContactMethodText,
} from '@/lib/contacts/safe-contact-link';
import {
  CONNECT_COPY,
  boundConnectHandle,
  boundConnectName,
  entityTypeLabel,
  type ConnectEntityType,
} from '@/lib/connect/copy';
import type { ConnectCard } from '@/lib/connect/add-logic';

function fingerprintForSeal(fp: string): string | null {
  const hex = (fp || '').replace(/[^0-9a-fA-F]/g, '');
  if (hex.length === 64 || hex.length === 40) return hex.toLowerCase();
  return null;
}

export function ConnectArrivalCard({ card }: { card: ConnectCard | null }) {
  const name = boundConnectName(card?.displayName) || '—';
  const handle = boundConnectHandle(card?.handle);
  const entity = entityTypeLabel(card?.entityType as ConnectEntityType | undefined);
  const sealFp = fingerprintForSeal(card?.fingerprint || '');
  const grouped = card?.fingerprint
    ? formatFingerprintForVerify(card.fingerprint)
    : '';
  const mailboxRaw = sanitizeContactMethodText(card?.mailboxPointer || '');
  const mailboxHref = mailboxRaw ? resolveUrlHref(mailboxRaw) : null;

  return (
    <div
      data-testid="connect-arrival-card"
      style={{
        marginTop: 16,
        padding: 16,
        borderRadius: 12,
        border: `1px solid ${E.borderLit}`,
        background: 'color-mix(in srgb, var(--se-accent) 6%, transparent)',
      }}
    >
      <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
        {sealFp ? (
          <IdentitySeal fingerprint={sealFp} size={64} label={name} />
        ) : (
          <div
            aria-hidden
            style={{
              width: 64,
              height: 64,
              borderRadius: 12,
              border: `1px dashed ${E.border}`,
              background: 'transparent',
            }}
          />
        )}
        <div style={{ minWidth: 0, flex: 1 }}>
          <p
            data-testid="connect-arrival-name"
            style={{ margin: 0, fontSize: 18, color: E.text, wordBreak: 'break-word' }}
          >
            {name}
          </p>
          <p
            data-testid="connect-entity-type"
            style={{
              margin: '4px 0 0',
              fontSize: 11,
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              color: E.dim,
            }}
          >
            {entity}
          </p>
          {handle ? (
            <p style={{ margin: '6px 0 0', fontSize: 12, color: E.muted }}>
              {CONNECT_COPY.handleLabel}: {handle}
            </p>
          ) : null}
        </div>
      </div>

      {grouped ? (
        <>
          <p
            style={{
              margin: '14px 0 0',
              fontSize: 11,
              letterSpacing: '0.12em',
              color: E.dim,
            }}
          >
            {CONNECT_COPY.fingerprintLabel}
          </p>
          <code
            data-testid="connect-fingerprint"
            style={{
              display: 'block',
              marginTop: 4,
              fontSize: 12,
              color: E.text,
              fontFamily: E.fontMono,
              wordBreak: 'break-word',
            }}
          >
            {grouped}
          </code>
        </>
      ) : null}

      {mailboxRaw ? (
        <p style={{ margin: '12px 0 0', fontSize: 12, color: E.muted, wordBreak: 'break-all' }}>
          {CONNECT_COPY.mailboxLabel}:{' '}
          {mailboxHref ? (
            <a
              href={mailboxHref}
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: E.accent }}
            >
              {mailboxRaw}
            </a>
          ) : (
            mailboxRaw
          )}
        </p>
      ) : null}
    </div>
  );
}
