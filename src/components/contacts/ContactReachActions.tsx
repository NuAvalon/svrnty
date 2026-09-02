'use client';

/**
 * Call / text / WhatsApp / Signal chips for a contact's methods (CUR-3 allowlist).
 */

import type { CSSProperties } from 'react';
import { Phone, MessageSquare } from 'lucide-react';
import { ContactMethodLink } from '@/components/contacts/ContactMethodLink';
import {
  safeEmailLink,
  safePhoneLink,
  safeHandleLink,
} from '@/lib/contacts/safe-contact-link';
import { resolveSmsHref, resolveWhatsAppPhoneHref } from '@/lib/contacts/resolve-sms-href';
import { solarEmber as E } from '@/components/recovery/solar-ember';

export type ContactReachInfo = {
  email?: string;
  phones?: string[];
  handles?: Record<string, string>;
};

const chip: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: 6,
  padding: '6px 10px',
  borderRadius: 999,
  border: `1px solid ${E.border}`,
  background: E.inputBg,
  fontSize: 12,
  fontFamily: E.fontSans,
  color: E.text,
  textDecoration: 'none',
};

function SafeChip({ href, label }: { href: string | null; label: string }) {
  if (!href) {
    return (
      <span style={{ ...chip, opacity: 0.45, cursor: 'default' }} title="Not available">
        {label}
      </span>
    );
  }
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" style={chip}>
      {label}
    </a>
  );
}

export function ContactReachActions({ info }: { info: ContactReachInfo }) {
  const phone = (info.phones || []).find(Boolean) || '';
  const tel = phone ? safePhoneLink(phone).href : null;
  const sms = phone ? resolveSmsHref(phone) : null;
  const waFromPhone = phone ? resolveWhatsAppPhoneHref(phone) : null;
  const waHandle = info.handles
    ? safeHandleLink('whatsapp', info.handles.whatsapp || info.handles.wa || '').href
    : null;
  const signalHandle = info.handles
    ? safeHandleLink('signal', info.handles.signal || '').href
    : null;
  const mail = info.email ? safeEmailLink(info.email).href : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <p
        style={{
          margin: 0,
          fontSize: 10,
          letterSpacing: '0.14em',
          textTransform: 'uppercase',
          color: E.dim,
          fontFamily: E.fontSans,
        }}
      >
        Reach
      </p>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
        <SafeChip href={tel} label="Call" />
        <SafeChip href={sms} label="Text" />
        <SafeChip href={waFromPhone || waHandle} label="WhatsApp" />
        <SafeChip href={signalHandle} label="Signal" />
        <SafeChip href={mail} label="Email" />
      </div>
      {phone ? (
        <p style={{ margin: 0, fontSize: 11, color: E.dim, fontFamily: E.fontMono }}>
          <Phone className="inline h-3 w-3 mr-1" />
          <ContactMethodLink safe={safePhoneLink(phone)} />
        </p>
      ) : null}
      {!phone && !mail && !signalHandle && !waHandle ? (
        <p style={{ margin: 0, fontSize: 12, color: E.muted, fontFamily: E.fontSans }}>
          <MessageSquare className="inline h-3 w-3 mr-1" />
          No call/text channels on this card yet.
        </p>
      ) : null}
    </div>
  );
}
