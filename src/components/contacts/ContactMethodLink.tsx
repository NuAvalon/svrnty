'use client';

// ContactMethodLink — I-10a-safe tap-to-open for imported contact methods (CUR-3).
// Allowlisted href → <a>. Otherwise inert text. Never dangerouslySetInnerHTML.

import type { CSSProperties, ReactNode } from 'react';
import type { SafeContactHref } from '@/lib/contacts/safe-contact-link';

const linkBase: CSSProperties = {
  color: 'inherit',
  textDecoration: 'underline',
  textUnderlineOffset: '2px',
  textDecorationColor: 'rgba(249,168,37,0.35)',
  wordBreak: 'break-all',
};

export function ContactMethodLink({
  safe,
  className,
  style,
  children,
}: {
  safe: SafeContactHref;
  className?: string;
  style?: CSSProperties;
  /** Optional override for the visible label (still must be trusted/safe text). */
  children?: ReactNode;
}) {
  const content = children ?? safe.label;
  if (!safe.label) return null;

  if (safe.href) {
    return (
      <a
        href={safe.href}
        className={className}
        style={{ ...linkBase, ...style }}
        // Imported contact → treat as cross-origin; never inherit opener.
        rel="noopener noreferrer"
        // tel:/mailto: stay same-tab; https deep-links open in a new tab.
        target={safe.href.startsWith('https:') ? '_blank' : undefined}
      >
        {content}
      </a>
    );
  }

  return (
    <span className={className} style={style}>
      {content}
    </span>
  );
}
