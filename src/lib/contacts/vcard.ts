// src/lib/contacts/vcard.ts
// vCard 3.0 export — generate .vcf files from TrustEdge contacts.
// Import into any phone, email client, or contact manager.

import type { TrustEdge } from '@/lib/trust/types';

/**
 * Generate a vCard 3.0 string for a single contact.
 */
export function toVCard(edge: TrustEdge): string {
  const lines: string[] = [
    'BEGIN:VCARD',
    'VERSION:3.0',
    `FN:${escapeVCard(edge.peer_name)}`,
  ];

  // Name parts (best effort — we only have display name)
  const parts = edge.peer_name.split(' ');
  if (parts.length >= 2) {
    lines.push(`N:${escapeVCard(parts.slice(1).join(' '))};${escapeVCard(parts[0])};;;`);
  } else {
    lines.push(`N:;${escapeVCard(edge.peer_name)};;;`);
  }

  // Email
  if (edge.peer_email) {
    lines.push(`EMAIL;TYPE=INTERNET:${edge.peer_email}`);
  }
  if (edge.contact_info?.emails) {
    for (const email of edge.contact_info.emails) {
      lines.push(`EMAIL;TYPE=INTERNET:${email}`);
    }
  }

  // Phones (multiple TEL lines — real vCards are phone-centric)
  if (edge.contact_info?.phones) {
    for (const phone of edge.contact_info.phones) {
      lines.push(`TEL;TYPE=CELL:${phone}`);
    }
  }

  // URLs
  if (edge.contact_info?.urls) {
    for (const url of edge.contact_info.urls) {
      lines.push(`URL:${url}`);
    }
  }

  // Notes — include trust state and fingerprint
  const noteLines = [
    `svrnty fingerprint: ${edge.peer_fingerprint}`,
    `Trust: ${edge.trusted ? 'trusted' : 'known'}${edge.trusted_since ? ` since ${edge.trusted_since.slice(0, 10)}` : ''}`,
  ];
  if (edge.notes) noteLines.push(edge.notes);
  lines.push(`NOTE:${escapeVCard(noteLines.join('\\n'))}`);

  // Handles as X-fields
  if (edge.contact_info?.handles) {
    for (const [platform, handle] of Object.entries(edge.contact_info.handles)) {
      lines.push(`X-${platform.toUpperCase()}:${escapeVCard(handle)}`);
    }
  }

  // Tags as categories
  if (edge.tags.length > 0) {
    lines.push(`CATEGORIES:${edge.tags.map(escapeVCard).join(',')}`);
  }

  lines.push('END:VCARD');
  return lines.join('\r\n');
}

/**
 * Generate a multi-contact vCard file.
 */
export function toVCardFile(edges: TrustEdge[]): string {
  return edges.map(toVCard).join('\r\n');
}

/**
 * Parse a vCard string back into partial TrustEdge data.
 * Best-effort — imports what it can find.
 */
export function fromVCard(vcf: string): Partial<TrustEdge>[] {
  const cards: Partial<TrustEdge>[] = [];
  const blocks = vcf.split('BEGIN:VCARD');

  for (const block of blocks) {
    if (!block.includes('END:VCARD')) continue;
    const lines = block.split(/\r?\n/);

    const edge: Partial<TrustEdge> = {
      contact_info: { phones: [], emails: [], handles: {}, urls: [] },
      tags: [],
      connection_channels: [],
    };

    for (const line of lines) {
      if (line.startsWith('FN:')) {
        edge.peer_name = unescapeVCard(line.slice(3));
      } else if (line.startsWith('EMAIL')) {
        const email = line.split(':').slice(1).join(':');
        if (!edge.peer_email) {
          edge.peer_email = email;
        } else {
          edge.contact_info!.emails!.push(email);
        }
      } else if (line.startsWith('TEL')) {
        edge.contact_info!.phones!.push(line.split(':').slice(1).join(':'));
      } else if (line.startsWith('URL:')) {
        edge.contact_info!.urls!.push(line.slice(4));
      } else if (line.startsWith('X-') && line.includes(':')) {
        const colonIdx = line.indexOf(':');
        const platform = line.slice(2, colonIdx).toLowerCase();
        const handle = line.slice(colonIdx + 1);
        edge.contact_info!.handles![platform] = handle;
        edge.connection_channels!.push(platform);
      } else if (line.startsWith('CATEGORIES:')) {
        edge.tags = line.slice(11).split(',').map(unescapeVCard);
      }
    }

    if (edge.peer_name) {
      cards.push(edge);
    }
  }

  return cards;
}

function escapeVCard(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,');
}

function unescapeVCard(s: string): string {
  return s.replace(/\\,/g, ',').replace(/\\;/g, ';').replace(/\\\\/g, '\\');
}
