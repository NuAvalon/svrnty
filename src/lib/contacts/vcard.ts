// src/lib/contacts/vcard.ts
// vCard 3.0 — portable phone book.
// Export is classical contact data only: name, emails, phones, urls, org/title,
// notes, handles. SVRNTY trust, fingerprints, group tags, they_trust, and
// share settings never leave on .vcf (device-local / living-wire — not a phone book).

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

  const ci = edge.contact_info;
  if (ci?.org) lines.push(`ORG:${escapeVCard(ci.org)}`);
  if (ci?.title) lines.push(`TITLE:${escapeVCard(ci.title)}`);
  if (ci?.nickname) lines.push(`NICKNAME:${escapeVCard(ci.nickname)}`);
  if (ci?.bday) lines.push(`BDAY:${escapeVCard(ci.bday)}`);
  if (ci?.adr) lines.push(`ADR;TYPE=HOME:;;${escapeVCard(ci.adr)};;;;`);
  if (ci?.extras) {
    for (const extra of ci.extras) {
      if (!extra.label || !extra.value) continue;
      const key = extra.label.replace(/[^A-Za-z0-9-]/g, '').toUpperCase() || 'CUSTOM';
      lines.push(`X-${key}:${escapeVCard(extra.value)}`);
    }
  }

  // Notes — portable phone book. Trust / fingerprint / owner-local groups stay off .vcf.
  if (edge.notes) {
    lines.push(`NOTE:${escapeVCard(edge.notes)}`);
  }

  // Handles as X-fields
  if (edge.contact_info?.handles) {
    for (const [platform, handle] of Object.entries(edge.contact_info.handles)) {
      lines.push(`X-${platform.toUpperCase()}:${escapeVCard(handle)}`);
    }
  }

  // Apollo §2 / gap-freeze KB#87571 — tags, blocked, and group-cluster labels are
  // device-local. NEVER emit CATEGORIES (or blocked) on export. fromVCard may still
  // *read* CATEGORIES into local tags on import; that stays on-device.

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
    // RFC 6350 line-unfolding: a line beginning with a space or tab is a continuation
    // of the previous one (real exports fold long TEL/EMAIL/NOTE lines).
    const lines = block.replace(/\r?\n[ \t]/g, '').split(/\r?\n/);

    const edge: Partial<TrustEdge> = {
      contact_info: { phones: [], emails: [], handles: {}, urls: [], extras: [] },
      tags: [],
      connection_channels: [],
    };

    for (const line of lines) {
      const colon = line.indexOf(':');
      if (colon === -1) continue;
      const value = line.slice(colon + 1);
      // Resolve the property NAME robustly for real-world exports:
      //  - drop a grouping prefix: Apple/iCloud/Google write labeled fields as "item1.TEL",
      //    "item2.EMAIL" — the old startsWith('TEL') missed these, so imports showed no detail.
      //  - drop params: "TEL;TYPE=CELL" -> "TEL".  - match case-insensitively.
      let name = line.slice(0, colon).split(';')[0];
      const dot = name.indexOf('.');
      if (dot !== -1) name = name.slice(dot + 1);
      const PROP = name.toUpperCase();

      if (PROP === 'FN') {
        edge.peer_name = unescapeVCard(value);
      } else if (PROP === 'EMAIL') {
        if (!edge.peer_email) {
          edge.peer_email = value;
        } else {
          edge.contact_info!.emails!.push(value);
        }
      } else if (PROP === 'TEL') {
        edge.contact_info!.phones!.push(value);
      } else if (PROP === 'URL') {
        edge.contact_info!.urls!.push(value);
      } else if (PROP === 'ORG') {
        edge.contact_info!.org = unescapeVCard(value);
      } else if (PROP === 'TITLE') {
        edge.contact_info!.title = unescapeVCard(value);
      } else if (PROP === 'NICKNAME') {
        edge.contact_info!.nickname = unescapeVCard(value);
      } else if (PROP === 'BDAY') {
        edge.contact_info!.bday = unescapeVCard(value);
      } else if (PROP === 'ADR') {
        const parts = value.split(';');
        edge.contact_info!.adr = unescapeVCard(parts.slice(2).join(' ').replace(/\s+/g, ' ').trim() || value);
      } else if (PROP === 'X-SVRNTY-FINGERPRINT') {
        // Inbound only — we no longer WRITE this on export. Old .vcf files may still carry it.
        edge.peer_fingerprint = unescapeVCard(value);
      } else if (PROP === 'NOTE') {
        edge.notes = unescapeVCard(value).replace(/\\n/g, '\n');
      } else if (PROP.startsWith('X-') && !PROP.startsWith('X-AB')) {
        // X-<platform> handles (twitter, signal, …). Skip Apple's internal X-AB* label
        // metadata (X-ABLabel/X-ABADR), which aren't reachable contact channels.
        const platform = PROP.slice(2).toLowerCase();
        const social = ['signal', 'telegram', 'twitter', 'x', 'whatsapp', 'impp', 'discord', 'instagram', 'matrix'];
        if (social.includes(platform)) {
          edge.contact_info!.handles![platform] = value;
          edge.connection_channels!.push(platform);
        } else {
          edge.contact_info!.extras = edge.contact_info!.extras || [];
          edge.contact_info!.extras.push({ label: platform, value: unescapeVCard(value) });
        }
      } else if (PROP === 'CATEGORIES') {
        edge.tags = value.split(',').map(unescapeVCard);
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
