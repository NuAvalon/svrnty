/**
 * sms: deep-link helper — same digit rules as tel: (CUR-3 / I-10a).
 */

import { resolvePhoneHref } from './safe-contact-link';

export function resolveSmsHref(raw: string): string | null {
  const tel = resolvePhoneHref(raw);
  if (!tel || !tel.startsWith('tel:')) return null;
  return `sms:${tel.slice('tel:'.length)}`;
}

/** WhatsApp chat link from a phone (wa.me), or null if digits unsafe. */
export function resolveWhatsAppPhoneHref(raw: string): string | null {
  const tel = resolvePhoneHref(raw);
  if (!tel) return null;
  const digits = tel.slice('tel:'.length).replace(/^\+/, '');
  if (!/^\d{7,15}$/.test(digits)) return null;
  return `https://wa.me/${digits}`;
}
