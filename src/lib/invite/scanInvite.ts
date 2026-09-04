// src/lib/invite/scanInvite.ts
//
// Scan-to-join handler (render-glass). The camera / QR decoder hands a STRING here;
// this module is the only place that string crosses into join: it calls parseInviteUrl
// (INV-4, the single invite parser) and returns either a ParsedInvite or a FIXED error.
//
// INV-5 — a scan handler is a leak-site. The key fragment (URL #hash) is key material.
// This module NEVER logs, echoes, interpolates, persists, or returns the raw scan text.
// Error strings are compile-time constants — no input interpolation.

import { parseInviteUrl, type ParsedInvite } from './parseInviteUrl';

/** Fixed — camera API missing, insecure context, or a non-permission failure. */
export const SCAN_ERROR_CAMERA =
  "Camera isn't available. Paste the invite link instead.";

/** Fixed — getUserMedia rejected as NotAllowedError / PermissionDeniedError. */
export const SCAN_ERROR_PERMISSION =
  'Camera permission was declined. Paste the invite link instead.';

/** Fixed — a QR decoded to text that parseInviteUrl rejected. NEVER interpolate the text. */
export const SCAN_ERROR_NOT_INVITE =
  "That doesn't look like a svrnty invite. Try another QR, or paste the link instead.";

export type ScanInviteResult =
  | { ok: true; invite: ParsedInvite }
  | { ok: false; error: string };

/**
 * Feed a decoded QR payload into the single invite parser.
 * TOTAL: never throws. Failure error is always SCAN_ERROR_NOT_INVITE (no interpolation).
 */
export function inviteFromScannedText(raw: unknown): ScanInviteResult {
  const parsed = parseInviteUrl(raw);
  if (!parsed) return { ok: false, error: SCAN_ERROR_NOT_INVITE };
  return { ok: true, invite: parsed };
}

/**
 * Map a getUserMedia / play() failure to a FIXED string.
 * Reads only `err.name` (DOMException class) — never `err.message` (could echo context).
 */
export function classifyCameraError(err: unknown): string {
  const name =
    err && typeof err === 'object' && 'name' in err ? String((err as { name: unknown }).name) : '';
  if (name === 'NotAllowedError' || name === 'PermissionDeniedError') {
    return SCAN_ERROR_PERMISSION;
  }
  return SCAN_ERROR_CAMERA;
}

/** Stop every track. Safe on null. Call on close, success, error, and unmount. */
export function stopMediaStream(stream: MediaStream | null | undefined): void {
  if (!stream) return;
  const tracks = stream.getTracks();
  for (const track of tracks) {
    try {
      track.stop();
    } catch {
      /* ignore — teardown must not throw */
    }
  }
}
