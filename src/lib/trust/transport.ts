// src/lib/trust/transport.ts
// Channel-agnostic trust signal transport layer.
// Signals are signed JSON — this layer handles formatting and delivery.
//
// Phase 1 (3/17): Signal deep links + Web Share API + clipboard
// Phase 2: Signal bot (programmatic), email adapter
// Phase 3: Mesh relay (agent-to-agent)

import type { SignedSignal, TrustSignal } from './types';

// --- Transport Interface ---

export interface TransportAdapter {
  readonly name: string;
  readonly icon: string;

  /** Can this transport be used in the current environment? */
  isAvailable(): boolean;

  /** Send a signed signal to a recipient. Returns true if handoff succeeded. */
  send(signal: SignedSignal, recipientHandle: string): Promise<boolean>;

  /** Format a signed signal for this channel (human-readable + verifiable). */
  format(signal: SignedSignal): string;
}

// --- Signal Format ---

const SIGNAL_HEADER = '[SVRNTY]';
const SIGNAL_SEPARATOR = '---';

/**
 * Format a signed signal as a compact, human-readable message.
 * The payload below the separator is the verifiable JSON.
 */
export function formatSignalMessage(signal: SignedSignal): string {
  const typeLabel = signalTypeLabel(signal.payload);
  const time = new Date(signal.timestamp).toLocaleString('en-US', {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });

  const header = [
    SIGNAL_HEADER,
    `${typeLabel}`,
    `From: ${signal.from.slice(0, 16)}...`,
    `To: ${signal.to.slice(0, 16)}...`,
    `Time: ${time}`,
  ];

  // Add type-specific context
  const context = signalContext(signal.payload);
  if (context) header.push(context);

  // The payload is base64-encoded JSON — compact, pasteable, verifiable
  const payloadJson = JSON.stringify({
    p: signal.payload,
    f: signal.from,
    t: signal.to,
    ts: signal.timestamp,
    s: signal.signature,
    pq: signal.pq_signature || null,
  });
  const payloadB64 = typeof btoa === 'function'
    ? btoa(payloadJson)
    : Buffer.from(payloadJson).toString('base64');

  return [...header, SIGNAL_SEPARATOR, payloadB64].join('\n');
}

/**
 * Parse a received signal message back into a SignedSignal.
 * Handles both raw JSON and the formatted message format.
 */
export function parseSignalMessage(text: string): SignedSignal | null {
  const trimmed = text.trim();

  // Try raw JSON first
  try {
    const parsed = JSON.parse(trimmed);
    if (parsed.payload && parsed.from && parsed.to && parsed.signature) {
      return parsed as SignedSignal;
    }
  } catch { /* not raw JSON */ }

  // Try formatted message
  const sepIdx = trimmed.indexOf(SIGNAL_SEPARATOR);
  if (sepIdx === -1) return null;

  const payloadB64 = trimmed.slice(sepIdx + SIGNAL_SEPARATOR.length).trim();
  if (!payloadB64) return null;

  try {
    const payloadJson = typeof atob === 'function'
      ? atob(payloadB64)
      : Buffer.from(payloadB64, 'base64').toString('utf8');
    const compact = JSON.parse(payloadJson);

    return {
      payload: compact.p,
      from: compact.f,
      to: compact.t,
      timestamp: compact.ts,
      signature: compact.s,
      pq_signature: compact.pq || undefined,
    };
  } catch {
    return null;
  }
}

// --- Signal (the app) Transport ---

export class SignalTransport implements TransportAdapter {
  readonly name = 'Signal';
  readonly icon = 'signal';

  isAvailable(): boolean {
    return typeof navigator !== 'undefined' && 'share' in navigator;
  }

  async send(signal: SignedSignal, recipientHandle: string): Promise<boolean> {
    const message = this.format(signal);

    // Try Web Share API first (works on mobile, opens Signal directly)
    if (navigator.share) {
      try {
        await navigator.share({
          title: `SVRNTY Trust Signal`,
          text: message,
        });
        return true;
      } catch (err) {
        // User cancelled or share failed — fall through to clipboard
        if ((err as Error).name === 'AbortError') return false;
      }
    }

    // Fallback: copy to clipboard
    return copyToClipboard(message);
  }

  format(signal: SignedSignal): string {
    return formatSignalMessage(signal);
  }

  /**
   * Generate a Signal.me link for a phone number or username.
   */
  static userLink(handle: string): string {
    if (handle.startsWith('+')) {
      return `https://signal.me/#p/${encodeURIComponent(handle)}`;
    }
    const username = handle.startsWith('@') ? handle.slice(1) : handle;
    return `https://signal.me/#eu/${encodeURIComponent(username)}`;
  }

  static isGroupLink(url: string): boolean {
    return url.startsWith('https://signal.group/');
  }
}

// --- Clipboard Transport (universal fallback) ---

export class ClipboardTransport implements TransportAdapter {
  readonly name = 'Clipboard';
  readonly icon = 'clipboard';

  isAvailable(): boolean {
    return typeof navigator !== 'undefined' && 'clipboard' in navigator;
  }

  async send(signal: SignedSignal): Promise<boolean> {
    return copyToClipboard(this.format(signal));
  }

  format(signal: SignedSignal): string {
    return formatSignalMessage(signal);
  }
}

// --- Transport Registry ---

const transports: TransportAdapter[] = [];

export function registerTransport(adapter: TransportAdapter): void {
  if (!transports.some(t => t.name === adapter.name)) {
    transports.push(adapter);
  }
}

export function getAvailableTransports(): TransportAdapter[] {
  return transports.filter(t => t.isAvailable());
}

export function getTransport(name: string): TransportAdapter | undefined {
  return transports.find(t => t.name === name);
}

// Register defaults
registerTransport(new SignalTransport());
registerTransport(new ClipboardTransport());

// --- Helpers ---

function signalTypeLabel(payload: TrustSignal): string {
  switch (payload.type) {
    case 'vouch': return 'Vouch';
    case 'concern': return 'Concern';
    case 'break': return 'Trust Break';
    case 'sync': return `Sync — ${payload.trusted ? 'Trusted' : 'Known'}`;
    case 'introduce': return `Introduction — ${payload.name}`;
    case 'key_rotation': return 'Key Rotation';
    case 'recovery_request': return 'Recovery Request';
    default: return 'Signal';
  }
}

function signalContext(payload: TrustSignal): string | null {
  switch (payload.type) {
    case 'vouch': return `Subject: ${payload.subject.slice(0, 16)}...`;
    case 'concern': return `Subject: ${payload.subject.slice(0, 16)}...\nDetail: ${payload.detail.slice(0, 60)}`;
    case 'break': return `Subject: ${payload.subject.slice(0, 16)}...${payload.reason ? `\nReason: ${payload.reason.slice(0, 60)}` : ''}`;
    case 'introduce': return `Introducing: ${payload.name}\nKey: ${payload.pub_key.slice(0, 32)}...`;
    case 'key_rotation': return `Old: ${payload.old_fingerprint.slice(0, 16)}...\nNew: ${payload.new_fingerprint.slice(0, 16)}...`;
    default: return null;
  }
}

async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* clipboard API failed */ }

  // Fallback: textarea trick
  try {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    const success = document.execCommand('copy');
    document.body.removeChild(textarea);
    return success;
  } catch {
    return false;
  }
}
