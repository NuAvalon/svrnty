// Classify an inbound svrnty note body for poll-json (= the depositor's _is_protocol_body,
// outpost/flint/devin_quarantine.py). Pure: no I/O, no keys. Shared by devin-comm.ts + its test.
export const TR_BODY = 'svrnty-tr-v1';

export type InboundKind = 'tr' | 'loom' | 'plain';

/** 'tr' = triple-ratchet packet (journal its DECRYPTED plaintext only); 'loom' = coordination
 *  envelope (machine fan-out, not a message); 'plain' = readable text. Anything that does not
 *  parse as one of the protocol objects is 'plain': surface it, never silently drop a message. */
export function classifyInbound(body: string): InboundKind {
  try {
    const o = JSON.parse(body);
    if (o && typeof o === 'object' && !Array.isArray(o)) {
      if (o.type === TR_BODY && o.packet) return 'tr';
      if ('loom_v' in o) return 'loom';
    }
  } catch { /* not JSON → readable text */ }
  return 'plain';
}
