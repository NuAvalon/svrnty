// Classify an inbound svrnty note body for poll-json (= the depositor's _is_protocol_body,
// outpost/flint/devin_quarantine.py). Pure: no I/O, no keys. Shared by devin-comm.ts + its test.
import { admitContact } from '../src/lib/trust/admit-contact';

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
      // STRICT (Archie #260): every real envelope carries loom_v === 1 (129/129 in a live store). A
      // bare `'loom_v' in o` let any note SKIP itself by adding a loom_v key = a message disguised as
      // machine traffic, silently dropped. Anything else with a loom_v key is readable → 'plain'.
      if (o.loom_v === 1) return 'loom';
    }
  } catch { /* not JSON → readable text */ }
  return 'plain';
}

export type JournalRoute = 'skip_unadmitted' | 'skip_loom' | 'tr' | 'plain';

/** poll-json's whole journal decision for one inbound note. A sender must be ADMITTED (in-book AND
 *  not blocked, the live accept path's own predicate): under survivor-safety v1.1 a block makes the
 *  sender vanish, so a blocked sender's earlier-stored notes must never resurface as EXT notices
 *  (Flint #260 review). Then 'tr' → trOpen (decrypted plaintext only), 'plain' → journal, loom → skip. */
export function routeInbound(contact: unknown, body: string): JournalRoute {
  if (!admitContact(contact)) return 'skip_unadmitted';
  const kind = classifyInbound(body);
  return kind === 'loom' ? 'skip_loom' : kind;
}

// Peer-chosen identifiers are echoed into a notice: plain tokens only, else '?'.
const SAFE_TOKEN = /^[A-Za-z0-9._:#/-]{1,64}$/;
const tok = (v: unknown): string => (typeof v === 'string' && SAFE_TOKEN.test(v) ? v : '?');

/** A loom envelope ADDRESSED to this cell (a channel_post whose mentions include ownFp, or a
 *  task_request assigned to ownFp or left open) → a one-line NOTICE for the journal; anything else
 *  → null (stays a counted skip). The notice never carries the post body or brief (M8): only type,
 *  channel, seq / task id, so a mention can't sit unseen until our loom reader (L2) lands
 *  (Archie #177969: Mneme's lane:ops posts to Archie). Call only for routeInbound === 'skip_loom'. */
export function loomNotice(body: string, ownFp: string): string | null {
  let o: { type?: unknown; payload?: Record<string, unknown> };
  try { o = JSON.parse(body); } catch { return null; }
  const p = o && typeof o.payload === 'object' && o.payload ? o.payload : null;
  if (!p || !ownFp) return null;
  const where = tok(p.channel_id ?? p.channel);
  if (o.type === 'channel_post') {
    const mentions = Array.isArray(p.mentions) ? p.mentions : [];
    if (!mentions.includes(ownFp)) return null;
    const seq = Number.isInteger(p.seq) ? ` seq ${p.seq}` : '';
    return `[loom channel_post ${where}${seq}] mentions you; body withheld until our loom reader lands, read it in your store.json`;
  }
  if (o.type === 'task_request') {
    const assignee = typeof p.assignee === 'string' ? p.assignee : '';
    if (assignee && assignee !== ownFp) return null;
    return `[loom task_request ${where} task ${tok(p.task_id)}] ${assignee ? 'assigned to you' : 'open to the lane'}; brief withheld until our loom reader lands, read it in your store.json`;
  }
  return null;
}
