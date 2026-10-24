// Classify an inbound svrnty note body for poll-json (= the depositor's _is_protocol_body,
// outpost/flint/devin_quarantine.py). Pure: no I/O, no keys. Shared by devin-comm.ts + its test.
import { createHash } from 'node:crypto';
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
/** The same sanitizer for journal-row fields a renderer might show (Flint #310: notice rows carry no raw peer value). */
export const safeToken = tok;

/** A loom envelope ADDRESSED to this cell (a channel_post whose mentions include ownFp, or a
 *  task_request assigned to ownFp) → a one-line NOTICE for the journal; anything else
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
  if (o.type === 'task_request' && p.assignee === ownFp) {
    return `[loom task_request ${where} task ${tok(p.task_id)}] assigned to you; brief withheld until our loom reader lands, read it in your store.json`;
  }
  return null;   // open task_requests are lane-ambient: see openTaskChannel / openTasksNotice
}

/** The channel of a task_request left OPEN to the lane (no assignee), else null. Open tasks are
 *  lane-ambient (Lever A): poll-json collapses them into ONE notice per peer per pass, so a peer
 *  posting N open tasks can't cause N wakes for every cell in the lane (Flint #263). */
export function openTaskChannel(body: string): string | null {
  try {
    const o = JSON.parse(body);
    const p = o && typeof o.payload === 'object' && o.payload ? o.payload : null;
    if (o?.type !== 'task_request' || !p) return null;
    if (typeof p.assignee === 'string' && p.assignee !== '') return null;
    return tok(p.channel_id ?? p.channel);
  } catch { return null; }
}

/** One notice for a peer's open task_requests. note_id is a hash of the sorted note ids, so the
 *  journal's (peer_fp, note_id) skip-set dedups it; a new open task changes the set → one new notice. */
export function openTasksNotice(peerFp: string, items: { note_id: string; channel: string }[]):
    { note_id: string; text: string } {
  const ids = items.map((i) => i.note_id).sort();
  const note_id = 'open-tasks:' + createHash('sha256').update(ids.join('\n')).digest('hex').slice(0, 24);
  const chans = [...new Set(items.map((i) => i.channel))].sort().join(', ');
  return { note_id, text: `[loom] ${ids.length} open task_request(s) in ${chans} from ${tok(peerFp).slice(0, 8)}; briefs withheld until our loom reader lands, read them in your store.json` };
}

/** One notice for a peer's notes that never decrypted (tombstoned after MAX_ATTEMPTS). Without it a dead
 *  note is only a `dead` counter on stdout: nobody is told (Archie #180230, the #637 silent-loss class).
 *  Called with only the NEWLY dead notes (the caller marks announced ones), so a later death never
 *  re-counts old ones (Archie #180425). Same set-hash dedup as openTasksNotice. Body-less: no ciphertext, no sender text, only count + window. */
export function deadNotesNotice(peerFp: string, items: { note_id: string; sent_at: string }[], maxAttempts: number):
    { note_id: string; text: string } {
  const ids = items.map((i) => i.note_id).sort();
  const note_id = 'dead-notes:' + createHash('sha256').update(ids.join('\n')).digest('hex').slice(0, 24);
  const times = items.map((i) => tok(i.sent_at)).sort();
  return { note_id, text: `[svrnty] ${ids.length} note(s) from ${tok(peerFp).slice(0, 8)} could not be decrypted after ${maxAttempts} tries (sent ${times[0]} to ${times.at(-1)}); ask the sender to resend` };
}
