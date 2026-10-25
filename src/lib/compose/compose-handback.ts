// src/lib/compose/compose-handback.ts
// What the "Signed. Not posted yet." screen shows and what Copy puts on the clipboard. PURE. The app observes only its OWN signature, never delivery
// (Hypatia §3 last screen, Apollo lane:portal #1178 Q3), so this screen points at no portal state and never says posted, sent or delivered as if done.
//
// THE PASTED SHAPE IS NOT PINNED WITH THE PORTAL (the spec says only "paste / deep link first"): this emits the signed object exactly as signComposeRequest
// returned it, compact JSON, FIXED key order {kind, object, suite, sig_packet_b64} with the object's own keys sorted, so the text is deterministic. It carries
// no key, no passphrase and nothing the portal did not already send us except the signature. If the portal parses a different shape, change it HERE, in one
// place, with a test.
import { CARD_COPY } from './compose-card-copy';
import type { SignedCompose } from './compose-sign';

export interface HandBackModel {
  title: string;
  body: string;
  /** The visible JSON, character for character what Copy copies. */
  json: string;
  copy: string;
  copied: string;
}

const sortedObject = (o: Readonly<Record<string, string>>): Record<string, string> =>
  Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k]]));

export function handBackText(s: SignedCompose): string {
  return JSON.stringify({ kind: s.kind, object: sortedObject(s.object), suite: s.suite, sig_packet_b64: s.sig_packet_b64 });
}

export function buildHandBackModel(s: SignedCompose): HandBackModel {
  return { title: CARD_COPY.handBack.title, body: CARD_COPY.handBack.body, json: handBackText(s), copy: CARD_COPY.handBack.copy, copied: CARD_COPY.handBack.copied };
}
