// src/lib/compose/compose-card-model.ts
// The sign card as DATA: what is shown and whether Approve exists at all. PURE: no React, no keys, no I/O, so every rule has a test that can fail.
// The component (ComposeSignCard.tsx) renders this and nothing else; it holds no decision of its own.
//
// RULES (Hypatia's card copy §3/§4/§6b, Flint S2/R2/R3):
//   - WYSIWYS: `body` / `taskTitle` / `location` are the validated request's fields verbatim. Nothing is shortened, scrolled, or re-wrapped here.
//   - Approve is offered only when ALL hold: it is a sign item, the four check-words are known, and the fleet is accepted (Weft is view-only until its side exists).
//   - A refused request (hidden characters) gets a notice, the offending text with [U+XXXX] markers, and ONLY Close: there is no Approve of any kind.
//   - The words are supplied by an injected function. If it returns anything but four plain words the card fails CLOSED (no Approve, a plain notice).
import { CARD_COPY } from './compose-card-copy';
import type { QueueItem } from './compose-queue';

export type DeriveWords = (object: Readonly<Record<string, string>>) => readonly string[];

export interface Segment {
  text: string;
  /** True for a [U+XXXX] marker standing in for a refused character. */
  marker: boolean;
}

export interface SignCardModel {
  mode: 'sign';
  kind: 'post' | 'task';
  title: string;
  intro: string;
  /** Post: `<fleet> · <thread>`. Task: null. */
  location: string | null;
  /** Task: `To: <agent>` / `To: the orchestrator, to route`. Post: null. */
  toLine: string | null;
  /** Task: the title, exactly. Post: null. */
  taskTitle: string | null;
  /** The FULL body exactly as it will be posted. */
  body: string;
  /** Task with a dag_node: `Linked to step: <dag_node>`. */
  linkedLine: string | null;
  /** `Check these words match the portal: w1 w2 w3 w4`, or null when the words are unavailable (then there is no Approve). */
  wordsLine: string | null;
  /** Shown instead of the words line when they are unavailable. */
  noWordsNotice: string | null;
  /** Weft requests are view-only until the Weft's side accepts signed posts. */
  weftNotice: string | null;
  /** The Approve label, or null: no Approve button may be rendered. */
  approve: string | null;
  decline: string;
  footnote: string;
}

export interface RefusedCardModel {
  mode: 'refused';
  title: string;
  notice: string;
  /** Which field the markers belong to ('body', 'thread', 'title', ...), or null if unknown. */
  field: string | null;
  /** The offending field's text with each refused character replaced by a [U+XXXX] marker. Empty when the text is unavailable. */
  segments: Segment[];
  close: string;
}

export type CardModel = SignCardModel | RefusedCardModel;

export interface CardOptions {
  /** True once the Weft's side accepts signed posts. Default false: Weft requests are view-only. */
  weftAccepted?: boolean;
  /**
   * True ONLY once the PORTAL's own test shows it derives the same four words from the object it serializes into the note (Flint lane:portal #1474 (3),
   * Hypatia: the card stays no-Approve until the vectors are pinned and green on both sides). Default false: with it off the words are treated as
   * unavailable, so there is NO Approve even when the app could derive them. The host reads composeWordsConfirmed().
   */
  wordsConfirmed?: boolean;
}

const WORD = /^[^\s]+$/u;
const marker = (cp: number) => `[U+${cp.toString(16).toUpperCase().padStart(4, '0')}]`;

/** Replace each code point at `indices` (code-point indices) with a visible marker. The refused characters themselves are never emitted. */
export function segmentWithMarkers(text: string, indices: readonly number[]): Segment[] {
  const bad = new Set(indices);
  const out: Segment[] = [];
  let run = '';
  let i = 0;
  for (const ch of text) {
    if (bad.has(i)) {
      if (run) { out.push({ text: run, marker: false }); run = ''; }
      out.push({ text: marker(ch.codePointAt(0)!), marker: true });
    } else {
      run += ch;
    }
    i++;
  }
  if (run) out.push({ text: run, marker: false });
  return out;
}

function validWords(w: unknown): w is readonly string[] {
  return Array.isArray(w) && w.length === 4 && w.every((x) => typeof x === 'string' && WORD.test(x));
}

export function buildCardModel(item: QueueItem, deriveWords?: DeriveWords, opts: CardOptions = {}): CardModel {
  if (item.kind === 'refusal') {
    return {
      mode: 'refused',
      title: CARD_COPY.post.title,
      notice: CARD_COPY.refused.notice,
      field: item.refusal.field ?? null,
      segments: item.shownText !== undefined ? segmentWithMarkers(item.shownText, item.refusal.indices ?? []) : [],
      close: CARD_COPY.refused.close,
    };
  }
  const { request } = item;
  const o = request.object;
  let words: readonly string[] | null = null;
  try {
    const w = deriveWords && opts.wordsConfirmed === true ? deriveWords(o) : undefined;
    words = validWords(w) ? w : null;
  } catch {
    words = null; // a throwing derivation fails closed like a missing one
  }
  const weftBlocked = o.fleet === 'weft' && opts.weftAccepted !== true;
  const canApprove = words !== null && !weftBlocked;
  const isTask = request.kind === 'task';
  const C = isTask ? CARD_COPY.task : CARD_COPY.post;
  return {
    mode: 'sign',
    kind: request.kind,
    title: C.title,
    intro: C.intro(o.origin),
    location: isTask ? null : `${o.fleet} · ${o.thread}`,
    toLine: isTask ? (o.target === 'route' ? CARD_COPY.task.toOrchestrator : CARD_COPY.task.toAgent(o.target)) : null,
    taskTitle: isTask ? o.title : null,
    body: o.body,
    linkedLine: isTask && o.dag_node !== undefined ? CARD_COPY.task.linked(o.dag_node) : null,
    wordsLine: words !== null ? CARD_COPY.words(words) : null,
    noWordsNotice: words === null ? CARD_COPY.noWords : null,
    weftNotice: weftBlocked ? CARD_COPY.weftViewOnly : null,
    approve: canApprove ? C.approve : null,
    decline: C.decline,
    footnote: C.footnote,
  };
}
