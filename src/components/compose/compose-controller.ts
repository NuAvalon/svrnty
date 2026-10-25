// src/components/compose/compose-controller.ts
// The state machine behind the sign card: arrivals -> queue -> ONE card -> Approve/Decline -> hand-back. Plain TypeScript with every effect injected
// (clock, pin read, note read, signer, words, log), so each rule has a test that can fail and the React components stay thin renderers of `getSnapshot()`.
//
// RULES THIS FILE OWNS (the pure rules live in src/lib/compose/*):
//   - Arrivals are handled ONE AT A TIME (a promise chain), so two notes landing together cannot both read the same queue and lose one.
//   - The note is READ BACK FROM THE STORE by id. The only writers of inbound records in the browser notes store are acceptInboundNote (verifyNoteSender
//     BEFORE isAdmitted) and the outbound local copy (direction 'outbound', ignored by receiveComposeNote). That is the whole basis for passing
//     `authenticatedByAcceptance: true` below; anything that could write an inbound record some other way must not be wired to this controller.
//   - approve(shownNonce): the click names the card the person SAW. If the queue moved on (the shown card expired and the next one slid under the
//     pointer) the click signs NOTHING. approve() also re-builds the card model and refuses unless it offers an Approve (so a missing words
//     derivation, a Weft request or the production switch being off can never be bypassed by calling it).
//   - A second approve() while one is signing is ignored (no double signature, no second hand-back).
//   - A pin read that throws is `unreadable` (blocked), never `absent` (Flint P2).
//   - C1 (Flint #1489): a request that was signed, declined or closed is REMEMBERED (compose-memory.ts, persisted encrypted, owner-scoped) until its own
//     expires_at, so a reload or a second tab cannot raise it again; the other tab's open card closes ("Handled in another tab."). Simultaneous Approve
//     in two tabs inside the same few milliseconds is NOT prevented here (no cross-tab lock); the portal's single-use nonce (C2) is the backstop.
//   - C3: the passive blocked-key notice is fixed copy, shown at most once per sender per 24 h; the sender's key is only ever a Settings candidate.
//   - A failed signature keeps a notice on screen with one Close (Hypatia §6d); nothing is claimed signed.
import { current, emptyQueue, prune, resolve, type QueueItem, type QueueState } from '@/lib/compose/compose-queue';
import { buildCardModel, type CardModel, type DeriveWords } from '@/lib/compose/compose-card-model';
import { buildHandBackModel, type HandBackModel } from '@/lib/compose/compose-handback';
import { isComposeShaped, receiveComposeNote } from '@/lib/compose/compose-receive';
import { CARD_COPY } from '@/lib/compose/compose-card-copy';
import { COMPOSE_MAX_WINDOW_MS } from '@/lib/compose/compose-request';
import { REFUSAL_TTL_MS } from '@/lib/compose/compose-queue';
import { addResolved, emptyMemory, isResolved, markNoticed, mergeMemory, shouldNotice, type ComposeMemory } from '@/lib/compose/compose-memory';
import type { ResolvedBus } from './compose-bus';
import { rememberCandidate, dropCandidate, type PinState } from '@/lib/compose/compose-pin';
import type { SignResult } from '@/lib/compose/compose-sign';

export interface ArrivalEvent {
  note_id?: string;
  thread_id?: string;
}

/** What the store gives back for one note id. `from_fingerprint` is the proven sender (see the header). */
export interface StoredNote {
  note_id: string;
  from_fingerprint: string;
  body: string;
  direction: string;
}

export interface ControllerDeps {
  now: () => Date;
  getPin: () => Promise<PinState>;
  readNote: (evt: ArrivalEvent) => Promise<StoredNote | null>;
  sign: (raw: unknown, shown: Readonly<Record<string, string>>, now: Date) => Promise<SignResult>;
  deriveWords: DeriveWords;
  /** composeWordsConfirmed(): the production switch. false = no Approve anywhere. */
  wordsConfirmed: boolean;
  /** Fixed text only. Never a request's own text, never a key, never an IP. */
  log: (line: string) => void;
  /** The persisted memory (C1/C3). An unreadable record must come back as an EMPTY memory (see client-store.getComposeMemory). */
  loadMemory: () => Promise<ComposeMemory>;
  saveMemory: (m: ComposeMemory) => Promise<void>;
  /** Cross-tab "handled" messages. */
  bus: ResolvedBus;
}

export interface ControllerSnapshot {
  /** The hand-back, if one is on screen. It takes the screen until dismissed; the next card waits behind it. */
  handBack: HandBackModel | null;
  /** The ONE card to show now (null when there is none or a hand-back is showing). */
  card: CardModel | null;
  /** The nonce of the shown card (a refusal card may have none): what approve()/dismissCard() must be given. */
  cardNonce: string | null;
  /** More cards waiting behind the shown one. */
  waiting: number;
  /** A signature is being made. */
  signing: boolean;
  /** A signature attempt failed: fixed text and one Close (Hypatia §6d). Takes the screen like the hand-back. */
  failed: { notice: string; close: string } | null;
  /** Shown briefly when another tab handled the card this tab was showing. */
  handledElsewhere: string | null;
  /** PASSIVE, no buttons: a blocked-key notice. */
  passiveNotice: string | null;
  /** Recently seen VERIFIED sender fps (newest first) the Settings panel may offer to compare. */
  candidates: readonly string[];
}

type Listener = () => void;

/** How long "Handled in another tab." stays up. */
const HANDLED_ELSEWHERE_MS = 3000;

export class ComposeController {
  private queue: QueueState = emptyQueue();
  private candidates: readonly string[] = [];
  private passiveNotice: string | null = null;
  private handBack: HandBackModel | null = null;
  private failed = false;
  private handledElsewhere = false;
  private memory: ComposeMemory = emptyMemory();
  private persistChain: Promise<void> = Promise.resolve();
  private handledUntilMs = 0;
  private unsubBus: () => void;
  private signing = false;
  private chain: Promise<void> = Promise.resolve();
  private listeners = new Set<Listener>();
  private snapshot: ControllerSnapshot;

  constructor(private readonly deps: ControllerDeps) {
    this.snapshot = this.build();
    this.unsubBus = deps.bus.subscribe((nonce) => this.onRemoteResolved(nonce));
  }

  /** Stop listening to other tabs (the host calls this when it unmounts). */
  dispose(): void {
    this.unsubBus();
  }

  subscribe = (l: Listener): (() => void) => {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  };

  /** Stable between changes (useSyncExternalStore requires it). */
  getSnapshot = (): ControllerSnapshot => this.snapshot;

  private build(): ControllerSnapshot {
    const now = this.deps.now();
    const pending = prune(this.queue, now).pending;
    const item = this.handBack || this.failed ? null : current(this.queue, now);
    const card = item ? buildCardModel(item, this.deps.deriveWords, { wordsConfirmed: this.deps.wordsConfirmed }) : null;
    return {
      handBack: this.handBack,
      card,
      cardNonce: item ? item.nonce : null,
      waiting: Math.max(0, pending.length - (item ? 1 : 0)),
      signing: this.signing,
      failed: this.failed ? { notice: CARD_COPY.signFailed.notice, close: CARD_COPY.signFailed.close } : null,
      handledElsewhere: this.handledElsewhere ? CARD_COPY.handledElsewhere : null,
      passiveNotice: this.passiveNotice,
      candidates: this.candidates,
    };
  }

  private emit(): void {
    this.snapshot = this.build();
    for (const l of [...this.listeners]) {
      try {
        l();
      } catch {
        /* a bad subscriber never blocks the others */
      }
    }
  }

  /** A note was accepted and stored. Serialised: arrivals are processed one after another. */
  onArrival(evt: ArrivalEvent): Promise<void> {
    this.chain = this.chain.then(() => this.handle(evt)).catch(() => undefined);
    return this.chain;
  }

  private async handle(evt: ArrivalEvent): Promise<void> {
    let rec: StoredNote | null = null;
    try {
      rec = await this.deps.readNote(evt);
    } catch {
      rec = null;
    }
    // Only an inbound, compose-shaped note matters; plain chat touches nothing (no memory read, no log, no candidate).
    if (!rec || rec.direction !== 'inbound' || !isComposeShaped(rec.body)) return;
    const nowMs = this.deps.now().getTime();
    await this.refreshMemory(nowMs);
    const nonce = nonceOfBody(rec.body);
    if (nonce !== null && isResolved(this.memory, nonce, nowMs)) {
      this.deps.log('A sign request that was already handled arrived again. It was not shown.');
      return; // C1: signed, declined or closed already (in this tab, another tab, or before a reload): never a second card
    }
    let pin: PinState;
    try {
      pin = await this.deps.getPin();
    } catch {
      pin = { state: 'unreadable' }; // we could not look: damaged, not absent
    }
    const now = this.deps.now();
    const { queue, event } = receiveComposeNote(
      { note_id: rec.note_id, from_fingerprint: rec.from_fingerprint, body: rec.body, direction: rec.direction, authenticatedByAcceptance: true },
      pin,
      this.queue,
      now,
    );
    this.queue = queue;
    switch (event.kind) {
      case 'ignored':
        return; // plain chat: nothing changes, nothing is logged
      case 'no-card':
        this.deps.log(event.logLine);
        return;
      case 'unpinned':
        this.candidates = rememberCandidate(this.candidates, event.candidate);
        this.deps.log(event.logLine);
        this.emit();
        return;
      case 'blocked':
        this.candidates = rememberCandidate(this.candidates, event.candidate);
        // C3: the notice is fixed copy and appears at most once per sender per 24 h; the key itself only ever becomes a Settings candidate.
        if (shouldNotice(this.memory, rec.from_fingerprint, now.getTime())) {
          this.passiveNotice = event.notice;
          this.memory = markNoticed(this.memory, rec.from_fingerprint, now.getTime());
          void this.persist();
        }
        this.emit();
        return;
      case 'bad-note':
        return; // a pinned sender's malformed note: no copy exists, nothing is shown
      default:
        if (event.logLine) this.deps.log(event.logLine);
        this.emit();
    }
  }

  private async refreshMemory(nowMs: number): Promise<void> {
    let stored: ComposeMemory;
    try {
      stored = await this.deps.loadMemory();
    } catch {
      stored = emptyMemory(); // a lost memory only costs one extra card for a still-unexpired replay
    }
    this.memory = mergeMemory(this.memory, stored, nowMs);
  }

  /** Write the memory, merged with whatever another tab wrote since we read. Serialised; a failure is logged and the in-memory copy still protects this tab. */
  private persist(): Promise<void> {
    this.persistChain = this.persistChain.then(async () => {
      try {
        const nowMs = this.deps.now().getTime();
        const stored = await this.deps.loadMemory().catch(() => emptyMemory());
        const merged = mergeMemory(stored, this.memory, nowMs);
        this.memory = merged;
        await this.deps.saveMemory(merged);
      } catch {
        this.deps.log('The compose memory could not be saved.');
      }
    });
    return this.persistChain;
  }

  /** Remember that this item is finished with (signed, declined, failed or closed) until its own expires_at, in this tab, on disk and in other tabs. */
  private markResolved(item: QueueItem): void {
    if (item.nonce === null) return; // a refusal with no readable nonce cannot be remembered
    const nowMs = this.deps.now().getTime();
    const until = item.kind === 'sign' ? item.expiresAtMs : item.receivedAtMs + REFUSAL_TTL_MS;
    this.memory = addResolved(this.memory, item.nonce, until, nowMs);
    void this.persist();
    this.deps.bus.emit(item.nonce);
  }

  /** Another tab finished with this request. Close our copy of the card (briefly saying so), unless we are in the middle of signing it ourselves. */
  private onRemoteResolved(nonce: string): void {
    const nowMs = this.deps.now().getTime();
    const it = this.queue.pending.find((i) => i.nonce === nonce);
    const until = it ? (it.kind === 'sign' ? it.expiresAtMs : it.receivedAtMs + REFUSAL_TTL_MS) : nowMs + COMPOSE_MAX_WINDOW_MS;
    this.memory = addResolved(this.memory, nonce, until, nowMs);
    if (!it) return;
    const shown = current(this.queue, this.deps.now());
    if (this.signing && shown === it) return; // we are signing it right now; the person already pressed Approve here
    this.queue = resolve(this.queue, it);
    if (shown === it && !this.handBack && !this.failed) {
      this.handledElsewhere = true;
      this.handledUntilMs = nowMs + HANDLED_ELSEWHERE_MS;
    }
    this.emit();
  }

  /** Re-evaluate time (an expired card disappears). Call on an interval. Emits only when what is shown changed. */
  tick(): void {
    if (this.handledElsewhere && this.deps.now().getTime() >= this.handledUntilMs) {
      this.handledElsewhere = false;
      this.emit();
      return;
    }
    const next = this.build();
    const prev = this.snapshot;
    if (next.cardNonce !== prev.cardNonce || next.waiting !== prev.waiting || (next.card === null) !== (prev.card === null)) this.emit();
  }

  /** Approve the card the person was LOOKING AT (`shownNonce`). Does nothing unless that card is still the current one and offers an Approve. */
  async approve(shownNonce: string): Promise<void> {
    if (this.signing || this.handBack || this.failed) return;
    const now = this.deps.now();
    const item = current(this.queue, now);
    if (!item || item.kind !== 'sign' || item.nonce !== shownNonce) return;
    const model = buildCardModel(item, this.deps.deriveWords, { wordsConfirmed: this.deps.wordsConfirmed });
    if (model.mode !== 'sign' || model.approve === null) return;
    this.signing = true;
    this.emit();
    let res: SignResult;
    try {
      res = await this.deps.sign(item.raw, item.request.object, this.deps.now());
    } catch {
      res = { ok: false, reason: 'sign-failed' };
    }
    this.signing = false;
    this.queue = resolve(this.queue, item);
    this.markResolved(item); // finished with, whatever the outcome: a retry is a NEW request from the portal
    if (res.ok) {
      this.handBack = buildHandBackModel(res.signed);
    } else {
      this.failed = true; // Hypatia §6d: fixed text + one Close; never the error's own text
      this.deps.log(`A sign request was not signed (${res.reason}).`);
    }
    this.emit();
  }

  /** "Don't sign", or Close on a refusal card. Removes the shown card and remembers it as handled so a replay cannot raise it again. */
  dismissCard(shownNonce: string | null): void {
    if (this.signing || this.handBack || this.failed) return;
    const item = current(this.queue, this.deps.now());
    if (!item) return;
    if (item.nonce !== shownNonce) return;
    this.queue = resolve(this.queue, item);
    this.markResolved(item);
    this.emit();
  }

  /** Done with the hand-back screen. */
  dismissHandBack(): void {
    if (!this.handBack) return;
    this.handBack = null;
    this.emit();
  }

  /** Close on the "couldn't sign" notice. */
  dismissFailed(): void {
    if (!this.failed) return;
    this.failed = false;
    this.emit();
  }

  dismissPassiveNotice(): void {
    if (this.passiveNotice === null) return;
    this.passiveNotice = null;
    this.emit();
  }

  /** Settings: "Keep it blocked" / after a pin is written. */
  forgetCandidate(fp: string): void {
    const next = dropCandidate(this.candidates, fp);
    if (next.length === this.candidates.length) return;
    this.candidates = next;
    this.emit();
  }

  /** Lock / identity switch: forget everything held in this tab's memory (the persisted memory stays on disk, encrypted). */
  reset(): void {
    this.queue = emptyQueue();
    this.candidates = [];
    this.passiveNotice = null;
    this.handBack = null;
    this.failed = false;
    this.handledElsewhere = false;
    this.memory = emptyMemory();
    this.signing = false;
    this.emit();
  }
}

const NONCE_RE = /^[0-9a-f]{32}$/;
/** The request nonce of a compose-shaped note body (already sniffed and size-bounded by isComposeShaped), or null. Never throws. */
function nonceOfBody(body: string): string | null {
  try {
    const n = (JSON.parse(body) as { request?: { nonce?: unknown } } | null)?.request?.nonce;
    return typeof n === 'string' && NONCE_RE.test(n) ? n : null;
  } catch {
    return null;
  }
}

export type { QueueItem };
