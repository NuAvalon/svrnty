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
import { current, emptyQueue, prune, resolve, type QueueItem, type QueueState } from '@/lib/compose/compose-queue';
import { buildCardModel, type CardModel, type DeriveWords } from '@/lib/compose/compose-card-model';
import { buildHandBackModel, type HandBackModel } from '@/lib/compose/compose-handback';
import { receiveComposeNote } from '@/lib/compose/compose-receive';
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
  /** PASSIVE, no buttons: a blocked-key notice. */
  passiveNotice: string | null;
  /** Recently seen VERIFIED sender fps (newest first) the Settings panel may offer to compare. */
  candidates: readonly string[];
}

type Listener = () => void;

export class ComposeController {
  private queue: QueueState = emptyQueue();
  private candidates: readonly string[] = [];
  private passiveNotice: string | null = null;
  private handBack: HandBackModel | null = null;
  private signing = false;
  private chain: Promise<void> = Promise.resolve();
  private listeners = new Set<Listener>();
  private snapshot: ControllerSnapshot;

  constructor(private readonly deps: ControllerDeps) {
    this.snapshot = this.build();
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
    const item = this.handBack ? null : current(this.queue, now);
    const card = item ? buildCardModel(item, this.deps.deriveWords, { wordsConfirmed: this.deps.wordsConfirmed }) : null;
    return {
      handBack: this.handBack,
      card,
      cardNonce: item ? item.nonce : null,
      waiting: Math.max(0, pending.length - (item ? 1 : 0)),
      signing: this.signing,
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
    if (!rec) return;
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
        this.passiveNotice = event.notice;
        this.emit();
        return;
      case 'bad-note':
        return; // a pinned sender's malformed note: no copy exists, nothing is shown
      default:
        if (event.logLine) this.deps.log(event.logLine);
        this.emit();
    }
  }

  /** Re-evaluate time (an expired card disappears). Call on an interval. Emits only when what is shown changed. */
  tick(): void {
    const next = this.build();
    const prev = this.snapshot;
    if (next.cardNonce !== prev.cardNonce || next.waiting !== prev.waiting || (next.card === null) !== (prev.card === null)) this.emit();
  }

  /** Approve the card the person was LOOKING AT (`shownNonce`). Does nothing unless that card is still the current one and offers an Approve. */
  async approve(shownNonce: string): Promise<void> {
    if (this.signing || this.handBack) return;
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
    if (res.ok) {
      this.handBack = buildHandBackModel(res.signed);
    } else {
      // No copy exists for a failed signature (open item for Hypatia): the card goes away, nothing is claimed, a fixed line is logged.
      this.deps.log(`A sign request was not signed (${res.reason}).`);
    }
    this.emit();
  }

  /** "Don't sign", or Close on a refusal card. Removes the shown card; its nonce stays remembered so a replay cannot raise it again. */
  dismissCard(shownNonce: string | null): void {
    if (this.signing || this.handBack) return;
    const item = current(this.queue, this.deps.now());
    if (!item) return;
    if (item.nonce !== shownNonce) return;
    this.queue = resolve(this.queue, item);
    this.emit();
  }

  /** Done with the hand-back screen. */
  dismissHandBack(): void {
    if (!this.handBack) return;
    this.handBack = null;
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

  /** Test seam / lock: forget everything held in memory (the queue, candidates, notices). */
  reset(): void {
    this.queue = emptyQueue();
    this.candidates = [];
    this.passiveNotice = null;
    this.handBack = null;
    this.signing = false;
    this.emit();
  }
}

export type { QueueItem };
