'use client';

/**
 * Mounted ONCE at the app shell (app/page.tsx, beside the always-on live-book poll), so a portal sign request reaches the person on whatever tab they
 * are on. It owns the tab's ComposeController, feeds it every accepted-note arrival, and renders the one card / the hand-back / the passive notice.
 *
 * WHERE THE TRUST COMES FROM: subscribeNoteArrivals fires only for notes the shell poll persisted through acceptInboundNote (verifyNoteSender BEFORE
 * isAdmitted), or for this tab's own sends (direction 'outbound', ignored). The controller re-reads the stored record by id and passes
 * `authenticatedByAcceptance: true`; see compose-controller.ts for the writer enumeration that justifies it.
 *
 * Renders nothing at all until there is something to show. No portal request ever opens a pin screen from here (Flint P1): only the Settings panel does.
 */

import { useEffect, useMemo } from 'react';
import { subscribeNoteArrivals } from '@/lib/notes/note-events';
import { listNotesForThread, isNotesStoreUnlocked, notesStoreOwner } from '@/lib/messaging/store';
import { getComposePinState, onSessionLock } from '@/lib/identity/client-store';
import { normalizeFingerprintHex } from '@/lib/identity/fingerprint';
import { loadOwnerNoteSender } from '@/components/notes/notes-keys';
import { signComposeRequest } from '@/lib/compose/compose-sign';
import { deriveComposeWords } from '@/lib/compose/compose-words';
import { composeWordsConfirmed } from '@/lib/compose/compose-words-gate';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { ComposeController, type ArrivalEvent, type StoredNote } from './compose-controller';
import { getActiveComposeController, setActiveComposeController, useComposeSnapshot } from './compose-registry';
import { ComposeCardView, ComposeHandBack } from './ComposeSignCard';

// The session lock hooks cannot be removed, so register exactly once for the module and let it find whichever controller is active.
let lockHookRegistered = false;
function ensureLockHook(): void {
  if (lockHookRegistered) return;
  lockHookRegistered = true;
  onSessionLock(() => getActiveComposeController()?.reset());
}

async function readStoredNote(ownerFp: string, evt: ArrivalEvent): Promise<StoredNote | null> {
  if (!evt.note_id || !evt.thread_id) return null;
  if (!isNotesStoreUnlocked() || normalizeFingerprintHex(notesStoreOwner() ?? '') !== ownerFp) return null; // not open FOR THIS owner: read nothing
  const rows = await listNotesForThread(evt.thread_id);
  const n = rows.find((r) => r.note_id === evt.note_id);
  return n ? { note_id: n.note_id, from_fingerprint: n.from_fingerprint, body: n.body, direction: n.direction } : null;
}

export function ComposeRequestHost({ identity }: { identity: unknown }) {
  const fp = useMemo(() => {
    const root = identity && typeof identity === 'object' ? (identity as { identity?: { fingerprint?: unknown } }) : {};
    const raw = root.identity?.fingerprint;
    return typeof raw === 'string' ? normalizeFingerprintHex(raw) : '';
  }, [identity]);

  useEffect(() => {
    if (!fp) return;
    ensureLockHook();
    const controller = new ComposeController({
      now: () => new Date(),
      getPin: () => getComposePinState(fp),
      readNote: (evt) => readStoredNote(fp, evt),
      sign: async (raw, shown, now) => {
        const owner = await loadOwnerNoteSender(fp, identity);
        if (!owner) return { ok: false, reason: 'sign-failed' };
        return signComposeRequest(raw, shown, now, { privateKeyArmored: owner.privateKeyArmored, passphrase: owner.passphrase });
      },
      deriveWords: deriveComposeWords,
      wordsConfirmed: composeWordsConfirmed(),
      log: (line) => console.info(line),
    });
    setActiveComposeController(controller);
    const off = subscribeNoteArrivals((evt) => {
      void controller.onArrival(evt);
    });
    const timer = setInterval(() => controller.tick(), 1000);
    return () => {
      clearInterval(timer);
      off();
      controller.reset();
      setActiveComposeController(null);
    };
    // Keyed on the fingerprint only: the identity object is re-created on refresh and must not tear the queue down.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fp]);

  const snap = useComposeSnapshot();
  const controller = getActiveComposeController();
  if (!snap || !controller) return null;

  return (
    <>
      {snap.passiveNotice !== null && snap.card === null && snap.handBack === null ? (
        <div
          role="status"
          data-testid="compose-passive-notice"
          style={{ position: 'fixed', left: 12, right: 12, bottom: 12, zIndex: 85, maxWidth: 520, margin: '0 auto', padding: '10px 12px', border: `1px solid ${E.border}`, borderRadius: 10, background: E.surfaceSolid, color: E.text, fontFamily: E.fontSans, fontSize: 13, lineHeight: 1.45, display: 'flex', gap: 10, alignItems: 'flex-start' }}
        >
          <span style={{ flex: 1 }}>{snap.passiveNotice}</span>
          <button type="button" aria-label="Close" data-testid="compose-passive-close" onClick={() => controller.dismissPassiveNotice()} style={{ background: 'transparent', border: 'none', color: E.muted, cursor: 'pointer', fontSize: 16, lineHeight: 1, minWidth: 32, minHeight: 32 }}>×</button>
        </div>
      ) : null}
      {snap.handBack !== null ? (
        <ComposeHandBack model={snap.handBack} onDone={() => controller.dismissHandBack()} />
      ) : snap.card !== null ? (
        <ComposeCardView
          card={snap.card}
          nonce={snap.cardNonce}
          busy={snap.signing}
          onApprove={() => {
            if (snap.cardNonce !== null) void controller.approve(snap.cardNonce);
          }}
          onDecline={() => controller.dismissCard(snap.cardNonce)}
        />
      ) : null}
    </>
  );
}
