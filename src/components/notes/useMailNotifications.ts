'use client';
// Phase 1 mail notifications: wires the note-arrival bus to decideMailNotification (src/lib/notes/mail-notifications.ts).
// Mounted once at the app shell. Does nothing unless the user turned it on in Settings and the browser granted permission.

import { useEffect, useRef } from 'react';
import { subscribeNoteArrivals } from '@/lib/notes/note-events';
import { getContactByFingerprint } from '@/lib/identity/client-store';
import {
  decideMailNotification,
  loadMailNotifyPrefs,
  notificationPermission,
  showMailNotification,
} from '@/lib/notes/mail-notifications';

export function useMailNotifications(args: { activeFingerprint: string | null; unlocked: boolean }): void {
  const ref = useRef(args);
  ref.current = args;
  useEffect(() => {
    return subscribeNoteArrivals((event) => {
      void (async () => {
        const { activeFingerprint, unlocked } = ref.current;
        const prefs = loadMailNotifyPrefs(); // read per event: a Settings change applies immediately, no reload
        if (!prefs.enabled) return;
        let localContactName: string | null = null;
        if (prefs.showSender && unlocked && activeFingerprint && event.from_fingerprint && event.kind === 'note') {
          try {
            localContactName = (await getContactByFingerprint(activeFingerprint, event.from_fingerprint))?.name ?? null;
          } catch {
            localContactName = null;
          }
        }
        const n = decideMailNotification({
          event,
          activeFingerprint,
          unlocked,
          pageHidden: typeof document !== 'undefined' && document.visibilityState !== 'visible',
          permission: notificationPermission(),
          prefs,
          localContactName,
        });
        if (!n) return;
        await showMailNotification(n, async () => {
          if (typeof navigator === 'undefined' || !('serviceWorker' in navigator)) return null;
          // `ready` never settles without a registered worker: give up after 3 s instead of leaving a promise per arrival.
          return Promise.race([navigator.serviceWorker.ready, new Promise<null>((r) => setTimeout(() => r(null), 3000))]);
        });
      })();
    });
  }, []);
}
