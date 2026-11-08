'use client';
// Settings: phase 1 mail notifications (opt-in, off by default). Copy = Hypatia 9e1aef8d, verbatim (COPY in mail-notifications.ts).
// Permission is requested ONLY from the toggle's click, never on load.

import { useEffect, useState } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import {
  COPY,
  SENDER_LINE_PENDING_COPY,
  loadMailNotifyPrefs,
  notificationPermission,
  saveMailNotifyPrefs,
  type MailNotifyPrefs,
} from '@/lib/notes/mail-notifications';

export function MailNotificationsSettingsPanel() {
  const [prefs, setPrefs] = useState<MailNotifyPrefs>({ enabled: false, showSender: false });
  const [permission, setPermission] = useState<NotificationPermission | 'unsupported'>('default');
  const [asking, setAsking] = useState(false);

  useEffect(() => {
    setPrefs(loadMailNotifyPrefs());
    setPermission(notificationPermission());
  }, []);

  if (permission === 'unsupported') return null; // no Notification API: nothing honest to offer

  const update = (next: MailNotifyPrefs) => {
    const clean = { enabled: next.enabled, showSender: next.enabled && next.showSender };
    setPrefs(clean);
    saveMailNotifyPrefs(clean);
  };

  const onToggle = async (on: boolean) => {
    if (!on) return update({ enabled: false, showSender: false });
    let p = notificationPermission();
    if (p === 'default') {
      setAsking(true);
      try {
        p = await Notification.requestPermission();
      } catch {
        p = notificationPermission();
      } finally {
        setAsking(false);
      }
    }
    setPermission(p);
    update({ ...prefs, enabled: p === 'granted' });
  };

  const text = { fontFamily: E.fontSans, fontSize: 13, color: E.text, lineHeight: 1.4 } as const;
  const helper = { display: 'block', fontSize: 11, color: E.dim, marginTop: 2 } as const;

  return (
    <section
      data-testid="mail-notify-settings"
      aria-label="Notifications"
      style={{
        marginTop: 16, padding: '16px 18px', background: E.surface, border: `1px solid ${E.border}`, borderRadius: 12,
        backdropFilter: 'blur(16px)', WebkitBackdropFilter: 'blur(16px)', maxWidth: 420, marginLeft: 'auto', marginRight: 'auto',
        textAlign: 'left' as const,
      }}
    >
      <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, cursor: 'pointer', marginBottom: 10 }}>
        <input
          data-testid="mail-notify-toggle"
          type="checkbox"
          checked={prefs.enabled}
          disabled={asking}
          onChange={(e) => void onToggle(e.target.checked)}
          style={{ marginTop: 2, accentColor: E.accent }}
        />
        <span style={text}>
          {COPY.toggle}
          <span style={helper}>{COPY.toggleHelper}</span>
          {permission === 'default' && !prefs.enabled && <span style={helper}>{COPY.beforePrompt}</span>}
          {permission === 'denied' && <span data-testid="mail-notify-denied" style={helper}>{COPY.denied}</span>}
        </span>
      </label>

      {prefs.enabled && !SENDER_LINE_PENDING_COPY && (
        <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, cursor: 'pointer', marginLeft: 24 }}>
          <input
            data-testid="mail-notify-show-sender"
            type="checkbox"
            checked={prefs.showSender}
            onChange={(e) => update({ ...prefs, showSender: e.target.checked })}
            style={{ marginTop: 2, accentColor: E.accent }}
          />
          <span style={text}>
            {COPY.nameToggle}
            <span style={helper}>{COPY.nameToggleHelper}</span>
          </span>
        </label>
      )}
    </section>
  );
}
