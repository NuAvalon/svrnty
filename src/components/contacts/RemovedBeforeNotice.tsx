'use client';

/**
 * "You removed this person before" on the owner's PRIVATE contact card (copy ledger rows 311a, 311b, 314a). It is a presenter only: the card that holds it decides whether it exists
 * (an explicit opt-in prop that only the contact book passes; the Galaxy never does), and the screen owns what the buttons do. Keep is the ONE caller of the drop; Remove them again is the
 * normal Remove. No default button, and nothing here closes on its own.
 */

import { solarEmber as E } from '@/components/recovery/solar-ember';
import { cardVerbBtnStyle } from '@/components/ui/CardActionMenu';
import {
  REMOVED_BEFORE_DROP_FAILED,
  REMOVED_BEFORE_KEEP,
  REMOVED_BEFORE_KEEP_HELPER,
  REMOVED_BEFORE_NOT_NOW,
  REMOVED_BEFORE_NOTICE,
  REMOVED_BEFORE_REMOVE_AGAIN,
  REMOVED_BEFORE_TRY_AGAIN,
} from './removed-before-copy';

export type RemovedBeforeNoticeProps = {
  /** The drop did not finish: show the failure line with Try again / Not now. */
  failed: boolean;
  /** The drop is running: both buttons are disabled. */
  busy: boolean;
  onKeep: () => void;
  onRemoveAgain: () => void;
  onNotNow: () => void;
};

export function RemovedBeforeNotice({ failed, busy, onKeep, onRemoveAgain, onNotNow }: RemovedBeforeNoticeProps) {
  return (
    <div
      data-testid="removed-before-notice"
      style={{ marginTop: 8, marginBottom: 4, padding: 10, borderRadius: 12, border: `1px solid ${E.border}`, background: E.surface, display: 'flex', flexDirection: 'column', gap: 8 }}
    >
      <p data-testid="removed-before-text" role="status" style={{ margin: 0, fontFamily: E.fontSans, fontSize: 13, lineHeight: 1.45, color: E.text }}>
        {failed ? REMOVED_BEFORE_DROP_FAILED : REMOVED_BEFORE_NOTICE}
      </p>
      <div style={{ display: 'flex', gap: 8 }}>
        <button
          type="button"
          data-testid={failed ? 'removed-before-try-again' : 'removed-before-keep'}
          disabled={busy}
          onClick={onKeep}
          style={cardVerbBtnStyle()}
        >
          {failed ? REMOVED_BEFORE_TRY_AGAIN : REMOVED_BEFORE_KEEP}
        </button>
        <button
          type="button"
          data-testid={failed ? 'removed-before-not-now' : 'removed-before-remove-again'}
          disabled={busy}
          onClick={failed ? onNotNow : onRemoveAgain}
          style={cardVerbBtnStyle({ muted: true })}
        >
          {failed ? REMOVED_BEFORE_NOT_NOW : REMOVED_BEFORE_REMOVE_AGAIN}
        </button>
      </div>
      {failed ? null : (
        <p data-testid="removed-before-helper" style={{ margin: 0, fontFamily: E.fontSans, fontSize: 12, lineHeight: 1.4, color: E.muted }}>
          {REMOVED_BEFORE_KEEP_HELPER}
        </p>
      )}
    </div>
  );
}
