'use client';

/**
 * "Held messages" in the Lenses & vault panel: the one place held notes are reached for a sender who has NO page entry: a removed contact (no page left) or an unblocked one (the entry beside Unblock goes with
 * the Block state). A frozen contact keeps its entry on its own page, so every held note is reachable from exactly one place. Archie's placement ruling, widened to the unblocked case; flagged for his confirmation.
 *   - The entry carries NO count and no digit, and is shown whether or not anything is held (its presence says nothing). Nothing is read until the owner opens it.
 *   - Inside, each sender is a plain button labelled "this person" with a short technical tag (they have no page to carry a name), and opens the same view the contact page opens.
 *   - It works only through the ports it is given: local to this device, nothing sent.
 */

import { useState } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { cardVerbBtnStyle } from '@/components/ui/CardActionMenu';
import { normalizeFingerprintHex } from '@/lib/identity/fingerprint';
import { HOLD_VIEW_EMPTY, HOLD_VIEW_ENTRY, HOLD_VIEW_LOAD_FAILED, holdViewName } from './hold-view-copy';
import { senderTag, type HeldPort } from './hold-view-model';
import type { HeldSectionPort } from './held-port';
import { HeldMessagesView } from './HeldMessagesView';

export type HeldMessagesSectionProps = {
  sectionPort: HeldSectionPort;
  heldPort: HeldPort;
};

export function HeldMessagesSection({ sectionPort, heldPort }: HeldMessagesSectionProps) {
  const [open, setOpen] = useState(false);
  const [groups, setGroups] = useState<string[] | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [chosen, setChosen] = useState<string | null>(null);

  const toggle = async () => {
    if (open) {
      setOpen(false);
      setChosen(null);
      return;
    }
    setOpen(true);
    try {
      const [senders, frozen] = await Promise.all([sectionPort.senders(), sectionPort.frozen()]);
      setGroups(senders.map((s) => s.from_fingerprint).filter((fp) => !frozen.has(normalizeFingerprintHex(fp))));
      setLoadFailed(false);
    } catch {
      setGroups(null);
      setLoadFailed(true);
    }
  };

  return (
    <div data-testid="held-section" style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
      <button type="button" data-testid="held-section-entry" aria-expanded={open} onClick={() => { void toggle(); }} style={cardVerbBtnStyle({ muted: true })}>
        {HOLD_VIEW_ENTRY}
      </button>
      {open ? (
        loadFailed ? (
          <p data-testid="held-section-load-failed" role="status" style={{ margin: 0, fontSize: 13, fontFamily: E.fontSans, color: E.text }}>{HOLD_VIEW_LOAD_FAILED}</p>
        ) : groups === null ? null : groups.length === 0 ? (
          <p data-testid="held-section-empty" style={{ margin: 0, fontSize: 13, fontFamily: E.fontSans, color: E.muted }}>{HOLD_VIEW_EMPTY}</p>
        ) : (
          <>
            <ul data-testid="held-section-groups" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 6 }}>
              {groups.map((fp) => (
                <li key={fp}>
                  <button type="button" data-testid={`held-section-sender-${senderTag(fp)}`} onClick={() => setChosen(fp)} style={cardVerbBtnStyle()}>
                    {holdViewName(null)} <code>{senderTag(fp)}</code>
                  </button>
                </li>
              ))}
            </ul>
            {chosen ? <HeldMessagesView key={chosen} fingerprint={chosen} name={null} port={heldPort} stillFrozen={false} /> : null}
          </>
        )
      ) : null}
    </div>
  );
}
