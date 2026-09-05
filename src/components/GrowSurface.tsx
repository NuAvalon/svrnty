'use client';

/**
 * Grow — one surface for give + receive.
 *
 * Tab 1 "Show my code" hosts the existing GrowSheet body (mint + QR + share link).
 * Tab 2 "Scan / paste" hosts the existing JoinByCode body (ScanToJoin + paste).
 * JoinerCeremony still takes over full-screen when a valid invite is set (Tab 2
 * already branches this; we do not flatten it into the tab chrome).
 *
 * Consent: joining remains an invite, not instant — Tab 2 only CALLS JoinByCode /
 * ScanToJoin / JoinerCeremony unchanged.
 */

import { useEffect, useState } from 'react';
import { GrowSheet } from '@/components/GrowSheet';
import { JoinByCode } from '@/components/JoinByCode';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { solarEmber as E } from '@/components/recovery/solar-ember';

const TAB_SHOW = 'show';
const TAB_SCAN = 'scan';

const tabTriggerClass =
  'flex-1 data-[state=active]:bg-[rgba(249,168,37,0.14)] data-[state=active]:text-[#fbead2]';

type Props = {
  open: boolean;
  onClose: () => void;
  identity: { identity?: { fingerprint?: string } } | null;
};

export function GrowSurface({ open, onClose, identity }: Props) {
  const [tab, setTab] = useState(TAB_SHOW);

  useEffect(() => {
    if (!open) setTab(TAB_SHOW);
  }, [open]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-label="Grow"
      data-testid="grow-surface"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 80,
        background: 'rgba(8,5,3,.72)',
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'center',
        padding: '72px 16px 24px',
      }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: 420,
          maxHeight: 'calc(100vh - 96px)',
          overflowY: 'auto',
          background: E.surfaceSolid,
          border: `1px solid ${E.borderLit}`,
          borderRadius: 16,
          padding: 24,
          boxShadow: '0 0 48px rgba(249,168,37,.08)',
          fontFamily: E.fontSans,
        }}
      >
        <Tabs value={tab} onValueChange={setTab} className="w-full">
          <TabsList
            className="w-full"
            style={{
              background: 'rgba(30,20,10,.55)',
              border: `1px solid ${E.border}`,
              height: 'auto',
              padding: 4,
              fontFamily: E.fontSans,
            }}
          >
            <TabsTrigger
              value={TAB_SHOW}
              data-testid="grow-tab-show"
              className={tabTriggerClass}
              style={{ color: E.muted, fontFamily: E.fontSans }}
            >
              Show my code
            </TabsTrigger>
            <TabsTrigger
              value={TAB_SCAN}
              data-testid="grow-tab-scan"
              className={tabTriggerClass}
              style={{ color: E.muted, fontFamily: E.fontSans }}
            >
              Scan / paste
            </TabsTrigger>
          </TabsList>

          {/* forceMount: keep the giver body mounted so switching tabs does not remint. */}
          <TabsContent
            value={TAB_SHOW}
            forceMount
            className="mt-4 data-[state=inactive]:hidden"
          >
            <GrowSheet open={open} onClose={onClose} identity={identity} embedded />
          </TabsContent>
          <TabsContent value={TAB_SCAN} className="mt-4">
            <JoinByCode open={open} onClose={onClose} embedded />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
