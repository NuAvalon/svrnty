'use client';

/**
 * Grow — one surface for give + receive.
 *
 * With a card: Tab 1 "Show my code" hosts GrowSheet (mint + QR + share link);
 * Tab 2 "Scan / paste" hosts JoinByCode (ScanToJoin + paste).
 *
 * Without a card: join-only. Grow always links you to someone — paste or scan
 * their invite. JoinerCeremony still takes over full-screen (and may mint a
 * card from that invite). There is no disconnected mint on this surface.
 *
 * Consent: joining remains an invite, not instant — Scan / paste only CALLS
 * JoinByCode / ScanToJoin / JoinerCeremony unchanged.
 */

import { useEffect, useState } from 'react';
import { GrowSheet } from '@/components/GrowSheet';
import { JoinByCode } from '@/components/JoinByCode';
import { GrowGatePanel } from '@/components/GrowGatePanel';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { TRUST_RECIPE_COPY } from '@/lib/trust/trust-recipe';

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
  const hasCard = Boolean(identity?.identity?.fingerprint);
  const [tab, setTab] = useState(hasCard ? TAB_SHOW : TAB_SCAN);

  useEffect(() => {
    if (!open) setTab(hasCard ? TAB_SHOW : TAB_SCAN);
  }, [open, hasCard]);

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
        {hasCard ? (
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

            {identity?.identity?.fingerprint ? (
              <div className="mt-4">
                <GrowGatePanel ownerFp={identity.identity.fingerprint} />
              </div>
            ) : null}

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
        ) : (
          <div data-testid="grow-join-only">
            <p
              style={{
                margin: 0,
                fontSize: 11,
                letterSpacing: '0.2em',
                textTransform: 'uppercase',
                color: E.accent,
              }}
            >
              {TRUST_RECIPE_COPY.gateGrow}
            </p>
            <p
              style={{
                margin: '10px 0 16px',
                fontSize: 14,
                color: E.muted,
                lineHeight: 1.5,
              }}
            >
              {TRUST_RECIPE_COPY.growAlwaysLinks}
            </p>
            <JoinByCode open={open} onClose={onClose} embedded />
          </div>
        )}
      </div>
    </div>
  );
}
