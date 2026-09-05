"use client";

import React, { useState } from 'react';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { HelpCircle, ChevronRight } from 'lucide-react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { TRUST_RECIPE_COPY } from '@/lib/trust/trust-recipe';

const steps = [
  {
    title: 'The Formula',
    content: [
      TRUST_RECIPE_COPY.knowLayer,
      TRUST_RECIPE_COPY.trustLayer,
      TRUST_RECIPE_COPY.mutualOnly,
    ],
  },
  {
    title: 'Create a card, not an account',
    content: [
      'On the gate: Start makes a new card. Continue opens a vault you already have.',
      'Enter your name and a passphrase that unlocks this device.',
      'This generates your keys. There is no recovery email. A card, not an account.',
      'Export a vault with an encryption password you set at export — that is not a website login.',
    ],
  },
  {
    title: 'Grow the Galaxy',
    content: [
      'Tap Grow. Show my code is your QR or short link. Scan / paste is how you join from theirs.',
      TRUST_RECIPE_COPY.mycelial,
      'Name them as you know them. Notes stay on this device.',
    ],
  },
  {
    title: 'Verify, then Trust',
    content: [
      TRUST_RECIPE_COPY.verifyWhy,
      TRUST_RECIPE_COPY.verifyPrivate,
      'They must verify you on their device too before Trust can be mutual. No one else sees your verify mark.',
    ],
  },
  {
    title: 'Decay',
    content: [
      TRUST_RECIPE_COPY.decay,
    ],
  },
  {
    title: TRUST_RECIPE_COPY.recoveryTitle,
    content: [
      // Claim-honesty: render only what's LIVE — the guardian GIVE (mounted, Shamir) —
      // plus a roadmap "Coming" line. recoveryRotate/Seed/Password are unmounted stubs; recoveryDistress
      // is a NO-OP send with a life-safety FALSE cry-claim → both GATED OUT of beta Help (constants kept
      // for when they wire up; do NOT re-add here until then).
      TRUST_RECIPE_COPY.recoverySelect,
      TRUST_RECIPE_COPY.recoveryComing,
    ],
  },
];

export type HelpGuideProps = {
  /** When false, parent supplies the opener; the dialog still mounts. */
  showTrigger?: boolean;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
};

export function HelpGuide({
  showTrigger = true,
  open: openProp,
  onOpenChange,
}: HelpGuideProps = {}) {
  const [uncontrolledOpen, setUncontrolledOpen] = useState(false);
  const [activeStep, setActiveStep] = useState(0);
  const controlled = openProp !== undefined;
  const open = controlled ? openProp : uncontrolledOpen;
  const setOpen = (next: boolean) => {
    if (!controlled) setUncontrolledOpen(next);
    onOpenChange?.(next);
  };

  const openHelp = () => {
    setActiveStep(0);
    setOpen(true);
  };

  React.useEffect(() => {
    if (open) setActiveStep(0);
  }, [open]);

  return (
    <>
      {showTrigger ? (
        <Button
          variant="ghost"
          size="sm"
          onClick={openHelp}
          style={{ color: E.dim, fontFamily: E.fontSans }}
        >
          <HelpCircle className="h-5 w-5 mr-1" />
          Help
        </Button>
      ) : null}

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-xl max-h-[85vh] overflow-y-auto" style={{ fontFamily: E.fontSans }}>
          <DialogHeader>
            <DialogTitle className="text-lg" style={{ color: E.accent, fontFamily: E.fontSans }}>
              {TRUST_RECIPE_COPY.helpTitle}
            </DialogTitle>
          </DialogHeader>

          {/* Step navigation */}
          <div className="flex flex-wrap gap-1.5 mb-4">
            {steps.map((step, i) => (
              <button
                key={i}
                onClick={() => setActiveStep(i)}
                className="text-xs px-2.5 py-1 rounded-full border transition-colors"
                style={{
                  fontFamily: E.fontSans,
                  borderColor: activeStep === i ? E.accent : E.border,
                  color: activeStep === i ? E.accent : E.dim,
                  background: activeStep === i ? 'rgba(249,168,37,0.1)' : 'transparent',
                }}
              >
                {i + 1}. {step.title}
              </button>
            ))}
          </div>

          {/* Active step content */}
          <div className="space-y-4">
            <h3 className="text-base font-medium" style={{ color: E.text, fontFamily: E.fontSans }}>
              {steps[activeStep].title}
            </h3>
            <ul className="space-y-3">
              {steps[activeStep].content.map((line, i) => (
                <li key={i} className="flex gap-2 text-sm" style={{ color: E.muted, fontFamily: E.fontSans }}>
                  <ChevronRight className="h-4 w-4 mt-0.5 flex-shrink-0" style={{ color: E.accent }} />
                  <span>{line}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Navigation */}
          <div className="flex justify-between mt-6 pt-4 border-t" style={{ borderColor: E.border }}>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setActiveStep(Math.max(0, activeStep - 1))}
              disabled={activeStep === 0}
              style={{ color: E.dim, fontFamily: E.fontSans }}
            >
              Previous
            </Button>
            <span className="text-xs self-center" style={{ color: E.dim }}>
              {activeStep + 1} of {steps.length}
            </span>
            {activeStep < steps.length - 1 ? (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setActiveStep(activeStep + 1)}
                style={{ color: E.accent, fontFamily: E.fontSans }}
              >
                Next
              </Button>
            ) : (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setOpen(false)}
                style={{ color: E.accent, fontFamily: E.fontSans }}
              >
                Got it
              </Button>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
