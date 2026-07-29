"use client";

import React, { useState } from 'react';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { HelpCircle, ChevronRight } from 'lucide-react';

const steps = [
  {
    title: 'Create Your Identity',
    content: [
      'Enter your name, email, and a strong passphrase.',
      'This generates your cryptographic keys — ED25519 (classical) and ML-DSA-87 (post-quantum).',
      'Your passphrase protects your private key. If you lose it, you lose your identity. There is no recovery email. There is no "forgot password."',
      'Write it down. Store it somewhere safe — not on your phone, not in a note app.',
    ],
  },
  {
    title: 'Back Up Your Keys',
    content: [
      'Go to Contacts → More → Secure Export to create an encrypted backup of your data.',
      'Set a strong password for the export. This is separate from your passphrase.',
      'Save the encrypted file somewhere you control: USB drive, external hard drive, or a cloud service you trust.',
      'Do this after creating your identity and again whenever you add important contacts.',
      'If your device is lost, this backup + your passphrase is how you recover.',
    ],
  },
  {
    title: 'Add People You Know',
    content: [
      'Click "Share Identity" in the Contacts tab. This creates a signed package with your public key.',
      'Copy it and send it to your friend via Signal, email, or any channel you trust.',
      'Your friend opens SVRNTY, clicks "Import Contact", and pastes your package.',
      'The signatures are verified automatically — they know it really came from you.',
      'They appear as "Known" in your network. You appear as "Known" in theirs.',
    ],
  },
  {
    title: 'Trust & Vouch',
    content: [
      'Known means you have their contact. It doesn\'t mean you trust them.',
      'Click "Vouch" on a contact to grant trust. This is your word — it means something.',
      'Trusted contacts are inside the walls. Known contacts are outside.',
      'If someone loses your trust, click "Break". They\'ll disappear from your trusted circle. Both of you will notice. That\'s the point — it creates the space to talk about it.',
    ],
  },
  {
    title: 'Trust Decay',
    content: [
      'Trust isn\'t permanent. If you don\'t interact with someone for 2 years, trust fades.',
      'This is like a key that expires — stay in touch, and it stays alive.',
      'When trust decays, the person drops back to Known. You can reverify to restore it.',
      'You can customize the decay period per contact if 2 years doesn\'t fit.',
    ],
  },
  {
    title: 'How It Works',
    content: [
      'All your data is encrypted with your keys and stored locally. The server can\'t read it.',
      'Every signal you send is signed with both classical and post-quantum cryptography.',
      'No accounts. No passwords stored on a server. No tracking. No ads.',
      'Your identity is yours. Your trust network is yours. We just built the walls.',
    ],
  },
];

export function HelpGuide() {
  const [open, setOpen] = useState(false);
  const [activeStep, setActiveStep] = useState(0);

  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        onClick={() => { setOpen(true); setActiveStep(0); }}
        className="absolute right-0 top-0"
        style={{ color: '#8a8070' }}
      >
        <HelpCircle className="h-5 w-5 mr-1" />
        Help
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="text-lg" style={{ color: '#c8a84e' }}>
              Getting Started
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
                  borderColor: activeStep === i ? '#c8a84e' : 'rgba(180,160,100,0.2)',
                  color: activeStep === i ? '#c8a84e' : '#8a8070',
                  background: activeStep === i ? 'rgba(200,168,78,0.1)' : 'transparent',
                }}
              >
                {i + 1}. {step.title}
              </button>
            ))}
          </div>

          {/* Active step content */}
          <div className="space-y-4">
            <h3 className="text-base font-medium" style={{ color: '#e0dcd0' }}>
              {steps[activeStep].title}
            </h3>
            <ul className="space-y-3">
              {steps[activeStep].content.map((line, i) => (
                <li key={i} className="flex gap-2 text-sm" style={{ color: '#a09880' }}>
                  <ChevronRight className="h-4 w-4 mt-0.5 flex-shrink-0" style={{ color: '#c8a84e' }} />
                  <span>{line}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Navigation */}
          <div className="flex justify-between mt-6 pt-4 border-t" style={{ borderColor: 'rgba(180,160,100,0.15)' }}>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setActiveStep(Math.max(0, activeStep - 1))}
              disabled={activeStep === 0}
              style={{ color: '#8a8070' }}
            >
              Previous
            </Button>
            <span className="text-xs self-center" style={{ color: '#5a5548' }}>
              {activeStep + 1} of {steps.length}
            </span>
            {activeStep < steps.length - 1 ? (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setActiveStep(activeStep + 1)}
                style={{ color: '#c8a84e' }}
              >
                Next
              </Button>
            ) : (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setOpen(false)}
                style={{ color: '#c8a84e' }}
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
