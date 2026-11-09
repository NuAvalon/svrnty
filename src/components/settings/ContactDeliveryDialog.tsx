'use client';

/** The per-contact Delivery choice. The write is the caller's (a plain updateContact with contactDeliveryPatch); the rule is delivery-receipt-setting.ts. */

import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { DELIVERY_COPY } from './delivery-copy';
import { contactDeliveryChoice, type ContactDeliveryChoice } from './delivery-actions';

const CHOICES: ReadonlyArray<{ id: ContactDeliveryChoice; label: string }> = [
  { id: 'follow', label: DELIVERY_COPY.followDefault },
  { id: 'on', label: DELIVERY_COPY.on },
  { id: 'off', label: DELIVERY_COPY.off },
];

export function ContactDeliveryDialog({
  open,
  contactName,
  stored,
  busy,
  error,
  onChoose,
  onClose,
}: {
  open: boolean;
  contactName: string;
  stored: unknown;
  busy: boolean;
  error: string | null;
  onChoose: (choice: ContactDeliveryChoice) => void;
  onClose: () => void;
}) {
  const current = contactDeliveryChoice(stored);
  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent className="sm:max-w-md" data-testid="contact-delivery-dialog">
        <DialogHeader>
          <DialogTitle>{DELIVERY_COPY.title}: {contactName}</DialogTitle>
          <DialogDescription data-testid="contact-delivery-line">{DELIVERY_COPY.contactLine}</DialogDescription>
        </DialogHeader>
        <div role="group" aria-label={DELIVERY_COPY.title} className="flex gap-2 py-2">
          {CHOICES.map((c) => (
            <Button
              key={c.id}
              type="button"
              data-testid={`contact-delivery-${c.id}`}
              aria-pressed={current === c.id}
              variant={current === c.id ? 'default' : 'outline'}
              disabled={busy}
              onClick={() => onChoose(c.id)}
              className="flex-1"
            >
              {c.label}
            </Button>
          ))}
        </div>
        {error ? <p data-testid="contact-delivery-error" role="alert" className="text-sm text-destructive">{error}</p> : null}
      </DialogContent>
    </Dialog>
  );
}
