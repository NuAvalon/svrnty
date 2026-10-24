// src/components/contact-update-send-copy.ts
// User-facing result line for a contact-update send. Pure so the wording is testable.
// S14 (HNDL): a recipient with no verified PQ KEM key is SKIPPED ('no-pq-kem'), never downgraded. Say THAT,
// not "no key". Claim-safe wording only ("security upgrade"): never "quantum-safe"/"PQ-secure" before the Nov-5 gate
// (Flint/Hypatia, lane:svrnty).
import type { SendContactUpdateResult } from '@/lib/sync/send-contact-update';

export function contactUpdateSendMessage(
  result: Pick<SendContactUpdateResult, 'deposited' | 'skipped' | 'failed'>,
): { ok: boolean; message: string } {
  const deposited = result.deposited.length;
  const failed = result.failed.length;
  const needsUpgrade = result.skipped.filter((s) => s.reason === 'no-pq-kem').length;
  const noKey = result.skipped.length - needsUpgrade;
  const plural = (n: number) => (n === 1 ? 'contact needs' : 'contacts need');
  if (deposited === 0) {
    const parts = [
      needsUpgrade ? `${needsUpgrade} ${plural(needsUpgrade)} a security upgrade` : '',
      noKey ? `${noKey} had no key` : '',
      failed ? `${failed} failed` : '',
    ].filter(Boolean);
    return {
      ok: false,
      message: `Couldn't deliver${parts.length ? `: ${parts.join(', ')}` : ''}. Saved locally — try Send again later.`,
    };
  }
  return {
    ok: true,
    message:
      `Sent to ${deposited} contact${deposited === 1 ? '' : 's'}` +
      (needsUpgrade ? `, ${needsUpgrade} ${plural(needsUpgrade)} a security upgrade (not sent)` : '') +
      (noKey ? `, ${noKey} skipped (no key yet)` : '') +
      (failed ? `, ${failed} failed (retry)` : '') +
      '.',
  };
}
