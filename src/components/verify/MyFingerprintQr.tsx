"use client";

import React from 'react';
import { SimpleQRCode } from '@/components/SimpleQRCode';
import { MY_QR_LINE, myQrPayload } from './my-fingerprint-qr';

/** The owner's fingerprint as a QR, with the one line that says what it is. Draws nothing if it was not given a 64-hex fingerprint. */
export function MyFingerprintQr({ fingerprint }: { fingerprint: string }) {
  const payload = myQrPayload(fingerprint);
  if (!payload) return null;
  return (
    <div className="flex flex-col items-center py-6 space-y-4" data-testid="my-qr">
      <SimpleQRCode value={payload} size={220} />
      <p className="text-xs text-gray-500 text-center max-w-xs" data-testid="my-qr-line">{MY_QR_LINE}</p>
    </div>
  );
}
