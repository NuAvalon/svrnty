// src/lib/trust/nfc-transport.ts
// Web NFC adapter for tap-to-share identity exchange.
// Uses NDEF text records — simple, universal, no binary framing needed.
//
// Web NFC is only available in Chrome on Android with NFC hardware.
// This module provides clean detection and graceful fallback.

/**
 * Check whether Web NFC is available in the current browser.
 */
export function isNfcAvailable(): boolean {
  return typeof window !== 'undefined' && 'NDEFReader' in window;
}

/**
 * Write an exchange package to an NFC tag as an NDEF text record.
 * The phone must be held near a writable NFC tag.
 *
 * @param exchangePackage - The signed identity package string (JSON)
 * @throws If Web NFC is not supported or the write fails
 */
export async function writeNfc(exchangePackage: string): Promise<void> {
  if (!isNfcAvailable()) {
    throw new Error(
      'NFC sharing requires Chrome on Android with NFC enabled.'
    );
  }

  // NDEFReader is only available at runtime in supported browsers
  const NDEFReader = (window as any).NDEFReader;
  const reader = new NDEFReader();

  await reader.write({
    records: [
      {
        recordType: 'text',
        data: exchangePackage,
        lang: 'en',
      },
    ],
  });
}

/**
 * Listen for an incoming NFC tap and return the exchange package string.
 * Returns a promise that resolves with the first NDEF text record received.
 * The caller should provide an AbortController signal to cancel listening.
 *
 * @param options.signal - Optional AbortSignal to cancel the scan
 * @throws If Web NFC is not supported or the scan fails
 */
export async function readNfc(options?: {
  signal?: AbortSignal;
}): Promise<string> {
  if (!isNfcAvailable()) {
    throw new Error(
      'NFC sharing requires Chrome on Android with NFC enabled.'
    );
  }

  const NDEFReader = (window as any).NDEFReader;
  const reader = new NDEFReader();

  return new Promise<string>((resolve, reject) => {
    reader.addEventListener('reading', (event: any) => {
      const { message } = event;
      for (const record of message.records) {
        if (record.recordType === 'text') {
          const decoder = new TextDecoder(record.encoding || 'utf-8');
          const text = decoder.decode(record.data);
          resolve(text);
          return;
        }
      }
      reject(new Error('No text record found in NFC tag.'));
    });

    reader.addEventListener('readingerror', () => {
      reject(new Error('Failed to read NFC tag. Try holding the device closer.'));
    });

    reader
      .scan({ signal: options?.signal })
      .catch((err: Error) => reject(err));
  });
}
