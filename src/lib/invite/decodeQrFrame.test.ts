// src/lib/invite/decodeQrFrame.test.ts
// BarcodeDetector-first, jsQR-fallback. Run: npx tsx --test src/lib/invite/decodeQrFrame.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeQrFrame, type QrFrame } from './decodeQrFrame';

const FRAME: QrFrame = { data: new Uint8ClampedArray(16), width: 4, height: 4 };

test('BarcodeDetector hit is returned and jsQR is not called', async () => {
  let jsqrCalls = 0;
  const text = await decodeQrFrame({
    source: {},
    frame: FRAME,
    deps: {
      barcodeDetect: async () => 'https://svrnty.is/c/from-bd#k',
      jsQRDecode: () => {
        jsqrCalls += 1;
        return 'https://svrnty.is/c/from-jsqr#k';
      },
    },
  });
  assert.equal(text, 'https://svrnty.is/c/from-bd#k');
  assert.equal(jsqrCalls, 0);
});

test('empty BarcodeDetector result falls through to jsQR', async () => {
  const text = await decodeQrFrame({
    source: {},
    frame: FRAME,
    deps: {
      barcodeDetect: async () => null,
      jsQRDecode: () => 'https://svrnty.is/c/from-jsqr#k',
    },
  });
  assert.equal(text, 'https://svrnty.is/c/from-jsqr#k');
});

test('no QR in the frame → null (keep scanning; no throw)', async () => {
  const text = await decodeQrFrame({
    source: {},
    frame: FRAME,
    deps: {
      barcodeDetect: async () => null,
      jsQRDecode: () => null,
    },
  });
  assert.equal(text, null);
});

test('BarcodeDetector throw falls through to jsQR (TOTAL)', async () => {
  const text = await decodeQrFrame({
    source: {},
    frame: FRAME,
    deps: {
      barcodeDetect: async () => {
        throw new Error('bd-fail');
      },
      jsQRDecode: () => 'recovered',
    },
  });
  assert.equal(text, 'recovered');
});
