// src/lib/invite/decodeQrFrame.ts
//
// In-memory QR decode for the join-scan camera. BarcodeDetector where the browser
// has it; jsQR as the fallback. Frames stay in RAM — this module never uploads,
// persists, or logs decoded text (INV-5). Callers must treat the returned string
// as untrusted input and pass it to inviteFromScannedText / parseInviteUrl.

export type QrFrame = {
  data: Uint8ClampedArray;
  width: number;
  height: number;
};

export type DecodeQrDeps = {
  /** Native BarcodeDetector path. Return the first QR payload, or null. */
  barcodeDetect?: (source: unknown) => Promise<string | null>;
  /** jsQR fallback. Return the payload, or null. */
  jsQRDecode?: (frame: QrFrame) => string | null | Promise<string | null>;
};

type JsQRFn = (
  data: Uint8ClampedArray,
  width: number,
  height: number,
) => { data: string } | null;

let jsQRPromise: Promise<JsQRFn | null> | null = null;

async function loadJsQR(): Promise<JsQRFn | null> {
  if (jsQRPromise) return jsQRPromise;
  jsQRPromise = import('jsqr')
    .then((mod) => {
      const fn = (mod as { default?: JsQRFn }).default ?? (mod as unknown as JsQRFn);
      return typeof fn === 'function' ? fn : null;
    })
    .catch(() => null);
  return jsQRPromise;
}

type BarcodeDetectorCtor = new (opts?: { formats?: string[] }) => {
  detect: (source: unknown) => Promise<Array<{ rawValue?: string }>>;
};

function getBarcodeDetectorCtor(): BarcodeDetectorCtor | null {
  if (typeof globalThis === 'undefined') return null;
  const ctor = (globalThis as { BarcodeDetector?: BarcodeDetectorCtor }).BarcodeDetector;
  return typeof ctor === 'function' ? ctor : null;
}

async function defaultBarcodeDetect(source: unknown): Promise<string | null> {
  const Ctor = getBarcodeDetectorCtor();
  if (!Ctor) return null;
  try {
    const detector = new Ctor({ formats: ['qr_code'] });
    const codes = await detector.detect(source);
    for (const code of codes) {
      if (typeof code.rawValue === 'string' && code.rawValue) return code.rawValue;
    }
    return null;
  } catch {
    return null;
  }
}

async function defaultJsQRDecode(frame: QrFrame): Promise<string | null> {
  const jsQR = await loadJsQR();
  if (!jsQR) return null;
  try {
    const result = jsQR(frame.data, frame.width, frame.height);
    const text = result?.data;
    return typeof text === 'string' && text ? text : null;
  } catch {
    return null;
  }
}

/**
 * Decode one camera frame. Prefers BarcodeDetector; falls back to jsQR.
 * Returns the raw QR text or null. TOTAL — never throws. Does not log the text.
 */
export async function decodeQrFrame(opts: {
  source: unknown;
  frame: QrFrame;
  deps?: DecodeQrDeps;
}): Promise<string | null> {
  const barcodeDetect = opts.deps?.barcodeDetect ?? defaultBarcodeDetect;
  try {
    const fromBd = await barcodeDetect(opts.source);
    if (typeof fromBd === 'string' && fromBd) return fromBd;
  } catch {
    /* TOTAL — native detector throw → jsQR fallback */
  }
  const jsQRDecode = opts.deps?.jsQRDecode ?? defaultJsQRDecode;
  try {
    const fromJs = await jsQRDecode(opts.frame);
    return typeof fromJs === 'string' && fromJs ? fromJs : null;
  } catch {
    return null;
  }
}
