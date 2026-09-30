'use client';

/**
 * Shared in-page QR camera. Decode stays in RAM (BarcodeDetector, jsQR fallback
 * via decodeQrFrame). Callers parse the string — this chrome never logs it,
 * never stores it in React state, never shows it.
 *
 * Permission is requested on mount (parent mounts only after a tap).
 */

import { useEffect, useRef, useState } from 'react';
import { decodeQrFrame } from '@/lib/invite/decodeQrFrame';
import {
  SCAN_ERROR_CAMERA,
  classifyCameraError,
  stopMediaStream,
} from '@/lib/invite/scanInvite';
import { solarEmber as E } from '@/components/recovery/solar-ember';

export type QrScanOutcome = { done: true } | { error: string };

type Props = {
  onDecoded: (text: string) => QrScanOutcome | void;
  videoTestId: string;
  errorTestId: string;
  ariaLabel: string;
};

export function QrScanCamera({
  onDecoded,
  videoTestId,
  errorTestId,
  ariaLabel,
}: Props) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const onDecodedRef = useRef(onDecoded);
  onDecodedRef.current = onDecoded;
  const [error, setError] = useState<string | null>(null);
  const [live, setLive] = useState(false);

  useEffect(() => {
    let cancelled = false;
    let timer = 0;
    let succeeded = false;
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });

    const teardown = () => {
      if (timer) window.clearTimeout(timer);
      stopMediaStream(streamRef.current);
      streamRef.current = null;
      const video = videoRef.current;
      if (video) video.srcObject = null;
    };

    async function loop() {
      if (cancelled || succeeded) return;
      const video = videoRef.current;
      if (video) {
        let frame = { data: new Uint8ClampedArray(4), width: 1, height: 1 };
        if (ctx && video.readyState >= 2 && video.videoWidth && video.videoHeight) {
          canvas.width = video.videoWidth;
          canvas.height = video.videoHeight;
          ctx.drawImage(video, 0, 0);
          const image = ctx.getImageData(0, 0, canvas.width, canvas.height);
          frame = { data: image.data, width: image.width, height: image.height };
        }
        const text = await decodeQrFrame({ source: video, frame });
        if (cancelled || succeeded) return;
        if (text) {
          const result = onDecodedRef.current(text);
          if (result && 'done' in result && result.done) {
            succeeded = true;
            teardown();
            return;
          }
          if (result && 'error' in result) setError(result.error);
        }
      }
      if (!cancelled && !succeeded) {
        timer = window.setTimeout(() => {
          void loop();
        }, 180);
      }
    }

    async function start() {
      if (!navigator.mediaDevices?.getUserMedia) {
        setError(SCAN_ERROR_CAMERA);
        return;
      }
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: { ideal: 'environment' } },
          audio: false,
        });
        if (cancelled) {
          stopMediaStream(stream);
          return;
        }
        streamRef.current = stream;
        const video = videoRef.current;
        if (!video) {
          stopMediaStream(stream);
          return;
        }
        video.srcObject = stream;
        setLive(true);
        void loop();
        try {
          await video.play();
        } catch (err) {
          if (cancelled || succeeded) return;
          cancelled = true;
          teardown();
          setError(classifyCameraError(err));
        }
      } catch (err) {
        if (cancelled) return;
        teardown();
        setError(classifyCameraError(err));
      }
    }

    void start();
    return () => {
      cancelled = true;
      teardown();
    };
  }, []);

  return (
    <div>
      <div
        style={{
          marginTop: 16,
          position: 'relative',
          borderRadius: 12,
          overflow: 'hidden',
          border: `1px solid ${E.borderLit}`,
          background: 'rgba(8,5,3,.85)',
          aspectRatio: '3 / 4',
          maxHeight: 360,
        }}
      >
        <video
          ref={videoRef}
          data-testid={videoTestId}
          aria-label={ariaLabel}
          playsInline
          muted
          autoPlay
          style={{
            display: 'block',
            width: '100%',
            height: '100%',
            objectFit: 'cover',
            opacity: live ? 1 : 0.35,
          }}
        />
        <div
          aria-hidden
          style={{
            pointerEvents: 'none',
            position: 'absolute',
            inset: 28,
            border: `1px solid ${E.borderLit}`,
            borderRadius: 8,
            boxShadow: '0 0 24px rgba(249,168,37,0.08)',
          }}
        />
      </div>

      {error && (
        <p
          data-testid={errorTestId}
          role="status"
          style={{ margin: '10px 0 0', fontSize: 12, color: E.danger, lineHeight: 1.5 }}
        >
          {error}
        </p>
      )}
    </div>
  );
}
