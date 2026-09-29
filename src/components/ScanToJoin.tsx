'use client';

/**
 * ScanToJoin — camera QR receive-side for the in-page join.
 *
 * Mounted only after the user taps Scan (permission on tap, not on dialog open).
 * Decodes locally (BarcodeDetector, jsQR fallback) → parseInviteUrl (INV-4) →
 * parent mounts the SAME <JoinerCeremony>. No second join path.
 *
 * INV-5: the decoded string is never stored in React state, never logged, never
 * shown. Errors are FIXED strings. Stream stops on close / success / error / unmount.
 * Frames stay in RAM — never uploaded or persisted.
 */

import { useEffect, useRef, useState } from 'react';
import { decodeQrFrame } from '@/lib/invite/decodeQrFrame';
import {
  SCAN_ERROR_CAMERA,
  classifyCameraError,
  inviteFromScannedText,
  stopMediaStream,
} from '@/lib/invite/scanInvite';
import type { ParsedInvite } from '@/lib/invite/parseInviteUrl';
import { solarEmber as E } from '@/components/recovery/solar-ember';

type Props = {
  onInvite: (invite: ParsedInvite) => void;
  onClose: () => void;
};

export function ScanToJoin({ onInvite, onClose }: Props) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
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
        // BarcodeDetector can read the <video> directly. jsQR needs pixels — only
        // grab a frame once the stream has dimensions (a 0×0 canvas throws).
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
          const result = inviteFromScannedText(text);
          if (result.ok) {
            succeeded = true;
            teardown();
            onInvite(result.invite);
            return;
          }
          setError(result.error);
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
  }, [onInvite]);

  return (
    <div>
      <p
        style={{
          margin: 0,
          fontSize: 11,
          letterSpacing: '0.2em',
          textTransform: 'uppercase',
          color: E.accent,
        }}
      >
        Add a connection
      </p>
      <h2 style={{ margin: '8px 0 0', fontSize: 22, fontWeight: 400, color: E.text }}>
        Scan invite
      </h2>
      <p style={{ margin: '10px 0 0', fontSize: 13, color: E.muted, lineHeight: 1.5 }}>
        Point the camera at the invite QR on their screen.
      </p>

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
          data-testid="scan-invite-video"
          aria-label="Camera preview for scanning an invite QR"
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
          data-testid="scan-invite-error"
          role="status"
          style={{ margin: '10px 0 0', fontSize: 12, color: E.danger, lineHeight: 1.5 }}
        >
          {error}
        </p>
      )}

      <button
        type="button"
        data-testid="scan-invite-cancel"
        onClick={onClose}
        style={{
          marginTop: 16,
          width: '100%',
          padding: '12px 14px',
          borderRadius: 8,
          border: `1px solid ${E.border}`,
          background: 'rgba(249,168,37,0.04)',
          color: E.muted,
          cursor: 'pointer',
          fontFamily: E.fontSans,
          fontSize: 12,
          fontWeight: 500,
          letterSpacing: '0.12em',
          textTransform: 'uppercase',
        }}
      >
        Paste instead
      </button>
    </div>
  );
}
