'use client';

/**
 * Shared guided verify sheet — Galaxy + address book.
 *
 * Know → Verify (private, this device) → Trust. Verify is never shown to
 * anyone else and never hits the wire. The sheet only calls onConfirm(method) after a
 * fingerprint match (in-person QR) or an explicit "the code matches" tick
 * (another channel).
 */

import { useCallback, useEffect, useState, type ReactNode } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import {
  formatFingerprintForVerify,
  TRUST_RECIPE_COPY,
} from '@/lib/trust/trust-recipe';
import { QrScanCamera, type QrScanOutcome } from '@/components/scan/QrScanCamera';
import {
  extractFingerprintFromScan,
  fingerprintsMatch,
} from './fingerprint-from-scan';
import { VERIFY_SHEET_COPY, boundVerifyName } from './verify-copy';

type Method = 'in_person' | 'other_channel';

type Props = {
  open: boolean;
  onClose: () => void;
  displayName: string;
  fingerprint: string;
  onConfirm: (method: Method) => void | Promise<void>;
};

function sheetBtn(opts: {
  label: string;
  onClick: () => void;
  primary?: boolean;
  disabled?: boolean;
  testId?: string;
}): ReactNode {
  return (
    <button
      type="button"
      data-testid={opts.testId}
      onClick={opts.onClick}
      disabled={opts.disabled}
      style={{
        fontSize: 12,
        fontFamily: E.fontSans,
        fontWeight: opts.primary ? 600 : 400,
        padding: '10px 12px',
        borderRadius: 8,
        border: `1px solid ${E.borderLit}`,
        background: opts.primary
          ? 'color-mix(in srgb, var(--se-accent) 14%, transparent)'
          : 'transparent',
        color: E.accent,
        cursor: opts.disabled ? 'default' : 'pointer',
        opacity: opts.disabled ? 0.45 : 1,
        letterSpacing: opts.primary ? '0.06em' : undefined,
        width: '100%',
      }}
    >
      {opts.label}
    </button>
  );
}

export function VerifySheet({
  open,
  onClose,
  displayName,
  fingerprint,
  onConfirm,
}: Props) {
  const name = boundVerifyName(displayName);
  const grouped = formatFingerprintForVerify(fingerprint);
  const [path, setPath] = useState<Method | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanMatched, setScanMatched] = useState(false);
  const [codeMatches, setCodeMatches] = useState(false);
  const [paste, setPaste] = useState('');
  const [mismatch, setMismatch] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setPath(null);
    setScanning(false);
    setScanMatched(false);
    setCodeMatches(false);
    setPaste('');
    setMismatch(null);
    setSaved(false);
    setBusy(false);
  }, [open, fingerprint]);

  const pasteMatch =
    paste.trim().length === 0 ? null : fingerprintsMatch(fingerprint, extractFingerprintFromScan(paste) ?? paste);

  const handleDecoded = useCallback(
    (text: string): QrScanOutcome | void => {
      const scanned = extractFingerprintFromScan(text);
      if (fingerprintsMatch(fingerprint, scanned)) {
        setScanMatched(true);
        setScanning(false);
        setMismatch(null);
        return { done: true };
      }
      const msg = VERIFY_SHEET_COPY.mismatch(name);
      setMismatch(msg);
      setScanMatched(false);
      return { error: msg };
    },
    [fingerprint, name],
  );

  const confirm = async (method: Method) => {
    if (busy) return;
    if (method === 'in_person' && !scanMatched) return;
    if (method === 'other_channel') {
      if (!codeMatches) return;
      if (pasteMatch === false) return;
    }
    setBusy(true);
    try {
      await onConfirm(method);
      setSaved(true);
      setScanning(false);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
    >
      <DialogContent
        data-testid="verify-sheet"
        className="gap-0 overflow-y-auto p-0 sm:rounded-2xl [&>button]:z-20"
        style={{
          width: 'min(28rem, calc(100vw - 1rem))',
          maxWidth: 'calc(100vw - 1rem)',
          maxHeight: 'min(92dvh, 40rem)',
          background: E.surfaceSolid,
          border: `1px solid ${E.border}`,
          color: E.text,
          fontFamily: E.fontSans,
        }}
      >
        <DialogHeader className="space-y-1 px-4 pb-2 pt-4 pr-12 text-left">
          <DialogTitle style={{ color: E.text, fontFamily: E.fontSans, fontSize: 18 }}>
            {VERIFY_SHEET_COPY.title}
            {name ? ` · ${name}` : ''}
          </DialogTitle>
          <DialogDescription style={{ color: E.muted, fontSize: 12, lineHeight: 1.45 }}>
            {TRUST_RECIPE_COPY.verifyWhy}
          </DialogDescription>
        </DialogHeader>

        <div style={{ padding: '8px 16px 16px', display: 'flex', flexDirection: 'column', gap: 12 }}>
          <p
            data-testid="verify-fingerprint"
            style={{
              margin: 0,
              fontSize: 18,
              lineHeight: 1.45,
              letterSpacing: '0.08em',
              fontFamily: E.fontMono,
              color: E.text,
              wordBreak: 'break-word',
            }}
          >
            {grouped}
          </p>
          <p style={{ margin: 0, fontSize: 12, color: E.dim, lineHeight: 1.45 }}>
            {TRUST_RECIPE_COPY.verifyPrivate}
          </p>

          {saved ? (
            <p
              data-testid="verify-saved"
              style={{ margin: 0, fontSize: 12, color: E.muted, lineHeight: 1.45 }}
            >
              {TRUST_RECIPE_COPY.verifiedHere}
            </p>
          ) : null}

          {mismatch ? (
            <p
              data-testid="verify-mismatch"
              role="status"
              style={{ margin: 0, fontSize: 12, color: E.danger, lineHeight: 1.5 }}
            >
              {mismatch}
            </p>
          ) : null}

          {!saved && !path ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {sheetBtn({
                label: TRUST_RECIPE_COPY.verifyInPerson,
                testId: 'verify-path-in-person',
                primary: true,
                onClick: () => {
                  setPath('in_person');
                  setMismatch(null);
                },
              })}
              {sheetBtn({
                label: TRUST_RECIPE_COPY.verifyOtherChannel,
                testId: 'verify-path-other-channel',
                onClick: () => {
                  setPath('other_channel');
                  setMismatch(null);
                },
              })}
            </div>
          ) : null}

          {!saved && path === 'in_person' ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <p style={{ margin: 0, fontSize: 12, color: E.dim, lineHeight: 1.45 }}>
                {TRUST_RECIPE_COPY.verifyConfirmBody}
              </p>
              {scanning ? (
                <>
                  <QrScanCamera
                    onDecoded={handleDecoded}
                    videoTestId="verify-scan-video"
                    errorTestId="verify-scan-error"
                    ariaLabel="Camera preview for scanning their identity QR"
                  />
                  {sheetBtn({
                    label: VERIFY_SHEET_COPY.notYet,
                    testId: 'verify-scan-cancel',
                    onClick: () => setScanning(false),
                  })}
                </>
              ) : (
                sheetBtn({
                  label: scanMatched ? VERIFY_SHEET_COPY.scanAgain : VERIFY_SHEET_COPY.scanTheirQr,
                  testId: 'verify-scan-start',
                  primary: !scanMatched,
                  onClick: () => {
                    setScanMatched(false);
                    setMismatch(null);
                    setScanning(true);
                  },
                })
              )}
              {sheetBtn({
                label: busy ? '…' : TRUST_RECIPE_COPY.verifyConfirm,
                testId: 'verify-confirm',
                primary: scanMatched,
                disabled: !scanMatched || busy,
                onClick: () => void confirm('in_person'),
              })}
            </div>
          ) : null}

          {!saved && path === 'other_channel' ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <label
                htmlFor="verify-paste"
                style={{ fontSize: 11, color: E.dim, letterSpacing: '0.06em', textTransform: 'uppercase' }}
              >
                {VERIFY_SHEET_COPY.pasteCompare}
              </label>
              <textarea
                id="verify-paste"
                data-testid="verify-paste"
                value={paste}
                onChange={(e) => {
                  const next = e.target.value;
                  setPaste(next);
                  if (!next.trim()) {
                    setMismatch(null);
                    return;
                  }
                  const extracted = extractFingerprintFromScan(next) ?? next;
                  if (fingerprintsMatch(fingerprint, extracted)) setMismatch(null);
                  else setMismatch(VERIFY_SHEET_COPY.mismatch(name));
                }}
                rows={3}
                style={{
                  width: '100%',
                  boxSizing: 'border-box',
                  borderRadius: 8,
                  border: `1px solid ${E.border}`,
                  background: E.inputBg,
                  color: E.text,
                  fontFamily: E.fontMono,
                  fontSize: 12,
                  letterSpacing: '0.06em',
                  padding: 10,
                  resize: 'vertical',
                }}
              />
              <label
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  fontSize: 13,
                  color: E.muted,
                  cursor: 'pointer',
                }}
              >
                <input
                  type="checkbox"
                  data-testid="verify-code-matches"
                  checked={codeMatches}
                  onChange={(e) => setCodeMatches(e.target.checked)}
                />
                {VERIFY_SHEET_COPY.codeMatches}
              </label>
              {sheetBtn({
                label: busy ? '…' : VERIFY_SHEET_COPY.confirmOther,
                testId: 'verify-confirm',
                primary: true,
                disabled: !codeMatches || pasteMatch === false || busy,
                onClick: () => void confirm('other_channel'),
              })}
            </div>
          ) : null}

          {saved
            ? sheetBtn({
                label: VERIFY_SHEET_COPY.close,
                testId: 'verify-close',
                onClick: onClose,
              })
            : path
              ? sheetBtn({
                  label: VERIFY_SHEET_COPY.notYet,
                  testId: 'verify-back',
                  onClick: () => {
                    setPath(null);
                    setScanning(false);
                    setScanMatched(false);
                    setCodeMatches(false);
                    setPaste('');
                    setMismatch(null);
                  },
                })
              : null}
        </div>
      </DialogContent>
    </Dialog>
  );
}
