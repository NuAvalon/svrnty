"use client";

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription,
} from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import {
  QrCode, Smartphone, Link2, Copy, Download, Check, Clock, Wifi,
} from 'lucide-react';
import { SimpleQRCode } from '@/components/SimpleQRCode';
import { isNfcAvailable, writeNfc } from '@/lib/trust/nfc-transport';
import { createRelay } from '@/lib/sync/relay';
import { shareUrlShort } from '@/lib/config/domain';

interface ContactShareDialogProps {
  open: boolean;
  onClose: () => void;
  exchangePackage: string;
  fingerprint: string;
}

type NfcStatus = 'idle' | 'writing' | 'success' | 'error' | 'unsupported';
type ShortCodeState = {
  code: string | null;
  key: string | null;
  expiresAt: number | null;
  loading: boolean;
  error: string | null;
};

export function ContactShareDialog({
  open,
  onClose,
  exchangePackage,
  fingerprint,
}: ContactShareDialogProps) {
  const [activeTab, setActiveTab] = useState('qr');
  const [copied, setCopied] = useState(false);
  const [nfcStatus, setNfcStatus] = useState<NfcStatus>('idle');
  const [nfcError, setNfcError] = useState<string | null>(null);
  const [shortCode, setShortCode] = useState<ShortCodeState>({
    code: null, key: null, expiresAt: null, loading: false, error: null,
  });
  const [timeLeft, setTimeLeft] = useState<string>('');
  const [linkCopied, setLinkCopied] = useState(false);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Reset state when dialog opens
  useEffect(() => {
    if (open) {
      setCopied(false);
      setNfcStatus(isNfcAvailable() ? 'idle' : 'unsupported');
      setNfcError(null);
      setShortCode({ code: null, key: null, expiresAt: null, loading: false, error: null });
      setLinkCopied(false);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [open]);

  // Countdown timer for short code expiry
  useEffect(() => {
    if (!shortCode.expiresAt) return;

    const update = () => {
      const remaining = shortCode.expiresAt! - Date.now();
      if (remaining <= 0) {
        setTimeLeft('Expired');
        setShortCode(prev => ({ ...prev, code: null, key: null, expiresAt: null }));
        if (timerRef.current) clearInterval(timerRef.current);
        return;
      }
      const mins = Math.floor(remaining / 60000);
      const secs = Math.floor((remaining % 60000) / 1000);
      setTimeLeft(`${mins}:${secs.toString().padStart(2, '0')}`);
    };

    update();
    timerRef.current = setInterval(update, 1000);
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [shortCode.expiresAt]);

  // --- Handlers ---

  const handleCopyRaw = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(exchangePackage);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
      const textarea = document.createElement('textarea');
      textarea.value = exchangePackage;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [exchangePackage]);

  const handleNfcWrite = useCallback(async () => {
    setNfcStatus('writing');
    setNfcError(null);
    try {
      await writeNfc(exchangePackage);
      setNfcStatus('success');
    } catch (err) {
      setNfcStatus('error');
      setNfcError(err instanceof Error ? err.message : 'NFC write failed');
    }
  }, [exchangePackage]);

  const handleGenerateShortCode = useCallback(async () => {
    setShortCode(prev => ({ ...prev, loading: true, error: null }));
    try {
      // createRelay encrypts client-side with AES-256-GCM, posts the blob,
      // and returns a URL with the key in the fragment (never reaches server)
      const result = await createRelay(exchangePackage);
      // Extract code and key from the URL: https://{domain}/c/{code}#{key} (split on /c/ — domain-agnostic)
      const urlParts = result.url.split('/c/')[1];
      const [code, key] = urlParts.split('#');
      setShortCode({
        code,
        key,
        expiresAt: new Date(result.expiresAt).getTime(),
        loading: false,
        error: null,
      });
    } catch (err) {
      setShortCode(prev => ({
        ...prev,
        loading: false,
        error: err instanceof Error ? err.message : 'Failed to generate link',
      }));
    }
  }, [exchangePackage]);

  const shortCodeLink = shortCode.code && shortCode.key
    ? shareUrlShort(shortCode.code, shortCode.key)
    : null;

  const handleCopyLink = useCallback(async () => {
    if (!shortCodeLink) return;
    try {
      await navigator.clipboard.writeText(shortCodeLink);
      setLinkCopied(true);
      setTimeout(() => setLinkCopied(false), 2000);
    } catch {
      // silent fallback
    }
  }, [shortCodeLink]);

  return (
    <Dialog open={open} onOpenChange={(isOpen) => { if (!isOpen) onClose(); }}>
      <DialogContent className="sm:max-w-lg bg-gray-950 border-gray-800">
        <DialogHeader>
          <DialogTitle className="text-amber-400 flex items-center gap-2">
            <Wifi className="h-5 w-5" />
            Share Your Identity
          </DialogTitle>
          <DialogDescription className="text-gray-400">
            Choose how to share your signed identity package.
          </DialogDescription>
        </DialogHeader>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full mt-2">
          <TabsList className="grid w-full grid-cols-4 bg-gray-900 border border-gray-800">
            <TabsTrigger
              value="qr"
              className="data-[state=active]:bg-amber-500/10 data-[state=active]:text-amber-400 text-xs sm:text-sm"
            >
              <QrCode className="h-4 w-4 mr-1 sm:mr-2" />
              <span className="hidden sm:inline">QR Code</span>
              <span className="sm:hidden">QR</span>
            </TabsTrigger>
            <TabsTrigger
              value="nfc"
              className="data-[state=active]:bg-amber-500/10 data-[state=active]:text-amber-400 text-xs sm:text-sm"
            >
              <Smartphone className="h-4 w-4 mr-1 sm:mr-2" />
              NFC
            </TabsTrigger>
            <TabsTrigger
              value="link"
              className="data-[state=active]:bg-amber-500/10 data-[state=active]:text-amber-400 text-xs sm:text-sm"
            >
              <Link2 className="h-4 w-4 mr-1 sm:mr-2" />
              <span className="hidden sm:inline">Short Code</span>
              <span className="sm:hidden">Link</span>
            </TabsTrigger>
            <TabsTrigger
              value="copy"
              className="data-[state=active]:bg-amber-500/10 data-[state=active]:text-amber-400 text-xs sm:text-sm"
            >
              <Copy className="h-4 w-4 mr-1 sm:mr-2" />
              Copy
            </TabsTrigger>
          </TabsList>

          {/* QR Code Tab */}
          <TabsContent value="qr" className="mt-4">
            <div className="flex flex-col items-center py-4 space-y-4">
              <SimpleQRCode value={exchangePackage} size={220} />
              <p className="text-xs text-gray-500 text-center max-w-xs">
                Scan this QR code with any SVRNTY-compatible app or camera to import this identity.
              </p>
            </div>
          </TabsContent>

          {/* NFC Tab */}
          <TabsContent value="nfc" className="mt-4">
            <div className="flex flex-col items-center py-6 space-y-4">
              {nfcStatus === 'unsupported' ? (
                <>
                  <div className="w-16 h-16 rounded-full bg-gray-800 flex items-center justify-center">
                    <Smartphone className="h-8 w-8 text-gray-600" />
                  </div>
                  <p className="text-sm text-gray-400 text-center max-w-xs">
                    NFC sharing requires Chrome on Android with NFC enabled.
                  </p>
                </>
              ) : (
                <>
                  <div className={`w-16 h-16 rounded-full flex items-center justify-center transition-colors ${
                    nfcStatus === 'success'
                      ? 'bg-teal-500/20'
                      : nfcStatus === 'writing'
                        ? 'bg-amber-500/20 animate-pulse'
                        : nfcStatus === 'error'
                          ? 'bg-red-500/20'
                          : 'bg-gray-800'
                  }`}>
                    {nfcStatus === 'success' ? (
                      <Check className="h-8 w-8 text-teal-400" />
                    ) : (
                      <Smartphone className={`h-8 w-8 ${
                        nfcStatus === 'writing' ? 'text-amber-400' :
                        nfcStatus === 'error' ? 'text-red-400' :
                        'text-gray-400'
                      }`} />
                    )}
                  </div>

                  {nfcStatus === 'idle' && (
                    <Button
                      onClick={handleNfcWrite}
                      className="bg-amber-600 hover:bg-amber-700 text-white"
                    >
                      <Smartphone className="h-4 w-4 mr-2" />
                      Tap to Share
                    </Button>
                  )}

                  {nfcStatus === 'writing' && (
                    <p className="text-sm text-amber-400 animate-pulse">
                      Hold your device near the other phone...
                    </p>
                  )}

                  {nfcStatus === 'success' && (
                    <p className="text-sm text-teal-400">
                      Identity shared via NFC successfully.
                    </p>
                  )}

                  {nfcStatus === 'error' && (
                    <div className="text-center space-y-2">
                      <p className="text-sm text-red-400">{nfcError}</p>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => { setNfcStatus('idle'); setNfcError(null); }}
                        className="border-gray-700 text-gray-300"
                      >
                        Try Again
                      </Button>
                    </div>
                  )}
                </>
              )}
            </div>
          </TabsContent>

          {/* Short Code / Link Tab */}
          <TabsContent value="link" className="mt-4">
            <div className="flex flex-col items-center py-4 space-y-4">
              {!shortCode.code ? (
                <>
                  <div className="w-16 h-16 rounded-full bg-gray-800 flex items-center justify-center">
                    <Link2 className="h-8 w-8 text-gray-400" />
                  </div>
                  <Button
                    onClick={handleGenerateShortCode}
                    disabled={shortCode.loading}
                    className="bg-amber-600 hover:bg-amber-700 text-white"
                  >
                    {shortCode.loading ? (
                      <>
                        <Clock className="h-4 w-4 mr-2 animate-spin" />
                        Generating...
                      </>
                    ) : (
                      <>
                        <Link2 className="h-4 w-4 mr-2" />
                        Generate Link
                      </>
                    )}
                  </Button>
                  {shortCode.error && (
                    <p className="text-sm text-red-400">{shortCode.error}</p>
                  )}
                </>
              ) : (
                <>
                  <div className="w-full bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-gray-500 uppercase tracking-wider font-medium">
                        Share Link
                      </span>
                      <div className="flex items-center gap-1 text-xs text-amber-400">
                        <Clock className="h-3 w-3" />
                        <span className="font-mono">{timeLeft}</span>
                      </div>
                    </div>
                    <div className="bg-gray-950 rounded-md p-3 border border-gray-800">
                      <code className="text-sm text-teal-400 font-mono break-all select-all">
                        {shortCodeLink}
                      </code>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={handleCopyLink}
                      className="w-full border-amber-500/30 text-amber-400 hover:bg-amber-500/10"
                    >
                      {linkCopied ? (
                        <><Check className="h-4 w-4 mr-2" /> Copied</>
                      ) : (
                        <><Copy className="h-4 w-4 mr-2" /> Copy Link</>
                      )}
                    </Button>
                  </div>
                  <p className="text-xs text-gray-500 text-center max-w-xs">
                    Link expires after first use or 15 minutes. The server cannot read your data.
                  </p>
                </>
              )}
            </div>
          </TabsContent>

          {/* Copy Raw Tab */}
          <TabsContent value="copy" className="mt-4">
            <div className="flex flex-col py-4 space-y-4">
              <div className="bg-gray-900 border border-gray-800 rounded-lg p-3 max-h-48 overflow-auto">
                <pre className="text-xs text-gray-400 font-mono whitespace-pre-wrap break-all select-all">
                  {exchangePackage}
                </pre>
              </div>
              <Button
                variant="outline"
                onClick={handleCopyRaw}
                className="w-full border-amber-500/30 text-amber-400 hover:bg-amber-500/10"
              >
                {copied ? (
                  <><Check className="h-4 w-4 mr-2" /> Copied to Clipboard</>
                ) : (
                  <><Copy className="h-4 w-4 mr-2" /> Copy Exchange Package</>
                )}
              </Button>
              <p className="text-xs text-gray-500 text-center">
                Paste this signed package into Signal, email, or any trusted channel.
                The recipient can verify it came from you.
              </p>
            </div>
          </TabsContent>
        </Tabs>

        {/* Fingerprint footer */}
        <div className="border-t border-gray-800 pt-3 mt-2">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-600">Your fingerprint</span>
            <code className="text-xs text-gray-500 font-mono">
              {fingerprint ? fingerprint.slice(0, 20) + '...' : ''}
            </code>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
