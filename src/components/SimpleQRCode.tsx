"use client";

import React, { useRef, useCallback } from 'react';
import QRCode from 'react-qr-code';
import { Download } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface SimpleQRCodeProps {
  value: string;
  size?: number;
}

export function SimpleQRCode({ value, size = 256 }: SimpleQRCodeProps) {
  const qrRef = useRef<HTMLDivElement>(null);

  const handleDownload = useCallback(() => {
    const svg = qrRef.current?.querySelector('svg');
    if (!svg) return;

    const canvas = document.createElement('canvas');
    const padding = 32;
    canvas.width = size + padding * 2;
    canvas.height = size + padding * 2;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // White background with padding
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Serialize SVG and draw to canvas
    const svgData = new XMLSerializer().serializeToString(svg);
    const img = new Image();
    const svgBlob = new Blob([svgData], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(svgBlob);

    img.onload = () => {
      ctx.drawImage(img, padding, padding, size, size);
      URL.revokeObjectURL(url);

      // Trigger download
      const dataUrl = canvas.toDataURL('image/png');
      const link = document.createElement('a');
      link.download = 'svrnty-identity-qr.png';
      link.href = dataUrl;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    };

    img.src = url;
  }, [size]);

  return (
    <div className="flex flex-col items-center gap-4">
      <div
        ref={qrRef}
        className="bg-white p-6 rounded-xl shadow-lg shadow-black/20"
        style={{ lineHeight: 0 }}
      >
        <QRCode
          value={value}
          size={size}
          level="M"
          bgColor="#ffffff"
          fgColor="#000000"
        />
      </div>
      <Button
        variant="outline"
        size="sm"
        onClick={handleDownload}
        className="border-amber-500/30 text-amber-400 hover:bg-amber-500/10 hover:text-amber-300"
      >
        <Download className="h-4 w-4 mr-2" />
        Download QR as PNG
      </Button>
    </div>
  );
}
