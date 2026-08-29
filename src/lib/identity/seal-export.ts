// Client-side seal export — SVG/PNG download of the rendered IdentitySeal.
// Lossy visual only; not reversible to a key (I-6).

import { solarEmber as E } from '@/components/recovery/solar-ember';

const NS = 'http://www.w3.org/2000/svg';

/** Clone a live seal SVG into a self-contained string with opaque background. */
export function serializeSealSvg(svg: SVGSVGElement, size = 512): string {
  const clone = svg.cloneNode(true) as SVGSVGElement;
  clone.setAttribute('xmlns', NS);
  clone.setAttribute('width', String(size));
  clone.setAttribute('height', String(size));
  clone.setAttribute('viewBox', '0 0 100 100');
  clone.removeAttribute('style');
  clone.removeAttribute('class');

  // Opaque Solar Ember ground so exports aren't transparent / white-washed
  const bg = document.createElementNS(NS, 'rect');
  bg.setAttribute('width', '100');
  bg.setAttribute('height', '100');
  bg.setAttribute('fill', E.bg);
  clone.insertBefore(bg, clone.firstChild);

  return new XMLSerializer().serializeToString(clone);
}

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function downloadSealSvg(svg: SVGSVGElement, filename: string, size = 512) {
  const markup = serializeSealSvg(svg, size);
  triggerDownload(new Blob([markup], { type: 'image/svg+xml;charset=utf-8' }), filename);
}

export async function downloadSealPng(svg: SVGSVGElement, filename: string, size = 512): Promise<void> {
  const markup = serializeSealSvg(svg, size);
  const dataUrl =
    'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(markup);

  const img = new Image();
  img.decoding = 'async';
  const loaded = new Promise<void>((resolve, reject) => {
    img.onload = () => resolve();
    img.onerror = () => reject(new Error('Failed to rasterize seal'));
  });
  img.src = dataUrl;
  await loaded;

  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d');
  if (!ctx) throw new Error('Canvas unavailable');
  ctx.fillStyle = E.bg;
  ctx.fillRect(0, 0, size, size);
  ctx.drawImage(img, 0, 0, size, size);

  const blob = await new Promise<Blob>((resolve, reject) => {
    canvas.toBlob(
      (b) => (b ? resolve(b) : reject(new Error('PNG encode failed'))),
      'image/png'
    );
  });
  triggerDownload(blob, filename);
}

export function sealFilename(base: string, ext: 'svg' | 'png'): string {
  const slug = (base || 'seal')
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'seal';
  return `svrnty-seal-${slug}.${ext}`;
}
